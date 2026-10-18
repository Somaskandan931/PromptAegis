"""Structured, allowlist-based parameter validation for tool calls (Phase 5).

Design principle
----------------
The earlier policy engine inspected arguments with a *blocklist* (three
attacker domains, keyword lists). A blocklist only detects what its author already
thought of, so it cannot be evaluated fairly against attacks it was written
for.  This module instead encodes each tool's **input contract**: the set of
argument names, types, lengths and character classes that are legitimate for
that tool.  Anything outside the contract is rejected, regardless of whether it
resembles a known attack.

Scope and honesty notes
-----------------------
* This is *authorization-time input validation*, not prompt-injection
  detection.  It never sees the model's prompt.
* The contracts below are derived from the tool interface (what a customer-
  support CRM legitimately accepts), not from the benchmark's attack strings.
  They are still a researcher-authored policy and are versioned
  (``CONTRACT_VERSION``); changing them after viewing held-out results
  invalidates that evaluation (see docs/research/EXPERIMENT_PROTOCOL.md).
* Validation of free text (e.g. email body) is intentionally limited to size
  and control-character checks; semantic maliciousness of prose is out of scope.

Every function is pure and deterministic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

CONTRACT_VERSION = "contracts-2026.10.17-b"

# Domains the organisation may e-mail.  An ALLOWLIST: unknown domain => deny.
ALLOWED_EMAIL_DOMAINS = frozenset({"company.com"})

_CUSTOMER_ID = re.compile(r"^cust-\d{5}$")
_ORDER_ID = re.compile(r"^ORD-\d{6}$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+)$")
# Names: letter runs (optionally ending in '.') separated by ONE space, hyphen or apostrophe.
_NAME = re.compile(r"^[A-Za-z]+\.?(?:[ '\-][A-Za-z]+\.?)*$")
_PHONE = re.compile(r"^\+?[0-9][0-9\- ]{6,18}[0-9]$")
_ADDRESS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .,#'/\-]{2,119}$")
_STATUS = frozenset({"pending", "shipped", "delivered", "cancelled", "refunded"})
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SQL_COMMENT_OR_STACK = re.compile(r"(--|/\*|\*/|;)")

UPDATABLE_FIELDS = {
    "name": _NAME,
    "email": _EMAIL,
    "phone": _PHONE,
    "address": _ADDRESS,
}


@dataclass(frozen=True)
class Violation:
    code: str          # stable machine code, e.g. PARAM_RECIPIENT_DOMAIN_NOT_ALLOWED
    argument: str      # argument path, e.g. "fields.email"
    detail: str        # non-sensitive explanation (never echoes the raw value)


@dataclass
class ValidationResult:
    valid: bool
    violations: List[Violation] = field(default_factory=list)

    @property
    def first(self) -> Optional[Violation]:
        return self.violations[0] if self.violations else None


def _v(code: str, arg: str, detail: str) -> Violation:
    return Violation(code, arg, detail)


def _is_str(x: Any) -> bool:
    return isinstance(x, str)


def _check_unexpected(args: Dict[str, Any], allowed: set, out: List[Violation], prefix: str = "") -> None:
    for key in args:
        if key not in allowed:
            out.append(_v("PARAM_UNEXPECTED_ARGUMENT", f"{prefix}{key}", "argument not in tool contract"))


def _email_domain_ok(addr: Any) -> Tuple[bool, str]:
    if not _is_str(addr):
        return False, "PARAM_RECIPIENT_TYPE"
    if _CONTROL.search(addr) or "\n" in addr or "\r" in addr:
        return False, "PARAM_RECIPIENT_CONTROL_CHARS"
    m = _EMAIL.match(addr)
    if not m:
        return False, "PARAM_RECIPIENT_MALFORMED"
    if m.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
        return False, "PARAM_RECIPIENT_DOMAIN_NOT_ALLOWED"
    return True, ""


# --------------------------------------------------------------------------
# Per-tool contracts
# --------------------------------------------------------------------------
def _validate_search_customer(a: Dict[str, Any]) -> List[Violation]:
    out: List[Violation] = []
    _check_unexpected(a, {"query"}, out)
    q = a.get("query")
    if q is None:
        out.append(_v("PARAM_MISSING_REQUIRED", "query", "query is required"))
    elif not _is_str(q):
        out.append(_v("PARAM_TYPE", "query", "query must be a string"))
    elif len(q) > 64:
        out.append(_v("PARAM_TOO_LONG", "query", "query exceeds 64 characters"))
    elif not (_CUSTOMER_ID.match(q) or _EMAIL.match(q) or _NAME.match(q)):
        out.append(_v("PARAM_QUERY_NOT_IN_CONTRACT", "query",
                      "query must be a customer id, an e-mail address or a personal name"))
    return out


def _validate_search_order(a: Dict[str, Any]) -> List[Violation]:
    out: List[Violation] = []
    _check_unexpected(a, {"order_id", "customer_id", "status"}, out)
    if not any(k in a for k in ("order_id", "customer_id")):
        out.append(_v("PARAM_MISSING_REQUIRED", "order_id|customer_id", "one identifier is required"))
    if "order_id" in a and not (_is_str(a["order_id"]) and _ORDER_ID.match(a["order_id"])):
        out.append(_v("PARAM_ID_FORMAT", "order_id", "order_id must match ORD-NNNNNN"))
    if "customer_id" in a and not (_is_str(a["customer_id"]) and _CUSTOMER_ID.match(a["customer_id"])):
        out.append(_v("PARAM_ID_FORMAT", "customer_id", "customer_id must match cust-NNNNN"))
    if "status" in a and a["status"] not in _STATUS:
        out.append(_v("PARAM_ENUM", "status", "status not in permitted set"))
    return out


def _validate_update_customer(a: Dict[str, Any]) -> List[Violation]:
    out: List[Violation] = []
    _check_unexpected(a, {"customer_id", "fields"}, out)
    cid = a.get("customer_id")
    if not (_is_str(cid) and _CUSTOMER_ID.match(cid)):
        out.append(_v("PARAM_ID_FORMAT", "customer_id", "customer_id must match cust-NNNNN"))
    fields = a.get("fields")
    if not isinstance(fields, dict) or not fields:
        out.append(_v("PARAM_MISSING_REQUIRED", "fields", "fields must be a non-empty object"))
        return out
    if len(fields) > 3:
        out.append(_v("PARAM_SCOPE_TOO_BROAD", "fields", "at most 3 fields may be updated per call"))
    for key, val in fields.items():
        path = f"fields.{key}"
        pattern = UPDATABLE_FIELDS.get(key)
        if pattern is None:
            out.append(_v("PARAM_FIELD_NOT_UPDATABLE", path, "field is not updatable by this tool"))
            continue
        if not _is_str(val):
            out.append(_v("PARAM_TYPE", path, "value must be a string"))
        elif _CONTROL.search(val) or _SQL_COMMENT_OR_STACK.search(val) or "<" in val or ">" in val:
            out.append(_v("PARAM_VALUE_FORBIDDEN_CHARS", path, "value contains characters outside the field contract"))
        elif not pattern.match(val):
            out.append(_v("PARAM_VALUE_FORMAT", path, f"value does not match the {key} format"))
    return out


def _validate_send_email(a: Dict[str, Any]) -> List[Violation]:
    out: List[Violation] = []
    _check_unexpected(a, {"to", "recipient", "subject", "body", "cc", "bcc"}, out)
    # cc/bcc are outside the contract for the support persona: they are the
    # classic covert-exfiltration channel, so they are rejected above unless
    # absent.  (They are listed in the allowed set only so that the message is
    # the specific code below, not a generic unexpected-argument code.)
    for k in ("cc", "bcc"):
        if k in a:
            out.append(_v("PARAM_COPY_RECIPIENTS_FORBIDDEN", k, "cc/bcc are not permitted"))
    to = a.get("to", a.get("recipient"))
    if "to" in a and "recipient" in a and a["to"] != a["recipient"]:
        out.append(_v("PARAM_RECIPIENT_AMBIGUOUS", "to|recipient", "conflicting recipient fields"))
    if to is None:
        out.append(_v("PARAM_MISSING_REQUIRED", "to", "recipient is required"))
    else:
        ok, code = _email_domain_ok(to)
        if not ok:
            out.append(_v(code, "to", "recipient failed the allowlist contract"))
    subj = a.get("subject", "")
    if not _is_str(subj) or len(subj) > 200 or _CONTROL.search(subj) or "\n" in subj or "\r" in subj:
        out.append(_v("PARAM_SUBJECT_INVALID", "subject", "subject must be a single line of at most 200 characters"))
    body = a.get("body", "")
    if not _is_str(body) or len(body) > 5000 or _CONTROL.search(body.replace("\n", "").replace("\r", "").replace("\t", "")):
        out.append(_v("PARAM_BODY_INVALID", "body", "body must be text of at most 5000 characters"))
    return out


def _validate_delete_customer(a: Dict[str, Any]) -> List[Violation]:
    out: List[Violation] = []
    _check_unexpected(a, {"customer_id", "reason"}, out)
    cid = a.get("customer_id")
    if not (_is_str(cid) and _CUSTOMER_ID.match(cid)):
        out.append(_v("PARAM_ID_FORMAT", "customer_id", "customer_id must match cust-NNNNN (wildcards are not allowed)"))
    return out


def _validate_export(a: Dict[str, Any]) -> List[Violation]:
    out: List[Violation] = []
    _check_unexpected(a, {"customer_id", "destination", "format"}, out)
    cid = a.get("customer_id")
    if not (_is_str(cid) and _CUSTOMER_ID.match(cid)):
        out.append(_v("PARAM_SCOPE_TOO_BROAD", "customer_id", "export must name exactly one customer"))
    dest = a.get("destination")
    if dest is not None:
        ok, code = _email_domain_ok(dest)
        if not ok:
            out.append(_v("PARAM_DESTINATION_NOT_ALLOWED", "destination", "export destination must be an allowed internal address"))
    return out


def _validate_execute_sql(a: Dict[str, Any]) -> List[Violation]:
    # Arbitrary SQL cannot be validated by pattern; the contract is "no raw SQL".
    return [_v("PARAM_RAW_SQL_NOT_SUPPORTED", "query", "raw SQL execution has no validating contract")]


def _validate_file_delete(a: Dict[str, Any]) -> List[Violation]:
    out: List[Violation] = []
    _check_unexpected(a, {"path"}, out)
    p = a.get("path")
    if not _is_str(p):
        out.append(_v("PARAM_TYPE", "path", "path must be a string"))
    else:
        norm = p.replace("\\", "/")
        parts = [seg for seg in norm.split("/") if seg]
        if ".." in parts or "%" in norm or not norm.startswith("/sandbox/tmp/"):
            out.append(_v("PARAM_PATH_OUT_OF_SCOPE", "path", "path must stay inside /sandbox/tmp/"))
    return out


CONTRACTS: Dict[str, Callable[[Dict[str, Any]], List[Violation]]] = {
    "search_customer": _validate_search_customer,
    "search_order": _validate_search_order,
    "update_customer": _validate_update_customer,
    "send_email": _validate_send_email,
    "delete_customer": _validate_delete_customer,
    "export_customer_data": _validate_export,
    "execute_sql": _validate_execute_sql,
    "file_delete": _validate_file_delete,
}


_CUSTOM_SCHEMA_TYPES = {"object", "array", "string", "integer", "number", "boolean", "null"}
_CUSTOM_SCHEMA_KEYS = {"type", "properties", "required", "additionalProperties", "enum",
                       "minLength", "maxLength", "minimum", "maximum", "items"}


def validate_contract_definition(schema: Any) -> None:
    """Reject malformed or unsupported custom contracts before they are stored.

    This deliberately supports a bounded JSON-Schema subset; pattern matching,
    references, unions and executable/custom validators are not accepted.
    """
    def check(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            raise ValueError(f"{path} must be an object")
        unknown = set(node) - _CUSTOM_SCHEMA_KEYS
        if unknown:
            raise ValueError(f"{path} has unsupported keys: {sorted(unknown)}")
        kind = node.get("type")
        if not isinstance(kind, str) or kind not in _CUSTOM_SCHEMA_TYPES:
            raise ValueError(f"{path}.type must be one of {sorted(_CUSTOM_SCHEMA_TYPES)}")
        if path == "$" and kind != "object":
            raise ValueError("custom tool argument contract root must have type object")
        props = node.get("properties", {})
        if kind == "object":
            if not isinstance(props, dict) or any(not isinstance(k, str) or not k for k in props):
                raise ValueError(f"{path}.properties must map nonempty names to schemas")
            required = node.get("required", [])
            if not isinstance(required, list) or any(not isinstance(k, str) or k not in props for k in required):
                raise ValueError(f"{path}.required must list declared properties")
            if "additionalProperties" in node and not isinstance(node["additionalProperties"], bool):
                raise ValueError(f"{path}.additionalProperties must be boolean")
            for key, child in props.items():
                check(child, f"{path}.{key}")
        elif "properties" in node or "required" in node or "additionalProperties" in node:
            raise ValueError(f"object-only keywords used on {path} with type {kind}")
        if kind == "array":
            if "items" in node:
                check(node["items"], f"{path}[]")
            elif "items" not in node:
                raise ValueError(f"{path}.items is required for arrays")
        elif "items" in node:
            raise ValueError(f"{path}.items is only valid for arrays")
        if "enum" in node and (not isinstance(node["enum"], list) or not node["enum"]):
            raise ValueError(f"{path}.enum must be a nonempty list")
        for key in ("minLength", "maxLength"):
            if key in node and (kind != "string" or type(node[key]) is not int or node[key] < 0):
                raise ValueError(f"{path}.{key} must be a nonnegative integer on strings")
        for key in ("minimum", "maximum"):
            if key in node and (kind not in {"number", "integer"} or type(node[key]) not in (int, float)):
                raise ValueError(f"{path}.{key} must be numeric on number types")
    check(schema, "$")


def _custom_schema_violations(value: Any, schema: Dict[str, Any], path: str = "") -> List[Violation]:
    out: List[Violation] = []
    key = path or "<root>"
    kind = schema["type"]
    type_ok = {
        "object": isinstance(value, dict), "array": isinstance(value, list),
        "string": isinstance(value, str), "integer": type(value) is int,
        "number": type(value) in (int, float) and type(value) is not bool,
        "boolean": type(value) is bool, "null": value is None,
    }[kind]
    if not type_ok:
        return [_v("PARAM_CUSTOM_TYPE", key, f"expected {kind}")]
    if "enum" in schema and value not in schema["enum"]:
        out.append(_v("PARAM_CUSTOM_ENUM", key, "value is not an allowed enum member"))
    if kind == "object":
        props = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                out.append(_v("PARAM_CUSTOM_REQUIRED", f"{path}.{required}".strip("."), "required argument is missing"))
        if schema.get("additionalProperties", False) is False:
            for extra in value.keys() - props.keys():
                out.append(_v("PARAM_CUSTOM_UNEXPECTED", f"{path}.{extra}".strip("."), "argument not in tool contract"))
        for name, child in props.items():
            if name in value:
                out.extend(_custom_schema_violations(value[name], child, f"{path}.{name}".strip(".")))
    elif kind == "array" and "items" in schema:
        for i, item in enumerate(value):
            out.extend(_custom_schema_violations(item, schema["items"], f"{path}[{i}]".strip(".")))
    elif kind == "string":
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(_v("PARAM_CUSTOM_MIN_LENGTH", key, "string is shorter than contract minimum"))
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(_v("PARAM_CUSTOM_MAX_LENGTH", key, "string exceeds contract maximum"))
    elif kind in {"number", "integer"}:
        if "minimum" in schema and value < schema["minimum"]:
            out.append(_v("PARAM_CUSTOM_MINIMUM", key, "number is below contract minimum"))
        if "maximum" in schema and value > schema["maximum"]:
            out.append(_v("PARAM_CUSTOM_MAXIMUM", key, "number exceeds contract maximum"))
    return out


def validate_arguments(tool_name: str, arguments: Any,
                       custom_contract: Optional[Dict[str, Any]] = None) -> ValidationResult:
    """Validate ``arguments`` against the contract for ``tool_name``.

    Unknown tools and non-dict arguments are invalid (fail closed).
    """
    if not isinstance(arguments, dict):
        return ValidationResult(False, [_v("PARAM_NOT_AN_OBJECT", "<root>", "arguments must be a JSON object")])
    contract = CONTRACTS.get(tool_name)
    if contract is not None:
        violations = contract(arguments)
        return ValidationResult(not violations, violations)
    if custom_contract is None:
        return ValidationResult(False, [_v("PARAM_NO_CONTRACT", "<root>", "no input contract registered for tool")])
    try:
        validate_contract_definition(custom_contract)
    except (TypeError, ValueError):
        return ValidationResult(False, [_v("PARAM_INVALID_CONTRACT", "<root>", "registered tool contract is invalid")])
    violations = _custom_schema_violations(arguments, custom_contract)
    return ValidationResult(not violations, violations)
