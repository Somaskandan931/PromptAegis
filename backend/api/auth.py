"""
PromptAegis Environment Authentication & Authorization Gateway Middleware.

Enforces:
1. Environment-scoped credential authentication via `X-PromptAegis-Key` or `Authorization: Bearer <key>`.
2. Cross-environment spoofing detection (rejecting mismatched asserted environments with HTTP 403).
3. Authoritative credential routing: The authenticated credential is the sole authority for environment identity.
4. Zero secret leakage: Credentials and tokens are never exposed in contexts, logs, or responses.
"""
from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import Header, HTTPException

from database.environments import (
    CredentialManager,
    EnvironmentRegistry,
    set_current_environment,
)


@dataclass
class EnvironmentContext:
    environment_id: str
    environment_info: Dict[str, Any]
    credential_info: Optional[Dict[str, Any]] = None
    role: str = "default"


def extract_token(
    x_promptaegis_key: Optional[str],
    authorization: Optional[str],
) -> Optional[str]:
    """Extract API token safely without echoing or leaking values."""
    if isinstance(x_promptaegis_key, str) and x_promptaegis_key.strip():
        return x_promptaegis_key.strip()
    if isinstance(authorization, str) and authorization.strip():
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        elif len(parts) == 1:
            return parts[0]
    return None


def get_authenticated_environment(
    x_promptaegis_key: Optional[str] = Header(None),
    x_promptaegis_environment: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> EnvironmentContext:
    """
    Enforces that the request provides a valid API credential bound to a registered environment.
    Rejects missing auth with 401 Unauthorized.
    Rejects spoofed environment headers with 403 Forbidden.
    """
    token = extract_token(x_promptaegis_key, authorization)
    if not token:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "AUTHENTICATION_REQUIRED",
                "message": "Missing API key. Provide a valid environment-bound key via X-PromptAegis-Key or Authorization: Bearer <key>.",
            },
        )

    cred = CredentialManager.get_credential(token)
    if not cred:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "INVALID_CREDENTIAL",
                "message": "The provided API credential is unrecognized or invalid.",
            },
        )

    bound_env = cred["environment_id"]
    env_info = EnvironmentRegistry.get_environment(bound_env, sanitize=True)
    if not env_info:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "ENVIRONMENT_NOT_FOUND",
                "message": f"Environment '{bound_env}' bound to credential is not registered in EnvironmentRegistry.",
            },
        )

    # Anti-spoofing verification: if header explicitly asserts an environment, it MUST match the credential
    if isinstance(x_promptaegis_environment, str) and x_promptaegis_environment.strip() and x_promptaegis_environment.strip() != bound_env:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "ENVIRONMENT_SPOOF_DETECTED",
                "message": (
                    f"Credential is authenticated for environment '{bound_env}', but request header "
                    f"asserted environment '{x_promptaegis_environment.strip()}'. Cross-environment access forbidden."
                ),
                "bound_environment": bound_env,
                "asserted_environment": x_promptaegis_environment.strip(),
            },
        )

    # Set execution context for current request
    set_current_environment(bound_env)

    # Build sanitized credential metadata (never attach raw token)
    cred_sanitized = {
        "environment_id": bound_env,
        "name": cred.get("name", ""),
        "allowed_roles": cred.get("allowed_roles", []),
        "is_test_credential": cred.get("is_test_credential", False),
    }

    primary_role = cred.get("allowed_roles", ["default"])[0] if cred.get("allowed_roles") else "default"

    return EnvironmentContext(
        environment_id=bound_env,
        environment_info=env_info,
        credential_info=cred_sanitized,
        role=primary_role,
    )
