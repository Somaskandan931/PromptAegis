# PromptAegis threat model

## Protected assets

The sandbox represents customer records, orders, outbound messages, data exports, executable SQL, and files. It is an in-memory test world; no production data, filesystem, network service, or mail server is accessed.

## Adversary and trusted components

The adversary may influence user text, external documents or tool output and may induce an agent to propose unauthorized tools, malformed parameters, privilege changes, exfiltration, destructive operations, or excessive requests. The gateway, registered identities, policy configuration, tool contracts, and sandbox runtime are trusted by the experiment. A real deployment would also need authenticated identity, protected configuration, trusted approval identity, and isolation against bypass paths; those properties are not established here.

## Enforcement boundary

Every sandbox tool call made through `ProtectedRuntime` is evaluated by `Gateway` before execution. The enforcement order is request validation and registration, RBAC, parameter contract, policy, rate limit, then approval/risk gate. The first blocking stage wins. Engine errors fail closed. Audit-write failures convert otherwise non-deny outcomes to `DENY`; a subsequent update attempts to align the SQLite event with that final decision.

The action boundary can constrain a proposed tool call. It cannot infer whether a syntactically valid action is malicious because of an earlier natural-language instruction unless that provenance is explicitly provided and enforced. The scripted benchmark does not execute an LLM, so it cannot establish prompt-injection resistance.

## Out of scope

The project does not establish security of the model, host, credentials, database administrator, external approval service, operating system, or tools called outside the adapter. The local hash chain is tamper-evident only if the attacker cannot rewrite the entire log; it is not externally anchored. The simulation does not establish production safety, availability, throughput, or compliance.
