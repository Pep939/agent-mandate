# ADR-0011: Local API security — authentication, CSRF, and secret handling

Status: accepted (2026-09-03)

## Context

Brief §16 Phase 4 requires: "FastAPI endpoints. HTMX screens for mandates,
deals, approvals, revocation and timeline. CSRF protection, authentication and
secret handling. Plain-language rendering."

This is a **local, single-operator console** for v0.1. The trust boundary is the
local machine and the operator. Production/multi-operator auth, TLS termination,
and content-scanning are explicitly out of scope (Consequences). The invariants
that bind this ADR:

- **Invariant 12** — signing keys and secrets never appear in prompts, logs,
  events, fixtures, client HTML, or source control.
- **Invariant 11** — all externally supplied content is untrusted, including
  counterparty messages, Agent Cards, webhook payloads, model output, and
  imported documents.
- **Invariant 15** — every binding action has a traceable principal, authority
  record, decision, event, and resulting artifact.

ADR-0005 already fixes that the gateway signing key is runtime-only. This ADR
covers the operator-facing HTTP boundary that Phase 4 introduces.

## Decisions

### Deployment posture

- The server binds to **127.0.0.1 only** by default.
- **No TLS in v0.1 local** — a documented limitation. Loopback-only binding is
  the mitigation that makes skipping TLS acceptable for v0.1; TLS plus strong
  auth are a production / Phase 6+ concern (separate-machine transport).

### Authentication (single operator)

- Credentials: a password supplied to the boundary from an env var
  (`MANDATE_OPERATOR_PASSWORD`) or a `0600` file under gitignored `.dev/`. Never
  in source, fixtures, logs, or client HTML (invariant 12).
- Login compares the submitted password to the operator secret with a
  **constant-time compare** (`hmac.compare_digest`). No user store, no
  per-user hashing — single-operator local.
- On success a server-side session is created and a session cookie set:
  `HttpOnly`, `SameSite=Strict`, short max-age (default 8h, sliding). The session
  secret comes from env (`MANDATE_SESSION_SECRET`) or a `0600` file; sessions are
  held server-side (in-memory for local; a durable session store is a later
  concern). Logout destroys the session.
- Every console route except `/login` requires a valid session; otherwise the
  request is redirected to login (GET) or rejected (state-changing).

### CSRF

- Every state-changing request — login, submit proposal, approve, deny, revoke —
  carries a **per-session synchronizer token** (a hidden field in each HTMX form).
  The token is validated before the action; a mismatch is a `400` and commits
  nothing. The token is regenerated on login.
- `SameSite=Strict` is the second layer; the synchronizer token is the first
  (defense in depth for the local single-origin flow).

### Secret handling (invariant 12)

- Runtime-only secrets: the operator password, the session secret, and the
  gateway signing seed. They are loaded **only at startup, in the `api/` boundary
  and `adapters/`** (Postgres DSN).
- The `GatewaySigner` is instantiated from the seed at app startup (runtime-only,
  ADR-0005) and is never passed to templates, logs, or responses.
- A **banned-secret scan** test asserts no literal secret material in `src/` and
  `tests/`. The existing banned-imports AST scan is extended for `api/`: `api/`
  (the boundary) may do I/O, but `domain` / `policy` / `ledger` / `crypto` /
  `application` remain I/O-free (invariant 2).

### Rendering and untrusted content (invariants 11, 15)

- **Server-rendered Jinja2, autoescape on.** HTMX for partial updates; minimal JS.
- **Plain-language rendering** is a fixed code mapping `reason_code` → human
  sentence (e.g. `spend_cap_exceeded` → "This would take the deal over its spend
  limit; a person must approve the extra amount."). The mapping is code, not data.
- **Untrusted text** — proposal notes, counterparty messages, imported documents —
  is rendered as **escaped text only**, never injected as HTML or into executable
  context (invariant 11). No client-side templating of untrusted strings.
- Every decision the console shows links back to its `authority_record_id`,
  decision, and event(s) (invariant 15). The approvals and timeline screens are
  the reconstruction surface for the evidence bundle.

## Consequences

- New dependencies: `fastapi`, `uvicorn[standard]`, `jinja2`, `itsdangerous`
  (session signing + token), `python-multipart` (form parsing). Test dependency:
  `httpx` (FastAPI `TestClient`).
- New package `src/mandate/api/` (the boundary): app factory, `deps` (DI),
  `security` (session + CSRF), `render` (reason-code map), `routes/`, `templates/`.
- Config via env + `0600` files in gitignored `.dev/`; a dev seed for the operator
  password and session secret mirrors `scripts/dev_keys.py` for the gateway key.
- **Out of scope for v0.1** (do not block the local console): multi-operator RBAC,
  OAuth/SSO, TLS, rate limiting, content-scanning/redaction of untrusted payloads
  (threat-model candidate), mobile/push.
- Tests pin: unauthenticated request → login/deny; CSRF mismatch → `400`; secrets
  absent from responses and source; every `reason_code` renders a sentence;
  untrusted text is escaped (XSS fixture).

## Implementation (2026-09-03)

Built in `src/mandate/api/`: `app.py` (factory + session middleware), `security.py`
(constant-time password check, server-side sessions, per-session CSRF synchronizer),
`boundary.py` (`build_claim` crypto→claim, signing, ULID, `now`), `deps.py` (DI +
guards), `phrasing.py` (the `reason_code`→sentence + outcome maps), `routes/`
(`auth`, `deals`, `operations`) and `templates/` (Jinja2, autoescape on).

Two notes on the module layout:

- The reason-code map lives in `phrasing.py`, not `render.py` — `render` is already
  the name of the template-render helper in `deps.py`, so the human-sentence map got
  its own name to avoid a clash. Same substance as the ADR's "render" module.
- Secrets resolve env → gitignored `.dev/` files → generated (one-run, printed).
  `scripts/dev_secrets.py` writes the `.dev/` files (0600), mirroring `dev_keys.py`.

Pinned tests (`tests/api/`, 22) plus the extended scans cover the list above:
`tests/unit/test_banned_imports.py` now asserts the pure layers never import
`mandate.api`, and `tests/unit/test_banned_secrets.py` asserts no committed default
secret and no real key material in `src/` / no private key in `tests/`.
