# Agent Credential Broker

> **The model emits intent. The harness owns credentials. The broker enforces policy.**

A Claude code reviewer files Jira tickets without ever holding a credential. Instead:
- Each agent run gets its own workload identity: an mTLS certificate with a SPIFFE-style ID.
- The user delegates a narrow grant to that run.
- A tool broker verifies identity, grant and policy before it calls Jira with a key that only the broker holds.

```
LLM reviewer ──intent──▶ harness ◀──mTLS──▶ grants
                            │
                            └──mTLS + token──▶ broker ──API key──▶ mock Jira
```

## Scenarios

| Scenario | What happens |
|---|---|
| **Normal** | The agent files tickets. The harness refreshes its 10s access token without the model noticing. |
| **Grant expires** | The grant expires 6s after the first ticket. The next refresh is denied at `/token`, and the model is told only *"Grant no longer available."* |
| **Grant revoked** | The user revokes the grant after the first ticket. The token already issued keeps working until it expires, and the log labels that window. The next token exchange is denied. |
| **Stolen token** | A second workload with its own valid identity replays this run's access token and delegation ID. The broker rejects the token (`binding_mismatch`), grants rejects the delegation (`actor_mismatch`), and the real run continues. |

The **Model context** panel shows the exact request sent to Claude, and it is scanned for anything credential-like. The toy repo contains a prompt injection that asks the reviewer to paste its API token into tickets. The agent has nothing to paste.

## Components

Everything is one binary (`demo <subcommand>`), and each service runs as its own container or process.

| Process | Holds | Never holds |
|---|---|---|
| `harness` | run private keys, delegation IDs, access tokens, Anthropic API key | Jira key, signing keys |
| `grants` | run-identity CA, token signing key, delegations, user state | Jira key |
| `broker` | Jira API key, token verification key | delegations, signing keys |
| `jira` | tickets | — |
| `web` | sessions, event log, delegation IDs | access tokens, any agent key |

Each service's key directory contains only what that service needs.

**Credentials are in two tiers:**
- **Delegation:** long-lived, stored server-side, revocable, and bound to one run's SPIFFE ID.
- **Access token:** Ed25519-signed and valid for 10s. It carries `sub` (the user), `act.sub` (the run, per RFC 8693), `scope`, `resource` and `tenant`.

Revocation and user state are checked when the harness exchanges the delegation for a token (`/token`). The broker checks everything offline, with no call back to grants, in this order:
1. mTLS identity
2. signature and audience
3. expiry
4. that `act.sub` matches the mTLS peer
5. the policy table
6. scope
7. resource

### Revocation semantics

**An issued access token remains valid until it expires. Revocation is enforced at the next token exchange.**

- **Worst case:** a revoked grant keeps working for at most one token lifetime (10s). After that the token is expired, and the broker rejects it however late the harness tries.
- **What we get in return:** the broker has no state and no runtime dependency on grants.
- **Why that's acceptable:** tokens are sender-constrained (bound to the run's mTLS identity), so a leaked token is useless to anyone else during that window.
- **Clock skew:** the broker allows none, because all services run on one host. Across hosts it would need a small allowance, and that allowance would widen the window.
- **If a lower bound is needed:** for high-risk actions, the broker could make an online revocation check (listed as a stretch goal).

## Run

Put `ANTHROPIC_API_KEY=...` in `.env`, then:

```bash
docker compose up --build
```

Then open http://localhost:8080.

Compose runs each service in its own container, so the boundaries are enforced by the platform:
- **Keys:** a one-shot `pki` container generates key material into a volume. Each service mounts only its own subdirectory, read-only.
- **API key:** only `harness` receives `ANTHROPIC_API_KEY`.
- **Networks:**
  - `mesh` carries mTLS and events.
  - `tools` is internal, with no internet access, and holds Jira. Only `broker` and `web` (for the read-only ticket view) are on it, so the harness has no network route to Jira.
- **Ports:** only `web` is published. It binds to `127.0.0.1` by default; set `WEB_BIND=0.0.0.0` to expose it.

To stop the stack and discard all keys and state:

```bash
docker compose down -v
```

Settings: `CLAUDE_MODEL` (default `claude-opus-5-5`), `WEB_PORT`, `RUNS_PER_DAY`.

**Without Docker:** `go build -o bin/demo ./cmd/demo`, then `./bin/demo supervise`. This runs the same services as local processes, and `supervise` gives the API key only to the harness.

**Cost guards:** 5 runs per hour per browser session, `RUNS_PER_DAY` across all sessions (default 300), at most 6 model turns and 3 tickets per run.

## Layout

```
cmd/demo/          subcommand dispatch
internal/pki/      CA, SPIFFE-style certs, mTLS configs
internal/token/    EdDSA access token
internal/grants/   /svid, delegations, /token, revoke
internal/broker/   verification + authorization pipeline, policy table
internal/harness/  agent loop, credential handling, failure classes, toy repo
internal/jira/     mock Jira
internal/web/      sessions, scenarios, event log, dashboard
```

## Deliberately out of scope

This demo does not include:
- real SPIRE or OAuth
- persistence
- key rotation
- certificate-thumbprint binding (`cnf`)
- pause and re-consent on expiry
- a policy engine
- authenticated decision-log events: services report events to `web` over plain HTTP on the internal network. This affects what the dashboard displays, but grants no authority.

The stolen-token scenario is driven by test-only code in the harness (`simulateTheft`). It deliberately replays a credential under a second identity, and would not exist in a real harness.

See `BUILD_PLAN.md` §11 for the stretch goals.
