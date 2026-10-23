# Design and decisions

## Why a library

Services each need real, scoped API tokens, and an orchestrator needs each service to issue
short-lived per-job credentials. Solved separately, every service grows its own token table with
its own rules. Turnkey solves it once **without** a central auth service: each service imports the
library and keeps its tokens in its own database, so no request depends on anything else being up.

Alternatives considered:
- **Vault / OpenBao:** renewable leases and child tokens limited to their parent are the right
  model, but it's another service to run and unseal, and its policies govern Vault's paths, not
  your APIs.
- **OAuth/OIDC servers:** built for people logging in; their tokens can't be extended in place.
- **Biscuit / Macaroons:** attenuation is elegant, but expiry baked into the token doesn't fit
  renewal, and revocation needs a store anyway.
- **Policy engines:** they decide, but issue nothing.

## One token concept

One table holds every kind of token. They differ only in which fields are set:

| Kind | Set | Example label |
|---|---|---|
| `token` | maybe `expires_at` | `build-server` |
| `session` | `expires_at`, `slide_seconds` | `session.3f9c0a1b2c4d` |
| `credential` | `expires_at`, `issued_by`, `subject` | `orchestrator.job-42` |

- Secrets are `<tokenPrefix><32 random bytes, base64url>`, shown once. The table stores the
  sha256 (hex), the same scheme many existing token tables use, so `tokens.import` can bring
  tokens over with their hashes.
- **Revoking** sets `revoked_at`; **expiry** is checked on every lookup; rows dead longer than
  the retention period (30 days) are purged, so the record of who had access lasts that long.
- There is **no cache**: `authenticate` reads the service's own database on every call, so a
  revoke applies on the next request.
- `last_used_at` is written at most every five minutes per token, to answer "is this still used?"
  without a write per request.
- Revoking a token revokes the credentials it issued.

## Browser sessions

An app that does its own login (a master password, or an OIDC provider) makes its session cookie
a Turnkey token of kind `session`. Turnkey never sees a password or talks to the provider. A
session slides: each use moves its expiry to `now + ttl`, at most every `ttl/10` (capped at an
hour), and the adapters re-send the cookie when it moved. Cookie-authenticated writes from another
origin are refused, because sibling sites on one parent domain share `SameSite=Lax` cookies.

Tokens have no owner or user field: Turnkey targets a service's operators, hosts and agents.
Per-user tokens in a multi-user app can be modelled with resource paths (`users/<id>/…`) or the
`subject`, or added later as an optional column.

## Tables and migrations

- Turnkey owns `<prefix>tokens` and `<prefix>migrations` (prefix `turnkey_` by default). It creates
  them, migrates them and checks them at startup.
- **Migrations are replayed, never shortcut.** A fresh database runs every numbered migration in
  order; there is no separate "full schema" file that could drift from them. Each applied
  migration is recorded with a checksum of its SQL.
- **Startup refuses** when an applied migration's checksum changed, when the database is at a
  newer version than the library (a downgrade), or when an expected column is missing.
- **Startup is locked** so two replicas booting together don't both migrate: a Postgres
  transaction-scoped advisory lock (Postgres DDL is transactional, so a failed migration rolls
  back whole), MySQL `GET_LOCK`, SQLite `BEGIN IMMEDIATE`.
- Timestamps are fixed-width ISO 8601 UTC strings: they compare correctly as text in every
  dialect and need no time-zone handling.
- **Never edit a shipped migration.** Add the next one, and add its columns to
  `EXPECTED_COLUMNS`.

## Dolt

Dolt commits every change; renewing credentials every few minutes would flood a service's
history. On Dolt (detected with `dolt_version()`), before creating any table, Turnkey adds
`<prefix>%` to `dolt_ignore` and commits only that change (`DOLT_ADD('dolt_ignore')`, then
`DOLT_COMMIT` with a configurable author), so the service's other pending changes aren't swept in.
Turnkey's tables then live in the working set and never enter a commit, including the service's
own `DOLT_COMMIT('-A')`.

A backup that dumps committed tables won't include them, and a restore also drops the ignore
rule; startup redoes both. A service that wants permanent tokens to survive a restore copies
`<prefix>tokens` from the working set in its backup.

## Zero runtime dependencies

Database drivers and web frameworks are the service's own. The driver adapters take the client
the service already created and use structural types, so Turnkey imports no driver, and the web
adapters import no framework.
