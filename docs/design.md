# Design and decisions

## Why a library

Services each need real, scoped API tokens, and an orchestrator needs each service to give it
short-lived per-job tokens. Solved separately, every service grows its own token table with its
own rules. Turnkey solves it once **without** a central auth service: each service imports the
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

There is one kind of token, one table, one set of operations and one HTTP API. A token may have
two optional properties, and that is all that distinguishes the uses:

| Set | Use | Example label |
|---|---|---|
| nothing extra (maybe `expires_at`) | hosts, scripts, people | `build-server` |
| `parent` (always `expires_at`) | a child: one job's token, made by an orchestrator | `orchestrator.job-42` |
| `slide_seconds` | a browser session | `session.3f9c0a1b2c4d` |

- Secrets are `<tokenPrefix><32 random bytes, base64url>`, shown once. The table stores the
  sha256 (hex), the same scheme many existing token tables use, so `tokens.import` can bring
  tokens over with their hashes.
- **Revoking** sets `revoked_at`; **expiry** is checked on every lookup; rows dead longer than
  the retention period (30 days) are purged, so the record of who had access lasts that long.
- There is **no cache**: `authenticate` reads the service's own database on every call, so a
  revoke applies on the next request.
- `last_used_at` is written at most every five minutes per token, to answer "is this still used?"
  without a write per request. That write, and a session's slide, are best-effort: a token that was
  valid when read is never refused because recording its use failed (two requests on one token can
  race to write the same row, which Dolt rejects for one of them). The failure is logged, the next
  request writes again, and a slide that was not written is not reported (`renewed` stays false).
  Timestamps are whole seconds, so racing writers usually carry the same value and merge cleanly.

**Why one concept (0.2.0).** 0.1 had a separate credential API (`issue`, `renew`, `revoke`) and
its own HTTP contract beside the token operations, with different rules: an issuer was limited to
what it held while `turnkey:manage` was not. Under the hood a credential was already a token row
with an issuer and an expiry. 0.2.0 makes that the whole model: a credential is a child token,
renewing is extending, there is one rule for giving permissions (only what you hold), and one API
an orchestrator uses like anyone else.

**Children are checked live.** A child's row says who its parent is; `authenticate` joins the
parent's row and refuses the child once the parent is revoked, expired or gone, or no longer
holds `turnkey:issue`, and narrows its grants to what the parent still covers. So revoking an
orchestrator's token stops every job's token at once, with no cascade writes and nothing to redo
after a crash. Children have no children: a child never passes a `turnkey:` check, so the chain is
one level and the check is one join.

**Only a parent's children are its business.** A token without `turnkey:manage` sees itself and
its children, and nothing else. That is what lets an orchestrator hold `turnkey:issue` without
being able to touch the service's other tokens.

**Children always expire.** If the orchestrator dies, nobody extends its children, and they
lapse within the cap (an hour by default). Revoking is the fast path; expiry is the safety net.

## Browser sessions

An app that does its own login (a master password, or an OIDC provider) makes its session cookie
a Turnkey token whose expiry slides. Turnkey never sees a password or talks to the provider. A
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

Dolt commits every change; extending children every few minutes would flood a service's
history. On Dolt (detected with `dolt_version()`), before creating any table, Turnkey adds
`<prefix>%` to `dolt_ignore` and commits only that change (`DOLT_ADD('dolt_ignore')`, then
`DOLT_COMMIT` with a configurable author), so the service's other pending changes aren't swept in.
Turnkey's tables then live in the working set and never enter a commit, including the service's
own `DOLT_COMMIT('-A')`.

A backup that dumps committed tables won't include them, and a restore also drops the ignore
rule; startup redoes both. A service that wants its tokens to survive a restore saves
`tokens.export()` in its backup and imports it after.

## Zero runtime dependencies

Database drivers and web frameworks are the service's own. The driver adapters take the client
the service already created and use structural types, so Turnkey imports no driver, and the web
adapters import no framework.
