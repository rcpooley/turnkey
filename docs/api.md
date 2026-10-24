# The HTTP API

The token operations over HTTP, as the adapters serve them (`turnkeyRouter`, `turnkeyHandler`,
`turnkeyRoutes`). The service mounts the API where it likes; paths here are below the mount
point (`/turnkey` by default for `node` and `fetch`).

Every call needs a token as `Authorization: Bearer <secret>`, and gets exactly the rules the
library applies ([permissions.md](permissions.md)). Requests and responses are JSON. An error is a
non-2xx status with `{"error": "<message>", "code": "<code>"}`:

| Status | Code | When |
|---|---|---|
| 400 | `bad_request` | a malformed body, permission or label; an unknown field |
| 401 | `unauthorized` | no token, or an unknown, revoked or expired one |
| 403 | `forbidden` | the rules refuse (see below) |
| 404 | `not_found` | no such token, one the caller may not see, or (for `extend`) one that is revoked or expired |
| 405 | `method_not_allowed` | a known path with the wrong method |
| 409 | `conflict` | a live token already has that label |

## Calls

`<ref>` is a token's id or label.

| Call | Body | Returns |
|---|---|---|
| `GET /self` | | the caller as a token (below), its current `grants`, and `maxChildTtlSeconds` |
| `GET /tokens` | | `{tokens: [...]}`: what the caller may see, live ones only. `?all=true` adds revoked and expired ones; `?parent=<ref>` keeps only that token's children |
| `POST /tokens` | `{label, grants, ttlSeconds?, expiresAt?, subject?}` | 201 `{token, secret}`: an independent token |
| `POST /tokens` | `{child: true, name?, grants, ttlSeconds?, expiresAt?, subject?}` | 201 `{token, secret}`: a child of the caller, labelled `<caller label>.<name>` |
| `POST /tokens` | either of the above with `dryRun: true` | 200 `{dryRun: true, label, grants, parent, expiresAt}`: every check passed, nothing was created |
| `GET /tokens/<ref>` | | the token |
| `POST /tokens/<ref>/extend` | `{ttlSeconds?}` or `{expiresAt?}` | the token, with its new expiry. The secret never changes |
| `POST /tokens/<ref>/revoke` | | the token, `active: false`. Idempotent |
| `POST /tokens/<ref>/grant` | `{grants}` | the token |
| `POST /tokens/<ref>/ungrant` | `{grants}` | the token |
| `POST /tokens/<ref>/rotate` | | `{token, secret}`: a new secret |

A **token** is `{id, label, grants, subject, parent, expiresAt, slideSeconds, createdAt,
createdBy, rotatedAt, rotatedBy, revokedAt, revokedBy, lastUsedAt, active}`. It never carries the
secret; `secret` is returned once, by create and rotate.

- `grants` are `"<action>:<resource>"` strings, returned in canonical form (sorted, without
  duplicates).
- Give `ttlSeconds` (from now) or `expiresAt` (ISO 8601), not both. Without either, an
  independent token never expires, and a child gets the cap.
- A child's lifetime is capped at `maxChildTtlSeconds`, on create and on every extend. Asking for
  more is not an error: `expiresAt` in the answer is what counts.
- `subject` is any JSON object up to 2 KB, kept with the token (a child's `{session, agent, host}`).
- Labels are lowercase letters, digits, `.`, `_`, `@` and `-`, at most 128. Labels starting with
  the service's session prefix (`session.` by default) are reserved for browser sessions.
- `createdBy`, `rotatedBy` and `revokedBy` record the caller's label.

## The rules

- `turnkey:manage` may do everything to every token. Anything it creates or grants must be
  covered by what it holds, and so must a token it rotates or extends (rotating hands over the
  secret; extending keeps the access alive).
- `turnkey:issue` may create children, within what it holds and without `turnkey:` permissions,
  and see, extend and revoke its own children.
- Any token may see itself (`GET /self`, `GET /tokens`) and revoke itself.
- A child never passes a `turnkey:` check, so it can't create, extend or change anything. Its
  permissions and secret are fixed; `grant`, `ungrant` and `rotate` refuse it with a 400.
- A child works only while its parent is live and still holds `turnkey:issue`, and only with the
  grants its parent still covers.
- Asking about a token the caller may not see is a 404, whether or not it exists.

## An orchestrator's calls

An orchestrator (something that starts jobs, agents or sandboxes) holds a token with
`turnkey:issue` plus the permissions it may hand out, and uses five calls:

1. `GET /self` once, to check its token and learn what it may hand out and the cap.
2. `POST /tokens` with `child` and `dryRun` when a job's configuration is saved, to check its
   permissions early.
3. `POST /tokens` with `child` when a job starts, asking for a lifetime (say 30 minutes), with
   the job's id as `name` so the child's actions are attributed to it.
4. `POST /tokens/<id>/extend` while the job runs (say every 10 minutes). A 404 means the child is
   gone (revoked, or expired before it was extended) and nothing will bring it back.
5. `POST /tokens/<id>/revoke` when the job ends, retrying until it works, or until the child has
   expired anyway. A 404 means it is already gone.

If the orchestrator stops, nobody extends its children and they expire on their own. Revoking
the orchestrator's token stops all of them at once.
