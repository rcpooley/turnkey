# The credential contract

An orchestrator (something that starts jobs, agents or sandboxes) gives each job short-lived
credentials for the services it uses. It doesn't know how any service's credentials work: each
service implements this small HTTP contract, and Turnkey implements it for you
(`credentialsRouter`, `credentialsHandler`).

## The lease model

- The orchestrator **issues** a credential when a job starts, asking for a lifetime (say 30 minutes).
- While the job runs, it **renews** it periodically (say every 10 minutes).
- When the job ends, it **revokes** it, retrying until that works or the credential expires.
- If the orchestrator stops, nobody renews, and every credential **expires on its own**.

**Renewing never changes the credential.** A job's environment is fixed when it starts, so the
value it was given must keep working; only the expiry moves.

## The calls

The service is registered with the orchestrator by a **base URL** and an **issuer token**. Every
call sends `Authorization: Bearer <issuer token>`. Requests and responses are JSON. An error is a
non-2xx status with `{"error": "<message>", "code"?: "<code>"}`.

| Call | Request | Response |
|---|---|---|
| `GET <base>/describe` | | `{service, maxTtlSeconds, values: {token: "<what it is>"}, permissions: "<format help>", grants}` |
| `POST <base>/validate` | `{permissions}` | 200 if acceptable; 400 for a bad shape; 403 beyond what the issuer may grant |
| `POST <base>/issue` | `{subject: {session, agent?, host?}, permissions, ttlSeconds}` | `{id, expiresAt, values: {token}}` |
| `POST <base>/renew` | `{id, ttlSeconds}` | `{id, expiresAt}`; **404** (`code: "not_found"`) once revoked or expired |
| `POST <base>/revoke` | `{id}` | `{id, revoked}`, 200 also when it was already gone |

- `permissions` is `{"grants": ["<action>:<resource>", …]}` and nothing else.
- The service may give less than `ttlSeconds`, up to `maxTtlSeconds`. `expiresAt` (ISO 8601) is
  what counts.
- `id` is the credential's handle, not a secret. `values.token` is the secret, returned once.
- The credential is labelled `<issuer label>.<subject.session>`, so what it does is attributed to
  the job.
- The issuer token must hold `turnkey:issue`. It can issue only permissions it holds itself (its
  **ceiling**), so a compromised orchestrator can't hand out more than it was allowed. `grants` in
  `describe` lists that ceiling.
- An issuer sees only its own credentials: renewing or revoking another issuer's is a 404 or a
  no-op.
- Revoking the issuer token revokes every credential it issued.
