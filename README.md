# Turnkey

API tokens, scoped permissions, browser sessions and short-lived issued credentials, kept in
**your service's own database**. Turnkey is a library, not a service: each app imports it, and its
tokens live in two tables next to the app's own data. Nothing else has to be running for a request
to be authenticated.

- **Tokens** for hosts, scripts and people: `action:resource` permissions, optional expiry,
  rotate, revoke, an audit record of who did what, and "last used".
- **Browser sessions** for an app that does its own login (a master password, or an OIDC
  provider): the session cookie is a Turnkey token that slides forward while used.
- **Issued credentials**: an orchestrator holding an issuer token asks for a short-lived token per
  job, renews it while the job runs, and revokes it after. If the orchestrator dies, the credentials
  expire on their own. The HTTP routes for this are ready-made ([the contract](docs/credential-contract.md)).
- **Postgres** (`pg`, `postgres.js`), **MySQL and Dolt** (`mysql2`), **SQLite** (`node:sqlite`).
- **Express, `node:http`, and fetch-style** (`Request`/`Response`, e.g. Hono) adapters.
- **Zero runtime dependencies.** You pass in the database client you already have.

What it does **not** do: check passwords, speak OAuth/OIDC, hold user accounts, rate-limit, or
store secrets for you. Your app proves who someone is; Turnkey keeps track of what each token
may do.

```sh
npm install @rcpooley/turnkey
```

Node 22.13 or newer.

## Setup

```ts
import { createTurnkey } from '@rcpooley/turnkey'
import { pg } from '@rcpooley/turnkey/db'     // or postgresJs(sql), mysql2(pool), nodeSqlite(db)

const tk = await createTurnkey({
  db: pg(pool),
  tokenPrefix: 'nt_',                          // your service's recognisable token format
  permissions: {
    actions: ['read', 'write', 'admin'],
    implies: { admin: ['write'], write: ['read'] },
  },
})
```

`createTurnkey` takes a database lock, applies any pending migrations to its own tables
(`turnkey_tokens`, `turnkey_migrations`), checks they match what this version expects, and starts
an hourly purge of long-dead rows. It refuses to start if a migration was altered or the database
was written by a newer Turnkey. All options are in [`src/turnkey.ts`](src/turnkey.ts)
(`TurnkeyOptions`); the common ones:

| Option | Default | |
|---|---|---|
| `tokenPrefix` | `tk_` | Every secret starts with it |
| `tablePrefix` | `turnkey_` | Table names, and the Dolt ignore pattern |
| `retentionDays` | 30 | How long revoked/expired rows are kept for the record |
| `credentials.maxTtlSeconds` | 3600 | Longest an issued credential lives before renewal |
| `sessions.ttlSeconds` | 30 days | Browser session lifetime (slides while used) |
| `purgeIntervalMs` | 1 hour | `false` to call `tk.purge()` yourself |

## Permissions

A permission is `action:resource`. Resources are `/`-separated paths matched hierarchically:

| Permission | Allows |
|---|---|
| `read:*` | read anything |
| `write:notes` | write `notes`, `notes/abc`, `notes/abc/attachments/1`, … |
| `write:notes/abc` | write `notes/abc` and below, not `notes/xyz` |
| `exec:jobs/*/run` | `exec` on `jobs/<anything>/run` and below |
| `*:*` | everything, including Turnkey's own permissions |

`implies` makes one action include others (`admin` → `write` → `read`). Turnkey reserves
`turnkey:manage` (manage tokens) and `turnkey:issue` (issue credentials). Full rules:
[docs/permissions.md](docs/permissions.md).

```ts
const who = await tk.authenticate(req.headers.authorization)  // Principal | null
if (tk.can(who, 'write', `notes/${id}`)) { … }
tk.require(who, 'write', `notes/${id}`)                       // throws TurnkeyError 401/403
```

`authenticate` reads the database on every call, so a revoke applies on the very next request.
Anything the grammar can't say (ownership, conditions) your service checks itself, after Turnkey
has said who is calling.

## Tokens

```ts
const { token, secret } = await tk.tokens.create({ label: 'build-server', grants: ['read:*'], createdBy: who.label })
// secret is shown once: nt_<43 chars>. Only its sha256 is stored.

await tk.tokens.list()                       // active ones; { all: true } includes revoked/expired
await tk.tokens.get('build-server')          // by label or id
await tk.tokens.grant('build-server', ['write:notes'])
await tk.tokens.ungrant('build-server', ['write:notes'])
await tk.tokens.rotate('build-server', who.label)   // new secret, same label and permissions
await tk.tokens.revoke('build-server', who.label)   // also revokes credentials it issued
await tk.tokens.import({ label: 'old', secretHash: sha256hex, grants: ['read:*'], createdBy: 'migration' })
```

A label belongs to one live token. Creating a label that only a revoked or expired token holds
replaces that row.

## Browser sessions

Your login checks the password (or finishes the OIDC flow), then:

```ts
import { sessionCookie, clearSessionCookie } from '@rcpooley/turnkey'

const cookie = { name: 'notes_session' }      // HttpOnly; Secure; SameSite=Lax by default

// login
const { token, secret } = await tk.sessions.create({ grants: ['admin:*', 'turnkey:manage'], createdBy: 'password-login' })
res.setHeader('Set-Cookie', sessionCookie(secret, token.expiresAt, cookie))

// logout, or "log out everywhere" after a password change
await tk.sessions.revoke(principal, 'logout')
await tk.sessions.revokeAll('password-changed')
res.setHeader('Set-Cookie', clearSessionCookie(cookie))
```

The adapters below read the cookie when there is no `Authorization` header, extend the session
while it is used (re-sending the cookie when they do), and refuse a cookie-authenticated write
(any method but GET/HEAD/OPTIONS) whose `Origin` is another site. Pass `trustedOrigins` to allow
a separate front end.

## Issued credentials

An issuer token holds `turnkey:issue` plus the permissions it may hand out. It can issue only what
it holds, never a `turnkey:` permission, and an issued credential never passes a `turnkey:` check
whatever it holds, so a leaked one can't mint a token that outlives it.

```ts
const c = await tk.credentials.issue(issuer, { grants: ['write:notes/abc'], ttlSeconds: 1800, subject: { session: 'job-42' } })
await tk.credentials.renew(issuer, c.id, 1800)   // moves the expiry; the secret never changes
await tk.credentials.revoke(issuer, c.id)        // idempotent
```

Over HTTP, the adapters below serve the contract's five routes ([docs/credential-contract.md](docs/credential-contract.md)).

## Adapters

**Express** (4 or 5):

```ts
import { authenticate, requirePermission, credentialsRouter } from '@rcpooley/turnkey/express'

app.use('/credentials', credentialsRouter(tk, { service: 'notes' }))
app.use('/api', authenticate(tk, { cookie: { name: 'notes_session' } }))  // sets req.principal; 401 without
app.post('/api/notes/:id', requirePermission(tk, 'write', (req) => `notes/${req.params.id}`), handler)
```

**`node:http`**:

```ts
import { principal, credentialsHandler, sendError } from '@rcpooley/turnkey/node'

const credentials = credentialsHandler(tk, { service: 'notes', prefix: '/credentials' })
http.createServer(async (req, res) => {
  if (await credentials(req, res)) return
  const who = await principal(tk, req, res, { cookie: { name: 'notes_session' } })
  …
})
```

**fetch-style** (`Request` → `Response`; Hono, Bun, Deno, workers):

```ts
import { authenticate, credentialsHandler } from '@rcpooley/turnkey/fetch'

const credentials = credentialsHandler(tk, { service: 'notes' })
app.all('/credentials/*', async (c) => (await credentials(c.req.raw)) ?? c.notFound())
const { principal, headers } = await authenticate(tk, request, { cookie: { name: 'notes_session' } })
// add `headers` (a renewed cookie) to your response
```

Turnkey never adds routes on its own; you mount what you want, where you want. Errors are
`TurnkeyError`s with `status` and `code`; the adapters answer them as `{error, code}`.

## Quiver commands

[`@rcpooley/turnkey/quiver`](src/quiver.ts) gives a service's Quiver module a ready-made
`tokens` group (`list | show | create | grant | ungrant | revoke | rotate | credentials`). Add
`commands` to your manifest and send those command paths to `run`, with the caller's principal:

```ts
import { tokenCommands } from '@rcpooley/turnkey/quiver'
const tokens = tokenCommands(tk)
manifest.commands.push(...tokens.commands)
if (tokens.handles(command)) return tokens.run(command, params, principal)   // needs turnkey:manage
```

## Break-glass CLI

For the first token, or after you revoked your own: wire `runAdminCli` into your service's admin
entry point. It talks to the database directly and checks no permission.

```ts
import { runAdminCli } from '@rcpooley/turnkey'
process.exitCode = await runAdminCli(tk, process.argv.slice(2))
// my-service-admin token create ops --grant '*:*'
```

## Databases

| Driver | Adapter | Notes |
|---|---|---|
| `pg` Pool | `pg(pool)` | Startup migrates in one transaction under `pg_advisory_xact_lock` |
| postgres.js | `postgresJs(sql)` | Don't enable a column-name `transform` on the instance you pass |
| `mysql2/promise` Pool | `mysql2(pool)` | MySQL 8 and Dolt. Startup holds `GET_LOCK` |
| `node:sqlite` DatabaseSync | `nodeSqlite(db)` | Startup runs in `BEGIN IMMEDIATE` |

Timestamps are stored as fixed-width ISO 8601 UTC text, so they compare the same way in every
dialect and stay readable in a SQL console.

**Dolt.** Dolt versions every change, and renewing credentials every few minutes would flood your
history. On Dolt, Turnkey adds `<tablePrefix>%` to `dolt_ignore` before creating its tables and
commits only that change (author: the `doltAuthor` option). Its tables then live in the working
set and never enter a commit, including your own `DOLT_COMMIT('-A')`. If your backup dumps
committed tables only, it won't contain Turnkey's; after a restore, startup recreates the rule and
the (empty) tables. Copy the `<prefix>tokens` table from the working set in your backup if
permanent tokens must survive a restore.

## Developing

```sh
npm install
scripts/test-dolt.sh start        # a throwaway Dolt server on 127.0.0.1:3518 (needs `dolt`)
npm test                          # builds, then runs the suite on every reachable database
```

The behaviour suite ([`test/behaviour.test.mjs`](test/behaviour.test.mjs)) runs against Postgres
through both drivers, Dolt and SQLite; a database that isn't reachable is skipped locally and fails
CI. Set `TURNKEY_TEST_PG` and `TURNKEY_TEST_DOLT` to point it elsewhere, or `TURNKEY_TEST_ONLY=sqlite`
for a quick run. The suite is the spec: a port to another language has to pass it.

Design and decisions: [docs/design.md](docs/design.md).

## License

MIT
