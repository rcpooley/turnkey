# Turnkey

API tokens with scoped permissions, kept in **your service's own database**. Turnkey is a library, not a service: each app imports it, and its
tokens live in two tables next to the app's own data. Nothing else has to be running for a request
to be authenticated.

- **One kind of token**, for hosts, scripts, people and jobs: `action:resource` permissions,
  optional expiry, rotate, revoke, an audit record of who did what, and "last used".
- **Child tokens**: a token holding `turnkey:issue` (an orchestrator) creates a short-lived token
  per job, extends it while the job runs, and revokes it after. A child holds at most what its
  parent holds and works only while its parent does; if the orchestrator dies, its children expire
  on their own.
- **Browser sessions** for an app that does its own login (a master password, or an OIDC
  provider): the session cookie is a token whose expiry slides forward while used.
- **One HTTP API** for all of it, ready to mount ([docs/api.md](docs/api.md)), plus ready-made
  Quiver commands and a break-glass CLI. All three apply the same rules.
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
| `children.maxTtlSeconds` | 3600 | Longest a child lives before its parent must extend it |
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

`implies` makes one action include others (`admin` → `write` → `read`). Turnkey reserves two
permissions of its own: `turnkey:manage` (every operation on every token) and `turnkey:issue`
(create children, and extend or revoke your own); `manage` includes `issue`. Full rules:
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

Every operation takes the **actor** asking for it. Pass the caller's principal and Turnkey applies
the rules; pass a string when it's your service's own code (a migration, a login handler), which
is trusted and recorded under that name.

```ts
// Your service's own code: trusted.
const { token, secret } = await tk.tokens.create({ label: 'build-server', grants: ['read:*'] }, 'setup')
// secret is shown once: nt_<43 chars>. Only its sha256 is stored.

// On behalf of a caller: needs turnkey:manage, and the caller must hold read:* itself.
await tk.tokens.create({ label: 'ci', grants: ['read:*'], ttlSeconds: 86_400 }, who)

await tk.tokens.list(who)                       // what `who` may see; { all: true } includes dead ones
await tk.tokens.get('build-server', who)        // by label or id; 404 if `who` may not see it
await tk.tokens.grant('build-server', ['write:notes'], who)
await tk.tokens.ungrant('build-server', ['write:notes'], who)
await tk.tokens.extend('ci', { ttlSeconds: 3600 }, who)   // moves the expiry; same secret
await tk.tokens.rotate('build-server', who)     // new secret, same label and permissions
await tk.tokens.revoke('build-server', who)     // its children stop with it
```

The rules ([docs/permissions.md](docs/permissions.md)):

| Actor | May |
|---|---|
| holds `turnkey:manage` | everything, on every token |
| holds `turnkey:issue` | create children; see, extend and revoke its own |
| any token | see and revoke itself (logging out is a session revoking itself) |
| anyone creating, granting, rotating or extending | give only what they hold |

A label belongs to one live token. Creating a label that only a revoked or expired token holds
replaces that row. For a backup, `tokens.export()` returns the live independent tokens with their
hashes, and `tokens.import()` brings them back with their secrets working.

## Children

A child is created by its parent, a token holding `turnkey:issue`:

```ts
const job = await tk.tokens.create({ child: true, name: 'job-42', grants: ['write:notes/abc'], ttlSeconds: 1800, subject: { session: 'job-42' } }, orchestrator)
// job.token.label is `<orchestrator label>.job-42`
await tk.tokens.extend(job.token.id, { ttlSeconds: 1800 }, orchestrator)   // the secret never changes
await tk.tokens.revoke(job.token.id, orchestrator)
```

- It holds only what its parent holds, and none of Turnkey's own permissions. It never passes a
  `turnkey:` check, so a leaked one can't create a token that outlives it.
- It expires within `children.maxTtlSeconds` (default an hour) and must be extended to live
  longer, so an orchestrator that dies leaves nothing behind for long.
- It works only while its parent is live and still holds `turnkey:issue`, and only with the
  grants its parent still covers. That's checked on every request: revoking or narrowing the
  parent applies to its children at once.
- `tk.tokens.check(input, who)` runs every check without creating anything (a dry run).

## Browser sessions

Your login checks the password (or finishes the OIDC flow), then:

```ts
import { sessionCookie, clearSessionCookie } from '@rcpooley/turnkey'

const cookie = { name: 'notes_session' }      // HttpOnly; Secure; SameSite=Lax by default

// login
const { token, secret } = await tk.sessions.create({ grants: ['admin:*', 'turnkey:manage'] }, 'password-login')
res.setHeader('Set-Cookie', sessionCookie(secret, token.expiresAt, cookie))

// logout: the session revokes itself. Or "log out everywhere" after a password change.
await tk.tokens.revoke(principal.id, principal)
await tk.sessions.revokeAll('password-changed')
res.setHeader('Set-Cookie', clearSessionCookie(cookie))
```

A session is a token labelled `<sessions.labelPrefix>.<random>` whose expiry slides forward while
it's used; other tokens can't take labels with that prefix. The adapters below read the cookie when there is no `Authorization` header, extend the
session while it is used (re-sending the cookie when they do), and refuse a cookie-authenticated
write (any method but GET/HEAD/OPTIONS) whose `Origin` is another site. Pass `trustedOrigins` to
allow a separate front end.

## The HTTP API

The same operations over HTTP, each authenticated by a Bearer token and held to the same rules:
`GET /self`, `GET|POST /tokens`, `GET /tokens/<ref>`, and `POST /tokens/<ref>/extend|revoke|grant|ungrant|rotate`.
An orchestrator needs only `self`, `POST /tokens` with `child` (and `dryRun`), `extend` and
`revoke`. Reference: [docs/api.md](docs/api.md).

## Adapters

**Express** (4 or 5):

```ts
import { authenticate, requirePermission, turnkeyRouter } from '@rcpooley/turnkey/express'

app.use('/turnkey', turnkeyRouter(tk))                                   // the token API
app.use('/api', authenticate(tk, { cookie: { name: 'notes_session' } }))  // sets req.principal; 401 without
app.post('/api/notes/:id', requirePermission(tk, 'write', (req) => `notes/${req.params.id}`), handler)
```

**`node:http`**:

```ts
import { principal, turnkeyHandler, sendError } from '@rcpooley/turnkey/node'

const tokenApi = turnkeyHandler(tk, { prefix: '/turnkey' })
http.createServer(async (req, res) => {
  if (await tokenApi(req, res)) return
  const who = await principal(tk, req, res, { cookie: { name: 'notes_session' } })
  …
})
```

**fetch-style** (`Request` → `Response`; Hono, Bun, Deno, workers):

```ts
import { authenticate, turnkeyHandler } from '@rcpooley/turnkey/fetch'

const tokenApi = turnkeyHandler(tk, { prefix: '/turnkey' })
app.all('/turnkey/*', async (c) => (await tokenApi(c.req.raw)) ?? c.notFound())
const { principal, headers } = await authenticate(tk, request, { cookie: { name: 'notes_session' } })
// add `headers` (a renewed cookie) to your response
```

Turnkey never adds routes on its own; you mount what you want, where you want. Errors are
`TurnkeyError`s with `status` and `code`; the adapters answer them as `{error, code}`.

## Quiver commands

[`@rcpooley/turnkey/quiver`](src/quiver.ts) gives a service's Quiver module a ready-made
`tokens` group (`list | show | create | extend | grant | ungrant | revoke | rotate`): the same
operations and rules. Add `commands` to your manifest and send those command paths to `run`, with
the caller's principal:

```ts
import { tokenCommands } from '@rcpooley/turnkey/quiver'
const tokens = tokenCommands(tk)
manifest.commands.push(...tokens.commands)
if (tokens.handles(command)) return tokens.run(command, params, principal)
```

## Break-glass CLI

For the first token, or after you revoked your own: wire `runAdminCli` into your service's admin
entry point. It talks to the database directly and checks no permission (its actor is
`admin-cli`). Commands: `list`, `show`, `create`, `extend`, `grant`, `ungrant`, `revoke`, `rotate`.

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

**Dolt.** Dolt versions every change, and extending children every few minutes would flood your
history. On Dolt, Turnkey adds `<tablePrefix>%` to `dolt_ignore` before creating its tables and
commits only that change (author: the `doltAuthor` option). Its tables then live in the working
set and never enter a commit, including your own `DOLT_COMMIT('-A')`. If your backup dumps
committed tables only, it won't contain Turnkey's; after a restore, startup recreates the rule and
the (empty) tables. Save `tokens.export()` in your backup and `tokens.import()` it on restore if
your tokens must survive one.

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
