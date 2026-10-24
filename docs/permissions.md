# Permissions

A permission is `action:resource`. A token holds a list of them (its *grants*), stored sorted and
de-duplicated.

## Actions

- The service declares its actions: `permissions: { actions: ['read', 'write', 'admin'] }`.
  Lowercase letters, digits, `_` and `-`, starting with a letter.
- `implies` says one action includes others: `{ admin: ['write'], write: ['read'] }`. It is
  transitive, so `admin` also includes `read`.
- `*` is every action, including Turnkey's own.
- `turnkey` is reserved for Turnkey's two permissions:
  - `turnkey:manage`: every operation on every token (your own admin routes should require it too);
  - `turnkey:issue`: create child tokens, and see, extend and revoke your own.

  `manage` includes `issue`. `turnkey:*` is both.

## Resources

- A resource is a path of segments separated by `/`: `notes`, `notes/abc`, `jobs/42/logs`.
- A segment is any run of visible characters except `/`, `:` and `*`, or `*` alone.
- A grant covers its own path **and everything below it**: `write:notes` covers `notes/abc` and
  `notes/abc/attachments/1`.
- A `*` segment matches any one segment: `exec:jobs/*/run` covers `jobs/42/run` and
  `jobs/42/run/now`, not `jobs/42/logs`.
- A resource of `*` alone covers everything.

## Coverage

Permission A **covers** permission B when:

1. A's action is `*`, equals B's, or implies B's; and
2. A's resource is `*`, or A's resource has no more segments than B's and each of A's segments
   is `*` or equals B's segment in the same place.

`turnkey:manage` also covers `turnkey:issue`.

`can(principal, action, resource)` asks whether any grant covers `action:resource`. Coverage
between grants is the same test. A narrower grant never covers a wider one: `write:notes` does
not cover `write:*`.

## Who may do what to tokens

Every token operation takes the actor asking. A string actor is the service's own code and is
trusted. A principal is held to these rules:

| Actor | May |
|---|---|
| holds `turnkey:manage` | everything, on every token: create (any lifetime), list, show, extend, grant, ungrant, rotate, revoke |
| holds `turnkey:issue` | create children; list, show, extend and revoke its own children |
| any token | see itself, and revoke itself |

**You can give only what you hold.** Creating a token, and granting to one, needs every new
permission to be covered by the actor's own grants. That includes Turnkey's: only a token holding
`turnkey:manage` can create another that holds it.

Rotating a token hands its new secret to the actor, and extending one keeps its access alive, so
both need the actor to cover everything that token holds (a parent extending its own child always
does). Revoking and ungranting only take access away, so `turnkey:manage` may do them to any token.

A token the actor may not see is a 404 to it, whether or not it exists.

## Children

A **child** is a token created by its **parent**, a token holding `turnkey:issue`.

- It holds only permissions its parent covers, and never a `turnkey:` permission. Creating one
  refuses `turnkey:` permissions outright.
- It **never passes a `turnkey:` check**, whatever it holds, even `*:*`. It can't create, extend
  or change tokens, so a leaked one can't make a token that outlives it.
- It always expires, within `children.maxTtlSeconds` (default an hour), on create and on every
  extend. Only its parent, or `turnkey:manage`, may extend it.
- It works only **while its parent does**: on every request, Turnkey also reads the parent, and
  the child is refused once the parent is revoked, expired or deleted, or no longer holds
  `turnkey:issue`. Its grants are narrowed to those the parent still covers. Nothing is written to
  the child, so revoking or narrowing a parent applies to its children at once.
- Its label is `<parent label>.<name>`, so what it does is attributed to the job it was made for.
  The name is shortened to fit; a parent whose label is longer than 111 characters can't have
  children. A child never takes over a dead label that isn't its own parent's child's: it gets a
  suffix instead. The `parent` field, not the label, says whose child it is.
- Its permissions and secret are fixed: `grant`, `ungrant` and `rotate` refuse it. Revoke it and
  create another instead.

## What the grammar leaves to you

Ownership ("the author of this note"), conditions ("only during business hours"), and anything
else beyond action and path are the service's own checks. Turnkey tells you who is calling and
what they were granted; the service decides the rest.
