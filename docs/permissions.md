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
  - `turnkey:manage`: manage tokens (the Quiver commands need it; your own admin routes should too);
  - `turnkey:issue`: issue credentials (the contract routes need it).

  `turnkey:*` is both.

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

`can(principal, action, resource)` asks whether any grant covers `action:resource`. Coverage
between grants is the same test, and it is what enforces that an issuer can only issue what it
holds. A narrower grant never covers a wider one: `write:notes` does not cover `write:*`.

## Issued credentials and `turnkey:`

- Issuing refuses any `turnkey:` permission outright.
- An issued credential (a token with an issuer) **never passes a `turnkey:` check**, whatever it
  holds, even `*:*`. A leaked short-lived credential can't create a token that outlives it.
- Renewing re-checks coverage: once the issuer no longer holds a credential's permissions (or
  `turnkey:issue`), renewal is refused and the credential lapses at its expiry.

## What the grammar leaves to you

Ownership ("the author of this note"), conditions ("only during business hours"), and anything
else beyond action and path are the service's own checks. Turnkey tells you who is calling and
what they were granted; the service decides the rest.
