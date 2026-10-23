// The behaviour suite: every API function and rule, run against every dialect. This file is also
// the spec a port to another language has to pass.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createTurnkey } from '../dist/index.js'
import { available, clock, fresh, PERMISSIONS, principalWith } from './helpers.mjs'

const sha = (s) => createHash('sha256').update(s).digest('hex')
const rejects = (p, status, re) => assert.rejects(p, (e) => e.status === status && (!re || re.test(e.message)))

for (const backend of await available()) {
  describe(`behaviour on ${backend.name}`, () => {
    // ------------------------------------------------------------------ tokens

    test('create, authenticate and the secret format', async () => {
      const t = await fresh(backend)
      try {
        const { token, secret } = await t.tk.tokens.create({ label: 'dev', grants: ['write:things', 'read:*', 'read:*'], createdBy: 'alice' })
        assert.match(secret, /^tt_[A-Za-z0-9_-]{43}$/)
        assert.deepEqual(token.grants, ['read:*', 'write:things'])
        assert.equal(token.kind, 'token')
        assert.equal(token.createdBy, 'alice')
        assert.equal(token.active, true)
        const p = await t.tk.authenticate(secret)
        assert.equal(p.label, 'dev')
        assert.equal(p.id, token.id)
        assert.deepEqual(p.grants, ['read:*', 'write:things'])
        assert.equal(p.issuedBy, null)
        assert.equal((await t.tk.authenticate(`Bearer ${secret}`)).id, token.id)
        assert.equal((await t.tk.authenticate(`bearer   ${secret}  `)).id, token.id)
        // Only the hash is stored.
        const [row] = await t.env.raw.query(`SELECT secret_hash FROM ${t.env.prefix}tokens WHERE id = ?`, [token.id])
        assert.equal(row.secret_hash, sha(secret))
        for (const bad of [null, undefined, '', 'Bearer ', secret + 'x', 'xx_' + secret.slice(3), secret.slice(0, -1), 'Basic abc']) {
          assert.equal(await t.tk.authenticate(bad), null, String(bad))
        }
      } finally {
        await t.close()
      }
    })

    test('labels are unique while live; a revoked or expired label is taken over', async () => {
      const t = await fresh(backend)
      try {
        await t.tk.tokens.create({ label: 'ci', grants: ['read:*'], createdBy: 'x' })
        await rejects(t.tk.tokens.create({ label: 'ci', grants: ['read:*'], createdBy: 'x' }), 409)
        await rejects(t.tk.tokens.create({ label: 'Bad Label', grants: ['read:*'], createdBy: 'x' }), 400)
        await rejects(t.tk.tokens.create({ label: 'ok', grants: [], createdBy: 'x' }), 400)
        await rejects(t.tk.tokens.create({ label: 'ok', grants: ['nope:x'], createdBy: 'x' }), 400)
        await rejects(t.tk.tokens.create({ label: 'ok', grants: ['read:*'], createdBy: '' }), 400)
        await t.tk.tokens.revoke('ci', 'x')
        const again = await t.tk.tokens.create({ label: 'ci', grants: ['write:*'], createdBy: 'x' })
        assert.deepEqual(again.token.grants, ['write:*'])
        await t.tk.tokens.create({ label: 'short', grants: ['read:*'], createdBy: 'x', expiresAt: new Date(t.clock.ms + 60_000) })
        t.clock.advance(61)
        await t.tk.tokens.create({ label: 'short', grants: ['read:*'], createdBy: 'x' })
      } finally {
        await t.close()
      }
    })

    test('can and require: hierarchy, implies, and the 403', async () => {
      const t = await fresh(backend)
      try {
        const { principal: p } = await principalWith(t.tk, 'a', ['write:sessions/abc', 'read:projects'])
        assert.ok(t.tk.can(p, 'write', 'sessions/abc'))
        assert.ok(t.tk.can(p, 'read', 'sessions/abc/files'), 'write implies read, and paths nest')
        assert.ok(!t.tk.can(p, 'write', 'sessions/abd'))
        assert.ok(!t.tk.can(p, 'write', 'sessions'))
        assert.ok(t.tk.can(p, 'read', 'projects/x'))
        assert.ok(!t.tk.can(p, 'write', 'projects/x'))
        assert.ok(!t.tk.can(p, 'turnkey', 'manage'))
        assert.ok(!t.tk.can(null, 'read', 'projects'))
        assert.ok(!t.tk.can(p, 'bogus', 'x'), 'an unknown action is simply not allowed')
        assert.throws(() => t.tk.require(p, 'write', 'projects/x'), (e) => e.status === 403 && /may not write projects\/x/.test(e.message))
        assert.throws(() => t.tk.require(null, 'read', 'x'), (e) => e.status === 401)
        t.tk.require(p, 'read', 'projects')
      } finally {
        await t.close()
      }
    })

    test('expiry is checked on every lookup', async () => {
      const t = await fresh(backend)
      try {
        const { secret } = await t.tk.tokens.create({ label: 'tmp', grants: ['read:*'], createdBy: 'x', expiresAt: new Date(t.clock.ms + 10_000).toISOString() })
        assert.ok(await t.tk.authenticate(secret))
        t.clock.advance(10)
        assert.equal(await t.tk.authenticate(secret), null)
        assert.equal((await t.tk.tokens.list()).length, 0)
        assert.equal((await t.tk.tokens.list({ all: true })).length, 1)
        assert.equal((await t.tk.tokens.get('tmp')).active, false)
        await rejects(t.tk.tokens.create({ label: 'past', grants: ['read:*'], createdBy: 'x', expiresAt: new Date(t.clock.ms - 1000) }), 400)
        await rejects(t.tk.tokens.create({ label: 'bad', grants: ['read:*'], createdBy: 'x', expiresAt: 'tomorrow' }), 400)
      } finally {
        await t.close()
      }
    })

    test('grant and ungrant keep canonical form', async () => {
      const t = await fresh(backend)
      try {
        const { secret } = await t.tk.tokens.create({ label: 'g', grants: ['read:a'], createdBy: 'x' })
        let info = await t.tk.tokens.grant('g', ['write:b', 'read:a'])
        assert.deepEqual(info.grants, ['read:a', 'write:b'])
        assert.deepEqual((await t.tk.authenticate(secret)).grants, ['read:a', 'write:b'], 'applies on the next request')
        info = await t.tk.tokens.ungrant(info.id, ['read:a'])
        assert.deepEqual(info.grants, ['write:b'])
        await rejects(t.tk.tokens.ungrant('g', ['read:zzz']), 400, /has no permission/)
        await rejects(t.tk.tokens.ungrant('g', ['write:b']), 400, /revoke it instead/)
        await rejects(t.tk.tokens.grant('nope', ['read:a']), 404)
      } finally {
        await t.close()
      }
    })

    test('revoke applies on the next request, is recorded, and takes issued credentials with it', async () => {
      const t = await fresh(backend)
      try {
        const { secret, principal: issuer } = await principalWith(t.tk, 'launcher', ['turnkey:issue', 'read:*'])
        const c = await t.tk.credentials.issue(issuer, { grants: ['read:x'], subject: { session: 's1' } })
        assert.ok(await t.tk.authenticate(c.secret))
        const info = await t.tk.tokens.revoke('launcher', 'alice')
        assert.equal(info.revokedBy, 'alice')
        assert.ok(info.revokedAt)
        assert.equal(await t.tk.authenticate(secret), null)
        assert.equal(await t.tk.authenticate(c.secret), null, "the issuer's credential went with it")
        const again = await t.tk.tokens.revoke('launcher', 'someone-else')
        assert.equal(again.revokedBy, 'alice', 'idempotent: the first revoke stays on record')
        await rejects(t.tk.tokens.revoke('missing', 'x'), 404)
      } finally {
        await t.close()
      }
    })

    test('rotate replaces the secret and keeps everything else', async () => {
      const t = await fresh(backend)
      try {
        const { token, secret } = await t.tk.tokens.create({ label: 'r', grants: ['read:*'], createdBy: 'x' })
        const r = await t.tk.tokens.rotate('r', 'alice')
        assert.notEqual(r.secret, secret)
        assert.equal(r.token.id, token.id)
        assert.equal(r.token.rotatedBy, 'alice')
        assert.equal(await t.tk.authenticate(secret), null)
        assert.equal((await t.tk.authenticate(r.secret)).label, 'r')
        await t.tk.tokens.revoke('r', 'x')
        await rejects(t.tk.tokens.rotate('r', 'x'), 404, /revoked or expired/)
      } finally {
        await t.close()
      }
    })

    test('import keeps an existing secret working', async () => {
      const t = await fresh(backend)
      try {
        const old = 'tt_existing-secret-from-another-system'
        const info = await t.tk.tokens.import({ label: 'legacy', secretHash: sha(old), grants: ['read:*'], createdBy: 'migration', createdAt: '2025-05-05T00:00:00Z' })
        assert.equal(info.createdAt, '2025-05-05T00:00:00.000Z')
        assert.equal((await t.tk.authenticate(old)).label, 'legacy')
        await rejects(t.tk.tokens.import({ label: 'x', secretHash: 'nothex', grants: ['read:*'], createdBy: 'm' }), 400)
        await rejects(t.tk.tokens.import({ label: 'y', secretHash: sha(old), grants: ['read:*'], createdBy: 'm' }), 409)
      } finally {
        await t.close()
      }
    })

    test('last_used_at is recorded, at most every few minutes', async () => {
      const t = await fresh(backend)
      try {
        const { token, secret } = await t.tk.tokens.create({ label: 'u', grants: ['read:*'], createdBy: 'x' })
        assert.equal(token.lastUsedAt, null)
        await t.tk.authenticate(secret)
        const first = (await t.tk.tokens.get('u')).lastUsedAt
        assert.equal(first, t.clock.now().toISOString())
        t.clock.advance(60)
        await t.tk.authenticate(secret)
        assert.equal((await t.tk.tokens.get('u')).lastUsedAt, first, 'not rewritten within five minutes')
        t.clock.advance(300)
        await t.tk.authenticate(secret)
        assert.equal((await t.tk.tokens.get('u')).lastUsedAt, t.clock.now().toISOString())
      } finally {
        await t.close()
      }
    })

    test('purge deletes rows dead longer than the retention period', async () => {
      const t = await fresh(backend, { retentionDays: 1 })
      try {
        await t.tk.tokens.create({ label: 'keep', grants: ['read:*'], createdBy: 'x' })
        await t.tk.tokens.create({ label: 'gone', grants: ['read:*'], createdBy: 'x' })
        await t.tk.tokens.create({ label: 'lapses', grants: ['read:*'], createdBy: 'x', expiresAt: new Date(t.clock.ms + 1000) })
        await t.tk.tokens.revoke('gone', 'x')
        t.clock.advance(3600)
        assert.equal(await t.tk.purge(), 0, 'still within retention')
        t.clock.advance(86_400)
        assert.equal(await t.tk.purge(), 2)
        assert.deepEqual((await t.tk.tokens.list({ all: true })).map((x) => x.label), ['keep'])
      } finally {
        await t.close()
      }
    })

    // ------------------------------------------------------------------ credentials

    test('issue: needs turnkey:issue, stays within what the issuer holds, never turnkey:', async () => {
      const t = await fresh(backend)
      try {
        const { principal: issuer } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'write:sessions', 'read:*'])
        const { principal: plain } = await principalWith(t.tk, 'plain', ['write:*'])
        await assert.rejects(() => t.tk.credentials.issue(plain, { grants: ['read:x'], subject: { session: 's' } }), (e) => e.status === 403)
        await assert.rejects(() => t.tk.credentials.issue(issuer, { grants: ['write:projects'], subject: { session: 's' } }), (e) => e.status === 403 && /write:projects/.test(e.message))
        await assert.rejects(() => t.tk.credentials.issue(issuer, { grants: ['turnkey:issue'], subject: { session: 's' } }), (e) => e.status === 403)
        await assert.rejects(() => t.tk.credentials.issue(issuer, { grants: [], subject: { session: 's' } }), (e) => e.status === 400)
        await assert.rejects(() => t.tk.credentials.issue(issuer, { grants: ['bad'], subject: { session: 's' } }), (e) => e.status === 400)

        const c = await t.tk.credentials.issue(issuer, { grants: ['write:sessions/abc', 'read:*'], ttlSeconds: 1800, subject: { session: 'Sess-ABC', agent: 'dev', host: 'h1' } })
        assert.equal(c.label, 'lp.sess-abc')
        assert.equal(c.expiresAt, new Date(t.clock.ms + 1800_000).toISOString())
        assert.match(c.id, /^tok_[0-9a-f]{24}$/)
        const p = await t.tk.authenticate(c.secret)
        assert.equal(p.kind, 'credential')
        assert.equal(p.issuedBy, issuer.id)
        assert.deepEqual(p.subject, { session: 'Sess-ABC', agent: 'dev', host: 'h1' })
        assert.ok(t.tk.can(p, 'write', 'sessions/abc'))
        assert.ok(!t.tk.can(p, 'write', 'sessions/abd'))

        const capped = await t.tk.credentials.issue(issuer, { grants: ['read:*'], ttlSeconds: 99_999, subject: { session: 'Sess-ABC' } })
        assert.equal(capped.expiresAt, new Date(t.clock.ms + 3600_000).toISOString(), 'capped at maxTtlSeconds')
        assert.notEqual(capped.label, c.label, 'a second credential for one session gets its own label')
        assert.ok(capped.label.startsWith('lp.sess-abc.'))
      } finally {
        await t.close()
      }
    })

    test('an issued credential never passes a turnkey check, whatever it holds', async () => {
      const t = await fresh(backend)
      try {
        const { principal: root } = await principalWith(t.tk, 'root', ['*:*'])
        assert.ok(t.tk.can(root, 'turnkey', 'manage'))
        assert.ok(t.tk.can(root, 'turnkey', 'issue'))
        const c = await t.tk.credentials.issue(root, { grants: ['*:*'], subject: { session: 's' } })
        const p = await t.tk.authenticate(c.secret)
        assert.ok(t.tk.can(p, 'write', 'anything'))
        assert.ok(!t.tk.can(p, 'turnkey', 'manage'))
        assert.ok(!t.tk.can(p, 'turnkey', 'issue'))
        assert.throws(() => t.tk.require(p, 'turnkey', 'manage'), /issued credential/)
        await assert.rejects(() => t.tk.credentials.issue(p, { grants: ['read:x'], subject: { session: 's2' } }), (e) => e.status === 403)
        await rejects(t.tk.tokens.rotate(c.id, 'x'), 400, /never rotated/)
      } finally {
        await t.close()
      }
    })

    test('renew moves only the expiry; 404 once revoked or expired', async () => {
      const t = await fresh(backend)
      try {
        const { principal: issuer } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'read:*'])
        const { principal: other } = await principalWith(t.tk, 'other', ['turnkey:issue', 'read:*'])
        const c = await t.tk.credentials.issue(issuer, { grants: ['read:x'], ttlSeconds: 1800, subject: { session: 's' } })
        t.clock.advance(600)
        const r = await t.tk.credentials.renew(issuer, c.id, 1800)
        assert.equal(r.expiresAt, new Date(t.clock.ms + 1800_000).toISOString())
        assert.ok(await t.tk.authenticate(c.secret), 'the secret is unchanged')
        assert.equal((await t.tk.authenticate(c.secret)).expiresAt, r.expiresAt)
        await rejects(t.tk.credentials.renew(other, c.id, 1800), 404, /no credential/)
        await rejects(t.tk.credentials.renew(issuer, 'tok_nope', 1800), 404)
        await rejects(t.tk.credentials.renew(issuer, c.id, 0), 400)
        t.clock.advance(1801)
        await assert.rejects(() => t.tk.credentials.renew(issuer, c.id, 1800), (e) => e.status === 404 && e.code === 'not_found')
        assert.equal(await t.tk.authenticate(c.secret), null)

        const d = await t.tk.credentials.issue(issuer, { grants: ['read:x'], subject: { session: 's2' } })
        await t.tk.credentials.revoke(issuer, d.id)
        await rejects(t.tk.credentials.renew(issuer, d.id), 404)
      } finally {
        await t.close()
      }
    })

    test('renew is refused once the issuer no longer holds the permissions', async () => {
      const t = await fresh(backend)
      try {
        await t.tk.tokens.create({ label: 'lp', grants: ['turnkey:issue', 'write:a', 'read:b'], createdBy: 'x' })
        const { secret } = await t.tk.tokens.rotate('lp', 'x')
        const issuer = await t.tk.authenticate(secret)
        const c = await t.tk.credentials.issue(issuer, { grants: ['write:a'], subject: { session: 's' } })
        await t.tk.tokens.ungrant('lp', ['write:a'])
        const narrowed = await t.tk.authenticate(secret)
        await assert.rejects(() => t.tk.credentials.renew(narrowed, c.id, 60), (e) => e.status === 403 && /write:a/.test(e.message))
        await t.tk.tokens.ungrant('lp', ['turnkey:issue'])
        const noIssue = await t.tk.authenticate(secret)
        await assert.rejects(() => t.tk.credentials.renew(noIssue, c.id, 60), (e) => e.status === 403)
      } finally {
        await t.close()
      }
    })

    test('credential revoke is idempotent and scoped to its issuer', async () => {
      const t = await fresh(backend)
      try {
        const { principal: issuer } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'read:*'])
        const { principal: other } = await principalWith(t.tk, 'other', ['turnkey:issue', 'read:*'])
        const c = await t.tk.credentials.issue(issuer, { grants: ['read:x'], subject: { session: 's' } })
        assert.deepEqual(await t.tk.credentials.revoke(other, c.id), { id: c.id, revoked: false })
        assert.ok(await t.tk.authenticate(c.secret), "another issuer can't revoke it")
        assert.deepEqual(await t.tk.credentials.revoke(issuer, c.id), { id: c.id, revoked: true })
        assert.deepEqual(await t.tk.credentials.revoke(issuer, c.id), { id: c.id, revoked: false })
        assert.deepEqual(await t.tk.credentials.revoke(issuer, 'tok_unknown'), { id: 'tok_unknown', revoked: false })
        assert.equal(await t.tk.authenticate(c.secret), null)
        const mine = await t.tk.credentials.issue(issuer, { grants: ['read:x'], subject: { session: 'z' } })
        await t.tk.credentials.issue(other, { grants: ['read:x'], subject: { session: 'z' } })
        assert.deepEqual((await t.tk.credentials.list(issuer)).map((x) => x.id), [mine.id])
        assert.equal((await t.tk.credentials.list()).length, 2)
      } finally {
        await t.close()
      }
    })

    // ------------------------------------------------------------------ sessions

    test('browser sessions expire, slide forward while used, and log out', async () => {
      const t = await fresh(backend, { sessions: { ttlSeconds: 86_400 } })
      try {
        const { token, secret } = await t.tk.sessions.create({ grants: ['admin:*', 'turnkey:manage'], createdBy: 'password-login', subject: { userAgent: 'test' } })
        assert.equal(token.kind, 'session')
        assert.match(token.label, /^session\.[0-9a-f]{12}$/)
        assert.equal(token.slideSeconds, 86_400)
        let p = await t.tk.authenticate(secret)
        assert.equal(p.renewed, false)
        assert.ok(t.tk.can(p, 'turnkey', 'manage'), 'a session (not an issued credential) may manage tokens')
        t.clock.advance(3 * 3600)
        p = await t.tk.authenticate(secret)
        assert.equal(p.renewed, true)
        assert.equal(p.expiresAt, new Date(t.clock.ms + 86_400_000).toISOString())
        t.clock.advance(60)
        assert.equal((await t.tk.authenticate(secret)).renewed, false, 'not extended again right away')
        t.clock.advance(86_400 - 120)
        assert.ok(await t.tk.authenticate(secret), 'still alive a full ttl after the last extension')
        t.clock.advance(86_401)
        assert.equal(await t.tk.authenticate(secret), null, 'idle longer than the ttl: expired')

        const fixed = await t.tk.sessions.create({ grants: ['read:*'], createdBy: 'x', ttlSeconds: 100, slide: false })
        t.clock.advance(50)
        assert.equal((await t.tk.authenticate(fixed.secret)).renewed, false)
        t.clock.advance(51)
        assert.equal(await t.tk.authenticate(fixed.secret), null)

        const a = await t.tk.sessions.create({ grants: ['read:*'], createdBy: 'x' })
        const b = await t.tk.sessions.create({ grants: ['read:*'], createdBy: 'x' })
        const tok = await t.tk.tokens.create({ label: 'cli', grants: ['read:*'], createdBy: 'x' })
        await t.tk.sessions.revoke(await t.tk.authenticate(a.secret), 'logout')
        assert.equal(await t.tk.authenticate(a.secret), null)
        assert.ok(await t.tk.authenticate(b.secret))
        await rejects(t.tk.sessions.revoke('cli', 'x'), 400)
        assert.equal(await t.tk.sessions.revokeAll('password-changed'), 1)
        assert.equal(await t.tk.authenticate(b.secret), null)
        assert.ok(await t.tk.authenticate(tok.secret), 'tokens are not sessions')
      } finally {
        await t.close()
      }
    })

    // ------------------------------------------------------------------ migrations

    test('migrations: recorded once, a restart is a no-op', async () => {
      const t = await fresh(backend)
      try {
        const rows = await t.env.raw.query(`SELECT version, name, checksum FROM ${t.env.prefix}migrations`)
        assert.equal(rows.length, 1)
        assert.equal(Number(rows[0].version), 1)
        assert.match(String(rows[0].checksum), /^[0-9a-f]{64}$/)
        const { secret } = await t.tk.tokens.create({ label: 'kept', grants: ['read:*'], createdBy: 'x' })
        const again = await createTurnkey({ db: t.env.driver, tablePrefix: t.env.prefix, tokenPrefix: 'tt_', permissions: PERMISSIONS, purgeIntervalMs: false, now: t.clock.now })
        assert.ok(await again.authenticate(secret))
        assert.equal((await t.env.raw.query(`SELECT version FROM ${t.env.prefix}migrations`)).length, 1)
        await again.close()
      } finally {
        await t.close()
      }
    })

    test('migrations: refuses a changed checksum, a newer database, and a missing column', async () => {
      const t = await fresh(backend)
      const start = () => createTurnkey({ db: t.env.driver, tablePrefix: t.env.prefix, permissions: PERMISSIONS, purgeIntervalMs: false })
      try {
        await t.env.raw.run(`UPDATE ${t.env.prefix}migrations SET checksum = ? WHERE version = 1`, ['0'.repeat(64)])
        await assert.rejects(start, (e) => e.code === 'schema' && /changed after it was applied/.test(e.message))
        await t.env.raw.run(`DELETE FROM ${t.env.prefix}migrations WHERE version = 1`)
        await t.env.raw.run(`INSERT INTO ${t.env.prefix}migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`, [1, 'tokens', (await import('../dist/schema.js')).checksum((await import('../dist/schema.js')).MIGRATIONS[0], t.env.driver.dialect), 'x'])
        await t.env.raw.run(`INSERT INTO ${t.env.prefix}migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`, [999, 'future', 'f'.repeat(64), 'x'])
        await assert.rejects(start, (e) => e.code === 'schema' && /newer than this library/.test(e.message))
        await t.env.raw.run(`DELETE FROM ${t.env.prefix}migrations WHERE version = 999`)
        await (await start()).close()
        await t.env.raw.run(`ALTER TABLE ${t.env.prefix}tokens DROP COLUMN last_used_at`)
        await assert.rejects(start, (e) => e.code === 'schema' && /missing column\(s\) last_used_at/.test(e.message))
      } finally {
        await t.close()
      }
    })

    test('concurrent startup: the lock lets one migrate and the rest wait', async () => {
      const env = await backend.open()
      try {
        const opts = { db: env.driver, tablePrefix: env.prefix, permissions: PERMISSIONS, purgeIntervalMs: false }
        const all = await Promise.all([1, 2, 3, 4].map(() => createTurnkey(opts)))
        assert.equal((await env.raw.query(`SELECT version FROM ${env.prefix}migrations`)).length, 1)
        await Promise.all(all.map((x) => x.close()))
      } finally {
        await env.close()
      }
    })

    test('options are validated', async () => {
      const env = await backend.open()
      try {
        const base = { db: env.driver, tablePrefix: env.prefix, permissions: PERMISSIONS, purgeIntervalMs: false }
        await assert.rejects(() => createTurnkey({ ...base, tablePrefix: 'Bad-Prefix' }), /tablePrefix/)
        await assert.rejects(() => createTurnkey({ ...base, tokenPrefix: 'has space' }), /tokenPrefix/)
        await assert.rejects(() => createTurnkey({ ...base, permissions: { actions: ['turnkey'] } }), /reserved/)
        await assert.rejects(() => createTurnkey({ ...base, credentials: { maxTtlSeconds: 0 } }), /maxTtlSeconds/)
      } finally {
        await env.close()
      }
    })

    // ------------------------------------------------------------------ Dolt

    if (backend.name === 'dolt') {
      test('Dolt: tables are ignored, renewals make no commits, the service commits only its own tables', async () => {
        const t = await fresh(backend)
        try {
          assert.equal(t.tk.dolt, true)
          const [ig] = await t.env.raw.query("SELECT ignored FROM dolt_ignore WHERE pattern = 'turnkey_%'")
          assert.equal(Number(ig.ignored), 1)
          const [log] = await t.env.raw.query('SELECT message, committer FROM dolt_log LIMIT 1')
          assert.match(log.message, /turnkey: keep turnkey_% tables out of version control/)
          const commits = async () => Number((await t.env.raw.query('SELECT COUNT(*) AS n FROM dolt_log'))[0].n)
          const before = await commits()
          const { principal: issuer } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'read:*'])
          const c = await t.tk.credentials.issue(issuer, { grants: ['read:x'], subject: { session: 's' } })
          for (let i = 0; i < 5; i++) await t.tk.credentials.renew(issuer, c.id, 600)
          assert.equal(await commits(), before, 'no commits from issuing or renewing')
          // The service commits its own change with -A: Turnkey's tables stay out.
          await t.env.raw.run('INSERT INTO app_things VALUES (1)')
          await t.env.raw.query("CALL DOLT_ADD('-A')")
          await t.env.raw.query("CALL DOLT_COMMIT('-m', 'app change')")
          const tables = (await t.env.raw.query("SELECT table_name FROM dolt_diff WHERE commit_hash = HASHOF('HEAD')")).map((r) => r.table_name)
          assert.deepEqual(tables, ['app_things'])
          const atHead = (await t.env.raw.query("SHOW TABLES AS OF 'HEAD'")).map((r) => Object.values(r)[0])
          assert.ok(!atHead.some((n) => String(n).startsWith('turnkey_')), `committed tables: ${atHead}`)
        } finally {
          await t.close()
        }
      })

      test('Dolt: after a restore drops the tables and the ignore rule, startup redoes both', async () => {
        const t = await fresh(backend)
        try {
          await t.tk.tokens.create({ label: 'old', grants: ['read:*'], createdBy: 'x' })
          // A restore from a commit taken before Turnkey existed: no ignore rule, no tables.
          await t.env.raw.run('DROP TABLE turnkey_tokens')
          await t.env.raw.run('DROP TABLE turnkey_migrations')
          await t.env.raw.run("DELETE FROM dolt_ignore WHERE pattern = 'turnkey_%'")
          await t.env.raw.query("CALL DOLT_ADD('dolt_ignore')")
          await t.env.raw.query("CALL DOLT_COMMIT('-m', 'restore')")
          const tk2 = await createTurnkey({ db: t.env.driver, permissions: PERMISSIONS, purgeIntervalMs: false, doltAuthor: 'Svc <svc@example.com>' })
          const [ig] = await t.env.raw.query("SELECT ignored FROM dolt_ignore WHERE pattern = 'turnkey_%'")
          assert.equal(Number(ig.ignored), 1)
          const [log] = await t.env.raw.query('SELECT committer, email FROM dolt_log LIMIT 1')
          assert.equal(log.committer, 'Svc')
          assert.equal((await tk2.tokens.list({ all: true })).length, 0)
          await tk2.close()
        } finally {
          await t.close()
        }
      })
    }
  })
}
