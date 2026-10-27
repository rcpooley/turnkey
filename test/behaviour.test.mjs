// The behaviour suite: every API function and rule, run against every dialect. This file is also
// the spec a port to another language has to pass.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createTurnkey } from '../dist/index.js'
import { available, backends, childOf, clock, fresh, PERMISSIONS, principalWith } from './helpers.mjs'

const sha = (s) => createHash('sha256').update(s).digest('hex')
// `re` is a pattern the message must match, or a note saying why.
const rejects = (p, status, re) => assert.rejects(p, (e) => e.status === status && (!(re instanceof RegExp) || re.test(e.message)), typeof re === 'string' ? re : undefined)

for (const backend of await available()) {
  describe(`behaviour on ${backend.name}`, () => {
    // ------------------------------------------------------------------ tokens

    test('create, authenticate and the secret format', async () => {
      const t = await fresh(backend)
      try {
        const { token, secret } = await t.tk.tokens.create({ label: 'dev', grants: ['write:things', 'read:*', 'read:*'] }, 'alice')
        assert.match(secret, /^tt_[A-Za-z0-9_-]{43}$/)
        assert.deepEqual(token.grants, ['read:*', 'write:things'])
        assert.equal(token.parent, null)
        assert.equal(token.createdBy, 'alice')
        assert.equal(token.active, true)
        assert.equal(token.expiresAt, null)
        assert.ok(!('kind' in token), 'there is one kind of token')
        const p = await t.tk.authenticate(secret)
        assert.equal(p.label, 'dev')
        assert.equal(p.id, token.id)
        assert.deepEqual(p.grants, ['read:*', 'write:things'])
        assert.equal(p.parent, null)
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
        await t.tk.tokens.create({ label: 'ci', grants: ['read:*'] }, 'x')
        await rejects(t.tk.tokens.create({ label: 'ci', grants: ['read:*'] }, 'x'), 409)
        await rejects(t.tk.tokens.create({ label: 'Bad Label', grants: ['read:*'] }, 'x'), 400)
        await rejects(t.tk.tokens.create({ grants: ['read:*'] }, 'x'), 400, /bad label/)
        await rejects(t.tk.tokens.create({ label: 'ok', grants: [] }, 'x'), 400)
        await rejects(t.tk.tokens.create({ label: 'ok', grants: ['nope:x'] }, 'x'), 400)
        await rejects(t.tk.tokens.create({ label: 'ok', grants: ['read:*'] }, ''), 400)
        await rejects(t.tk.tokens.create({ label: 'ok', name: 'n', grants: ['read:*'] }, 'x'), 400, /name is for a child/)
        await t.tk.tokens.revoke('ci', 'x')
        const again = await t.tk.tokens.create({ label: 'ci', grants: ['write:*'] }, 'x')
        assert.deepEqual(again.token.grants, ['write:*'])
        await t.tk.tokens.create({ label: 'short', grants: ['read:*'], expiresAt: new Date(t.clock.ms + 60_000) }, 'x')
        t.clock.advance(61)
        await t.tk.tokens.create({ label: 'short', grants: ['read:*'] }, 'x')
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
        const { principal: m } = await principalWith(t.tk, 'm', ['turnkey:manage'])
        assert.ok(t.tk.can(m, 'turnkey', 'issue'), 'manage includes issue')
      } finally {
        await t.close()
      }
    })

    test('expiry: expiresAt or ttlSeconds, checked on every lookup', async () => {
      const t = await fresh(backend)
      try {
        const { secret } = await t.tk.tokens.create({ label: 'tmp', grants: ['read:*'], expiresAt: new Date(t.clock.ms + 10_000).toISOString() }, 'x')
        const ttl = await t.tk.tokens.create({ label: 'ttl', grants: ['read:*'], ttlSeconds: 20 }, 'x')
        assert.equal(ttl.token.expiresAt, new Date(t.clock.ms + 20_000).toISOString())
        assert.ok(await t.tk.authenticate(secret))
        t.clock.advance(10)
        assert.equal(await t.tk.authenticate(secret), null)
        assert.equal((await t.tk.tokens.list('x')).length, 1)
        assert.equal((await t.tk.tokens.list('x', { all: true })).length, 2)
        assert.equal((await t.tk.tokens.get('tmp', 'x')).active, false)
        await rejects(t.tk.tokens.create({ label: 'past', grants: ['read:*'], expiresAt: new Date(t.clock.ms - 1000) }, 'x'), 400)
        await rejects(t.tk.tokens.create({ label: 'bad', grants: ['read:*'], expiresAt: 'tomorrow' }, 'x'), 400)
        await rejects(t.tk.tokens.create({ label: 'both', grants: ['read:*'], expiresAt: new Date(t.clock.ms + 1000), ttlSeconds: 5 }, 'x'), 400, /not both/)
        await rejects(t.tk.tokens.create({ label: 'zero', grants: ['read:*'], ttlSeconds: 0 }, 'x'), 400)
      } finally {
        await t.close()
      }
    })

    test('grant and ungrant keep canonical form', async () => {
      const t = await fresh(backend)
      try {
        const { secret } = await t.tk.tokens.create({ label: 'g', grants: ['read:a'] }, 'x')
        let info = await t.tk.tokens.grant('g', ['write:b', 'read:a'], 'x')
        assert.deepEqual(info.grants, ['read:a', 'write:b'])
        assert.deepEqual((await t.tk.authenticate(secret)).grants, ['read:a', 'write:b'], 'applies on the next request')
        info = await t.tk.tokens.ungrant(info.id, ['read:a'], 'x')
        assert.deepEqual(info.grants, ['write:b'])
        await rejects(t.tk.tokens.ungrant('g', ['read:zzz'], 'x'), 400, /has no permission/)
        await rejects(t.tk.tokens.ungrant('g', ['write:b'], 'x'), 400, /revoke it instead/)
        await rejects(t.tk.tokens.grant('nope', ['read:a'], 'x'), 404)
      } finally {
        await t.close()
      }
    })

    test('revoke applies on the next request, is recorded and idempotent', async () => {
      const t = await fresh(backend)
      try {
        const { secret } = await principalWith(t.tk, 'host', ['read:*'])
        const info = await t.tk.tokens.revoke('host', 'alice')
        assert.equal(info.revokedBy, 'alice')
        assert.ok(info.revokedAt)
        assert.equal(info.active, false)
        assert.equal(await t.tk.authenticate(secret), null)
        const again = await t.tk.tokens.revoke('host', 'someone-else')
        assert.equal(again.revokedBy, 'alice', 'the first revoke stays on record')
        await rejects(t.tk.tokens.revoke('missing', 'x'), 404)
      } finally {
        await t.close()
      }
    })

    test('rotate replaces the secret and keeps everything else', async () => {
      const t = await fresh(backend)
      try {
        const { token, secret } = await t.tk.tokens.create({ label: 'r', grants: ['read:*'] }, 'x')
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

    test('export and import: a backup brings independent tokens back with their secrets', async () => {
      const t = await fresh(backend)
      try {
        const keep = await principalWith(t.tk, 'keep', ['read:*', 'turnkey:issue'])
        await t.tk.tokens.create({ label: 'dead', grants: ['read:*'] }, 'x').then(() => t.tk.tokens.revoke('dead', 'x'))
        await t.tk.sessions.create({ grants: ['read:*'] }, 'login')
        await childOf(t.tk, keep.principal, { name: 'job' })
        const saved = await t.tk.tokens.export()
        assert.deepEqual(saved.map((x) => x.label), ['keep'], 'no revoked tokens, sessions or children')
        assert.equal(saved[0].secretHash, sha(keep.secret))

        const t2 = await fresh(backend)
        try {
          const info = await t2.tk.tokens.import(saved[0], 'restore')
          assert.equal(info.createdBy, 'test', 'the original record is kept')
          assert.equal((await t2.tk.authenticate(keep.secret)).label, 'keep')
        } finally {
          await t2.close()
        }

        const old = 'tt_existing-secret-from-another-system'
        const legacy = await t.tk.tokens.import({ label: 'legacy', secretHash: sha(old), grants: ['read:*'], createdAt: '2025-05-05T00:00:00Z' }, 'migration')
        assert.equal(legacy.createdAt, '2025-05-05T00:00:00.000Z')
        assert.equal(legacy.createdBy, 'migration')
        assert.equal((await t.tk.authenticate(old)).label, 'legacy')
        await rejects(t.tk.tokens.import({ label: 'x', secretHash: 'nothex', grants: ['read:*'] }, 'm'), 400)
        await rejects(t.tk.tokens.import({ label: 'y', secretHash: sha(old), grants: ['read:*'] }, 'm'), 409)
      } finally {
        await t.close()
      }
    })

    test('last_used_at is recorded, at most every few minutes', async () => {
      const t = await fresh(backend)
      try {
        const { token, secret } = await t.tk.tokens.create({ label: 'u', grants: ['read:*'] }, 'x')
        assert.equal(token.lastUsedAt, null)
        await t.tk.authenticate(secret)
        const first = (await t.tk.tokens.get('u', 'x')).lastUsedAt
        assert.equal(first, t.clock.now().toISOString())
        t.clock.advance(60)
        await t.tk.authenticate(secret)
        assert.equal((await t.tk.tokens.get('u', 'x')).lastUsedAt, first, 'not rewritten within five minutes')
        t.clock.advance(300)
        await t.tk.authenticate(secret)
        assert.equal((await t.tk.tokens.get('u', 'x')).lastUsedAt, t.clock.now().toISOString())
      } finally {
        await t.close()
      }
    })

    test('concurrent requests on a stale token all succeed', async () => {
      // Each clock reading is a second later, so racing writers carry different values: the case an
      // optimistic-concurrency backend (Dolt) rejects for all but one of them.
      let base = Date.parse('2030-01-01T00:00:00.000Z')
      let tick = 0
      const t = await fresh(backend, { now: () => new Date(base + tick++ * 1000) })
      try {
        const { secret } = await t.tk.tokens.create({ label: 'busy', grants: ['read:*'] }, 'x')
        assert.ok(await t.tk.authenticate(secret))
        base += 10 * 60_000
        const all = await Promise.all(Array.from({ length: 8 }, () => t.tk.authenticate(secret)))
        assert.equal(all.filter((p) => p?.label === 'busy').length, 8, 'every request got the principal')
        assert.ok(Date.parse((await t.tk.tokens.get('busy', 'x')).lastUsedAt) >= base, 'one of them recorded the use')
      } finally {
        await t.close()
      }
    })

    test('purge deletes rows dead longer than the retention period', async () => {
      const t = await fresh(backend, { retentionDays: 1 })
      try {
        await t.tk.tokens.create({ label: 'keep', grants: ['read:*'] }, 'x')
        await t.tk.tokens.create({ label: 'gone', grants: ['read:*'] }, 'x')
        await t.tk.tokens.create({ label: 'lapses', grants: ['read:*'], expiresAt: new Date(t.clock.ms + 1000) }, 'x')
        await t.tk.tokens.revoke('gone', 'x')
        t.clock.advance(3600)
        assert.equal(await t.tk.purge(), 0, 'still within retention')
        t.clock.advance(86_400)
        assert.equal(await t.tk.purge(), 2)
        assert.deepEqual((await t.tk.tokens.list('x', { all: true })).map((x) => x.label), ['keep'])
      } finally {
        await t.close()
      }
    })

    // ------------------------------------------------------------------ the rules for principals

    test('creating and granting: turnkey:manage, and only what you hold', async () => {
      const t = await fresh(backend)
      try {
        const { principal: admin } = await principalWith(t.tk, 'admin', ['turnkey:manage', 'write:*'])
        const { principal: plain } = await principalWith(t.tk, 'plain', ['write:*'])
        const { principal: issuer } = await principalWith(t.tk, 'issuer', ['turnkey:issue', 'write:*'])
        await rejects(t.tk.tokens.create({ label: 'x', grants: ['read:a'] }, plain), 403, /turnkey manage/)
        await rejects(t.tk.tokens.create({ label: 'x', grants: ['read:a'] }, issuer), 403, /turnkey manage/)

        const made = await t.tk.tokens.create({ label: 'host', grants: ['write:things', 'turnkey:manage'] }, admin)
        assert.equal(made.token.createdBy, 'admin')
        assert.equal(made.token.parent, null, 'made with manage: independent')
        await t.tk.tokens.create({ label: 'lp', grants: ['turnkey:issue', 'read:*'] }, admin)
        await rejects(t.tk.tokens.create({ label: 'root', grants: ['*:*'] }, admin), 403, /may not give \*:\*/)
        await rejects(t.tk.tokens.create({ label: 'adm', grants: ['admin:x'] }, admin), 403, /may not give admin:x/)

        await t.tk.tokens.grant('host', ['write:other'], admin)
        await rejects(t.tk.tokens.grant('host', ['admin:x'], admin), 403, /may not give/)
        await rejects(t.tk.tokens.grant('host', ['read:x'], plain), 404, 'it cannot see the token')
        await rejects(t.tk.tokens.ungrant('plain', ['write:*'], plain), 403, /turnkey manage/)
        await rejects(t.tk.tokens.rotate('plain', plain), 403)
        assert.equal((await t.tk.tokens.rotate('host', { ...admin, actor: 'session:s1@admin' })).token.rotatedBy, 'session:s1@admin')

        // Rotating hands over the secret, and extending keeps access alive: only for what you hold.
        await t.tk.tokens.create({ label: 'root', grants: ['*:*'], ttlSeconds: 60 }, 'service')
        await rejects(t.tk.tokens.rotate('root', admin), 403, /may not rotate "root": it holds \*:\*/)
        await rejects(t.tk.tokens.extend('root', { ttlSeconds: 3600 }, admin), 403, /may not extend "root"/)
        assert.equal((await t.tk.tokens.revoke('root', admin)).active, false, 'but it may revoke it')
        assert.equal((await t.tk.tokens.extend('host', { ttlSeconds: 60 }, admin)).expiresAt, new Date(t.clock.ms + 60_000).toISOString())
      } finally {
        await t.close()
      }
    })

    test('what a principal sees: manage sees all; otherwise itself and its children', async () => {
      const t = await fresh(backend)
      try {
        const { principal: admin } = await principalWith(t.tk, 'admin', ['turnkey:manage', 'read:*'])
        const { principal: lp } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'read:*'])
        const { principal: other } = await principalWith(t.tk, 'other', ['turnkey:issue', 'read:*'])
        const { principal: plain } = await principalWith(t.tk, 'plain', ['read:*'])
        const mine = await childOf(t.tk, lp, { name: 's1' })
        await childOf(t.tk, other, { name: 's1' })

        assert.equal((await t.tk.tokens.list(admin)).length, 6)
        assert.deepEqual((await t.tk.tokens.list(lp)).map((x) => x.label).sort(), ['lp', 'lp.s1'])
        assert.deepEqual((await t.tk.tokens.list(plain)).map((x) => x.label), ['plain'])
        assert.deepEqual((await t.tk.tokens.list(mine.principal)).map((x) => x.label), ['lp.s1'])
        assert.deepEqual((await t.tk.tokens.list(admin, { parent: 'lp' })).map((x) => x.label), ['lp.s1'])
        assert.deepEqual((await t.tk.tokens.list(lp, { parent: 'lp' })).map((x) => x.label), ['lp.s1'])
        await rejects(t.tk.tokens.list(lp, { parent: 'other' }), 404)
        assert.equal((await t.tk.tokens.get('lp.s1', lp)).parent, lp.id)
        await rejects(t.tk.tokens.get('other.s1', lp), 404, /no token/)
        await rejects(t.tk.tokens.get('admin', plain), 404)
        assert.equal((await t.tk.tokens.get('plain', plain)).label, 'plain')
      } finally {
        await t.close()
      }
    })

    test('revoking: manage, the parent, or the token itself', async () => {
      const t = await fresh(backend)
      try {
        const { principal: admin } = await principalWith(t.tk, 'admin', ['turnkey:manage', 'read:*'])
        const { principal: lp } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'read:*'])
        const self = await principalWith(t.tk, 'self', ['read:*'])
        const c1 = await childOf(t.tk, lp, { name: 'a' })
        const c2 = await childOf(t.tk, lp, { name: 'b' })
        await rejects(t.tk.tokens.revoke('lp', c1.principal), 404, 'a child cannot see its parent')
        await rejects(t.tk.tokens.revoke('admin', self.principal), 404)
        assert.equal((await t.tk.tokens.revoke('self', self.principal)).revokedBy, 'self', 'logging itself out')
        assert.equal(await t.tk.authenticate(self.secret), null)
        assert.equal((await t.tk.tokens.revoke(c1.token.id, lp)).revokedBy, 'lp')
        assert.equal((await t.tk.tokens.revoke('lp.b', c2.principal)).active, false, 'a child may revoke itself')
        const c3 = await childOf(t.tk, lp, { name: 'c' })
        assert.equal((await t.tk.tokens.revoke('lp.c', admin)).revokedBy, 'admin')
        assert.equal(await t.tk.authenticate(c3.secret), null)
      } finally {
        await t.close()
      }
    })

    // ------------------------------------------------------------------ children

    test('a child: turnkey:issue, within what the parent holds, never turnkey:, labelled after its parent', async () => {
      const t = await fresh(backend)
      try {
        const { principal: lp } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'write:sessions', 'read:*'])
        const { principal: plain } = await principalWith(t.tk, 'plain', ['write:*'])
        const child = (input, actor = lp) => t.tk.tokens.create({ name: 's', ...input, child: true }, actor)
        await rejects(child({ grants: ['read:x'] }, plain), 403, /turnkey issue/)
        await rejects(child({ grants: ['read:x'] }, 'service'), 400, /created by its parent/)
        await rejects(child({ grants: ['write:projects'] }), 403, /write:projects/)
        await rejects(child({ grants: ['turnkey:issue'] }), 403, /child token may not hold/)
        await rejects(child({ grants: [] }), 400)
        await rejects(child({ grants: ['bad'] }), 400)
        await rejects(child({ label: 'x', grants: ['read:x'] }), 400, /give name, not label/)

        const c = await child({ name: 'Sess-ABC', grants: ['write:sessions/abc', 'read:*'], ttlSeconds: 1800, subject: { session: 'Sess-ABC', agent: 'dev', host: 'h1' } })
        assert.equal(c.token.label, 'lp.sess-abc')
        assert.equal(c.token.parent, lp.id)
        assert.equal(c.token.createdBy, 'lp')
        assert.equal(c.token.expiresAt, new Date(t.clock.ms + 1800_000).toISOString())
        assert.match(c.token.id, /^tok_[0-9a-f]{24}$/)
        const p = await t.tk.authenticate(c.secret)
        assert.equal(p.parent, lp.id)
        assert.deepEqual(p.subject, { session: 'Sess-ABC', agent: 'dev', host: 'h1' })
        assert.ok(t.tk.can(p, 'write', 'sessions/abc'))
        assert.ok(!t.tk.can(p, 'write', 'sessions/abd'))

        const capped = await child({ name: 'Sess-ABC', grants: ['read:*'], ttlSeconds: 99_999 })
        assert.equal(capped.token.expiresAt, new Date(t.clock.ms + 3600_000).toISOString(), 'capped at children.maxTtlSeconds')
        assert.notEqual(capped.token.label, c.token.label, 'a second child with one name gets its own label')
        assert.ok(capped.token.label.startsWith('lp.sess-abc.'))
        const byDate = await child({ name: 'later', grants: ['read:*'], expiresAt: new Date(t.clock.ms + 7200_000) })
        assert.equal(byDate.token.expiresAt, new Date(t.clock.ms + 3600_000).toISOString(), 'an expiresAt is capped too')
        const unnamed = await t.tk.tokens.create({ grants: ['read:*'], child: true }, lp)
        assert.match(unnamed.token.label, /^lp\.[0-9a-f]{8}$/)

        const plan = await t.tk.tokens.check({ name: 'dry', grants: ['read:x'], child: true }, lp)
        assert.deepEqual(plan, { label: 'lp.dry', grants: ['read:x'], parent: lp.id, expiresAt: new Date(t.clock.ms + 3600_000).toISOString() })
        await rejects(t.tk.tokens.check({ grants: ['write:projects'], child: true }, lp), 403)
        assert.equal((await t.tk.tokens.list(lp, { all: true })).length, 5, 'a dry run makes nothing')
      } finally {
        await t.close()
      }
    })

    test('a child never passes a turnkey check, whatever it holds', async () => {
      const t = await fresh(backend)
      try {
        const { principal: root } = await principalWith(t.tk, 'root', ['*:*'])
        assert.ok(t.tk.can(root, 'turnkey', 'manage'))
        const c = await childOf(t.tk, root, { grants: ['*:*'] })
        const p = c.principal
        assert.ok(t.tk.can(p, 'write', 'anything'))
        assert.ok(!t.tk.can(p, 'turnkey', 'manage'))
        assert.ok(!t.tk.can(p, 'turnkey', 'issue'))
        assert.throws(() => t.tk.require(p, 'turnkey', 'manage'), /a child token never may/)
        await rejects(t.tk.tokens.create({ grants: ['read:x'], child: true }, p), 403, 'no grandchildren')
        await rejects(t.tk.tokens.create({ label: 'x', grants: ['read:x'] }, p), 403)
        await rejects(t.tk.tokens.extend(c.token.id, { ttlSeconds: 60 }, p), 403, /only its parent/)
        await rejects(t.tk.tokens.rotate(c.token.id, root), 400, /child token/)
        await rejects(t.tk.tokens.grant(c.token.id, ['read:x'], root), 400, /fixed/)
        await rejects(t.tk.tokens.ungrant(c.token.id, ['*:*'], 'service'), 400, /fixed/)
      } finally {
        await t.close()
      }
    })

    test('extend moves only the expiry, within the cap; 404 once revoked or expired', async () => {
      const t = await fresh(backend)
      try {
        const { principal: lp } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'read:*'])
        const { principal: other } = await principalWith(t.tk, 'other', ['turnkey:issue', 'read:*'])
        const { principal: admin } = await principalWith(t.tk, 'admin', ['turnkey:manage', 'read:*'])
        const c = await childOf(t.tk, lp, { name: 's', grants: ['read:x'], ttlSeconds: 1800 })
        t.clock.advance(600)
        const r = await t.tk.tokens.extend(c.token.id, { ttlSeconds: 1800 }, lp)
        assert.equal(r.expiresAt, new Date(t.clock.ms + 1800_000).toISOString())
        assert.equal((await t.tk.authenticate(c.secret)).expiresAt, r.expiresAt, 'the secret is unchanged')
        assert.equal((await t.tk.tokens.extend(c.token.id, {}, lp)).expiresAt, new Date(t.clock.ms + 3600_000).toISOString(), 'default: the cap')
        assert.equal((await t.tk.tokens.extend(c.token.id, { ttlSeconds: 99_999 }, admin)).expiresAt, new Date(t.clock.ms + 3600_000).toISOString(), 'capped, even for manage')
        await rejects(t.tk.tokens.extend(c.token.id, { ttlSeconds: 1800 }, other), 404, /no token/)
        await rejects(t.tk.tokens.extend('tok_nope', { ttlSeconds: 1800 }, lp), 404)
        await rejects(t.tk.tokens.extend(c.token.id, { ttlSeconds: 0 }, lp), 400)
        await rejects(t.tk.tokens.extend('lp', { ttlSeconds: 60 }, lp), 403, 'a token cannot extend itself')
        t.clock.advance(3601)
        await assert.rejects(() => t.tk.tokens.extend(c.token.id, { ttlSeconds: 1800 }, lp), (e) => e.status === 404 && e.code === 'not_found')
        assert.equal(await t.tk.authenticate(c.secret), null)

        const d = await childOf(t.tk, lp, { name: 's2' })
        await t.tk.tokens.revoke(d.token.id, lp)
        await rejects(t.tk.tokens.extend(d.token.id, {}, lp), 404)

        const tmp = await t.tk.tokens.create({ label: 'tmp', grants: ['read:*'], ttlSeconds: 60 }, 'x')
        assert.equal((await t.tk.tokens.extend('tmp', { ttlSeconds: 86_400 * 365 }, admin)).expiresAt, new Date(t.clock.ms + 86_400_000 * 365).toISOString(), 'no cap for an independent token')
        await rejects(t.tk.tokens.extend('tmp', {}, admin), 400, /give ttlSeconds or expiresAt/)
        assert.ok(await t.tk.authenticate(tmp.secret))
      } finally {
        await t.close()
      }
    })

    test('a child works only while its parent does, and only with what its parent still holds', async () => {
      const t = await fresh(backend)
      try {
        const parent = await principalWith(t.tk, 'lp', ['turnkey:issue', 'write:a', 'read:b'])
        const c = await childOf(t.tk, parent.principal, { name: 's', grants: ['write:a', 'read:b'] })
        assert.deepEqual(c.principal.grants, ['read:b', 'write:a'])

        await t.tk.tokens.ungrant('lp', ['write:a'], 'x')
        assert.deepEqual((await t.tk.authenticate(c.secret)).grants, ['read:b'], 'narrowed on the next request')
        await t.tk.tokens.grant('lp', ['write:a'], 'x')
        assert.deepEqual((await t.tk.authenticate(c.secret)).grants, ['read:b', 'write:a'])
        await t.tk.tokens.ungrant('lp', ['turnkey:issue'], 'x')
        assert.equal(await t.tk.authenticate(c.secret), null, 'a parent that may no longer issue')
        await t.tk.tokens.grant('lp', ['turnkey:manage'], 'x')
        assert.ok(await t.tk.authenticate(c.secret), 'manage includes issue')

        await t.tk.tokens.revoke('lp', 'x')
        assert.equal(await t.tk.authenticate(c.secret), null, 'gone with its parent, at once')
        const info = await t.tk.tokens.get(c.token.id, 'x')
        assert.equal(info.active, false)
        assert.equal(info.revokedAt, null, 'nothing was written to the child')

        const p2 = await principalWith(t.tk, 'short', ['turnkey:issue', 'read:*'])
        await t.tk.tokens.extend('short', { ttlSeconds: 60 }, 'x')
        const c2 = await childOf(t.tk, (await t.tk.authenticate(p2.secret)), { name: 's' })
        t.clock.advance(61)
        assert.equal(await t.tk.authenticate(c2.secret), null, 'gone when its parent expires')

        const p3 = await principalWith(t.tk, 'gone', ['turnkey:issue', 'read:*'])
        const c3 = await childOf(t.tk, p3.principal, { name: 's' })
        await t.env.raw.run(`DELETE FROM ${t.env.prefix}tokens WHERE id = ?`, [p3.token.id])
        assert.equal(await t.tk.authenticate(c3.secret), null, 'and when its parent was purged')
      } finally {
        await t.close()
      }
    })

    test('child labels: never another parent\'s dead label, always <parent>.<name>, and a long parent label is refused', async () => {
      const t = await fresh(backend)
      try {
        const { principal: orch } = await principalWith(t.tk, 'orch', ['turnkey:issue', 'read:*'])
        await t.tk.tokens.create({ label: 'orch.admin', grants: ['read:*'] }, 'x')
        const dead = await t.tk.tokens.revoke('orch.admin', 'x')
        const c = await childOf(t.tk, orch, { name: 'admin' })
        assert.notEqual(c.token.label, 'orch.admin', 'the revoked token keeps its label and record')
        assert.match(c.token.label, /^orch\.admin\.[0-9a-z]+$/)
        assert.equal((await t.tk.tokens.get(dead.id, 'x')).revokedBy, 'x')
        // The parent's own dead child label is reused.
        const c1 = await childOf(t.tk, orch, { name: 'job' })
        await t.tk.tokens.revoke(c1.token.id, orch)
        assert.equal((await childOf(t.tk, orch, { name: 'job' })).token.label, 'orch.job')

        const long = 'p'.repeat(100)
        const { principal: lp } = await principalWith(t.tk, long, ['turnkey:issue', 'read:*'])
        const named = await childOf(t.tk, lp, { name: 'x'.repeat(50) })
        assert.equal(named.token.label, `${long}.${'x'.repeat(19)}`)
        const { principal: tooLong } = await principalWith(t.tk, 'q'.repeat(125), ['turnkey:issue', 'read:*'])
        await rejects(childOf(t.tk, tooLong, { name: 'a' }), 400, /too long a label/)
      } finally {
        await t.close()
      }
    })

    test('a child is active exactly when it authenticates; coversAll applies the child rule; bad ttls are a 400', async () => {
      const t = await fresh(backend)
      try {
        const root = await principalWith(t.tk, 'root', ['*:*'])
        const big = await childOf(t.tk, root.principal, { name: 's', grants: ['*:*'] })
        assert.ok(!t.tk.coversAll(big.principal, ['turnkey:manage']))
        assert.ok(t.tk.coversAll(big.principal, ['write:x']))
        await principalWith(t.tk, 'lp', ['turnkey:issue', 'write:*'])
        const p = await t.tk.authenticate((await t.tk.tokens.rotate('lp', 'x')).secret)
        const c = await childOf(t.tk, p, { name: 's', grants: ['write:x'] })
        await t.tk.tokens.ungrant('lp', ['turnkey:issue'], 'x')
        assert.equal(await t.tk.authenticate(c.secret), null)
        assert.equal((await t.tk.tokens.get(c.token.id, 'x')).active, false)
        assert.equal((await t.tk.tokens.list('x')).some((x) => x.id === c.token.id), false)

        const { principal: lp2 } = await principalWith(t.tk, 'lp2', ['turnkey:issue', 'read:*'])
        for (const ttlSeconds of [1e17, 1.5, -1, '60', [5], true]) {
          await rejects(t.tk.tokens.create({ name: 'n', grants: ['read:*'], ttlSeconds, child: true }, lp2), 400, JSON.stringify(ttlSeconds))
        }
        await rejects(t.tk.tokens.create({ label: 'big', grants: ['read:*'], ttlSeconds: 1e17 }, 'x'), 400)
      } finally {
        await t.close()
      }
    })

    test('a dry run sees a label conflict; session labels are reserved; a child\'s grants are a 400 to its parent too', async () => {
      const t = await fresh(backend)
      try {
        const { principal: admin } = await principalWith(t.tk, 'admin', ['turnkey:manage', 'read:*'])
        await rejects(t.tk.tokens.check({ label: 'admin', grants: ['read:*'] }, admin), 409)
        await rejects(t.tk.tokens.create({ label: 'session.abc', grants: ['read:*'] }, 'x'), 400, /browser sessions/)
        const { principal: lp } = await principalWith(t.tk, 'lp', ['turnkey:issue', 'read:*'])
        const c = await childOf(t.tk, lp, { name: 's' })
        await rejects(t.tk.tokens.grant(c.token.id, ['read:x'], lp), 400, /fixed/)
        await rejects(t.tk.tokens.rotate(c.token.id, lp), 400, /fixed/)
      } finally {
        await t.close()
      }
    })

    // ------------------------------------------------------------------ sessions

    test('browser sessions expire, slide forward while used, and log out', async () => {
      const t = await fresh(backend, { sessions: { ttlSeconds: 86_400 } })
      try {
        const { token, secret } = await t.tk.sessions.create({ grants: ['admin:*', 'turnkey:manage'], subject: { userAgent: 'test' } }, 'password-login')
        assert.match(token.label, /^session\.[0-9a-f]{12}$/)
        assert.equal(token.slideSeconds, 86_400)
        assert.equal(token.createdBy, 'password-login')
        let p = await t.tk.authenticate(secret)
        assert.equal(p.renewed, false)
        assert.equal(p.slideSeconds, 86_400)
        assert.ok(t.tk.can(p, 'turnkey', 'manage'), 'a session may manage tokens')
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

        const fixed = await t.tk.sessions.create({ grants: ['read:*'], ttlSeconds: 100, slide: false }, 'x')
        t.clock.advance(50)
        assert.equal((await t.tk.authenticate(fixed.secret)).renewed, false)
        t.clock.advance(51)
        assert.equal(await t.tk.authenticate(fixed.secret), null)

        const a = await t.tk.sessions.create({ grants: ['read:*'] }, 'x')
        const b = await t.tk.sessions.create({ grants: ['read:*'] }, 'x')
        const tok = await t.tk.tokens.create({ label: 'cli', grants: ['read:*'] }, 'x')
        const pa = await t.tk.authenticate(a.secret)
        await t.tk.tokens.revoke(pa.id, pa)
        assert.equal(await t.tk.authenticate(a.secret), null, 'logout: the session revokes itself')
        assert.ok(await t.tk.authenticate(b.secret))
        assert.deepEqual((await t.tk.sessions.list()).map((s) => s.id), [b.token.id])
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
        const rows = await t.env.raw.query(`SELECT version, name, checksum FROM ${t.env.prefix}migrations ORDER BY version`)
        assert.deepEqual(rows.map((r) => Number(r.version)), [1, 2])
        assert.match(String(rows[0].checksum), /^[0-9a-f]{64}$/)
        const { secret } = await t.tk.tokens.create({ label: 'kept', grants: ['read:*'] }, 'x')
        const again = await createTurnkey({ db: t.env.driver, tablePrefix: t.env.prefix, tokenPrefix: 'tt_', permissions: PERMISSIONS, purgeIntervalMs: false, now: t.clock.now })
        assert.ok(await again.authenticate(secret))
        assert.equal((await t.env.raw.query(`SELECT version FROM ${t.env.prefix}migrations`)).length, 2)
        await again.close()
      } finally {
        await t.close()
      }
    })

    test('migrations: a 0.1 database (kinds, issued_by) upgrades with its tokens working', async () => {
      const env = await backend.open()
      try {
        const schema = await import('../dist/schema.js')
        const d = env.driver.dialect
        const P = env.prefix
        await env.raw.run(schema.withPrefix(schema.MIGRATIONS_TABLE(d), P))
        const v1 = schema.MIGRATIONS[0]
        for (const st of v1.statements[d]) await env.raw.run(schema.withPrefix(st, P))
        await env.raw.run(`INSERT INTO ${P}migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`, [1, v1.name, schema.checksum(v1, d), '2026-01-01T00:00:00.000Z'])
        const c = clock()
        const later = new Date(c.ms + 1800_000).toISOString()
        const row = (id, label, kind, secret, grants, issuedBy, expires, slide) =>
          env.raw.run(
            `INSERT INTO ${P}tokens (id, label, kind, secret_hash, grants, issued_by, expires_at, slide_seconds, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [id, label, kind, sha(secret), grants, issuedBy, expires, slide, '2026-01-01T00:00:00.000Z', 'old'],
          )
        await row('tok_1', 'lp', 'token', 'tt_issuer', 'read:* turnkey:issue', null, null, null)
        await row('tok_2', 'lp.s1', 'credential', 'tt_cred', 'read:x', 'tok_1', later, null)
        await row('tok_3', 'session.abc', 'session', 'tt_sess', 'read:*', null, later, 86400)

        const tk = await createTurnkey({ db: env.driver, tablePrefix: P, tokenPrefix: 'tt_', permissions: PERMISSIONS, purgeIntervalMs: false, now: c.now })
        try {
          const versions = (await env.raw.query(`SELECT version FROM ${P}migrations ORDER BY version`)).map((r) => Number(r.version))
          assert.deepEqual(versions, [1, 2])
          const cred = await tk.authenticate('tt_cred')
          assert.equal(cred.parent, 'tok_1', 'a credential is now a child of its issuer')
          assert.deepEqual(cred.grants, ['read:x'])
          assert.equal((await tk.authenticate('tt_sess')).slideSeconds, 86400)
          const issuer = await tk.authenticate('tt_issuer')
          assert.deepEqual((await tk.tokens.list(issuer)).map((x) => x.label).sort(), ['lp', 'lp.s1'])
          await tk.tokens.revoke('lp', 'x')
          assert.equal(await tk.authenticate('tt_cred'), null)
        } finally {
          await tk.close()
        }
      } finally {
        await env.close()
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
        assert.equal((await env.raw.query(`SELECT version FROM ${env.prefix}migrations`)).length, 2)
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
        await assert.rejects(() => createTurnkey({ ...base, children: { maxTtlSeconds: 0 } }), /maxTtlSeconds/)
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
          const c = await childOf(t.tk, issuer, { name: 's', grants: ['read:x'] })
          for (let i = 0; i < 5; i++) await t.tk.tokens.extend(c.token.id, { ttlSeconds: 600 }, issuer)
          assert.equal(await commits(), before, 'no commits from creating or extending')
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
          await t.tk.tokens.create({ label: 'old', grants: ['read:*'] }, 'x')
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
          assert.equal((await tk2.tokens.list('x', { all: true })).length, 0)
          await tk2.close()
        } finally {
          await t.close()
        }
      })
    }
  })
}

// The bookkeeping write's failure path, forced: a driver whose UPDATE of the usage columns fails.
describe('a failed usage write never fails authenticate', () => {
  const sqlite = backends.find((b) => b.name === 'sqlite')
  const failing = (fail) => ({
    ...sqlite,
    async open() {
      const env = await sqlite.open()
      const driver = {
        ...env.driver,
        async run(sql, params) {
          if (fail.on && /^UPDATE .* SET .*last_used_at = \?/.test(sql)) throw new Error('serialization failure: this transaction conflicts with a committed transaction from another client')
          return env.driver.run(sql, params)
        },
      }
      return { ...env, driver }
    },
  })

  test('the principal is returned, the failure is logged, and the next request writes', async () => {
    const fail = { on: false }
    const logged = []
    const t = await fresh(failing(fail), { log: (m) => logged.push(m) })
    try {
      const { secret } = await t.tk.tokens.create({ label: 'u', grants: ['read:*'] }, 'x')
      fail.on = true
      const p = await t.tk.authenticate(secret)
      assert.equal(p.label, 'u')
      assert.equal((await t.tk.tokens.get('u', 'x')).lastUsedAt, null, 'nothing recorded')
      assert.equal(logged.filter((m) => /could not record the use of token "u"/.test(m)).length, 1)
      fail.on = false
      assert.ok(await t.tk.authenticate(secret))
      assert.equal((await t.tk.tokens.get('u', 'x')).lastUsedAt, t.clock.now().toISOString(), 'recorded on the next request')
    } finally {
      await t.close()
    }
  })

  test('a slide that was not written is not reported: renewed is false and expiresAt unchanged', async () => {
    const fail = { on: false }
    const t = await fresh(failing(fail), { sessions: { ttlSeconds: 86_400 }, log: () => {} })
    try {
      const { token, secret } = await t.tk.sessions.create({ grants: ['read:*'] }, 'login')
      t.clock.advance(3 * 3600)
      fail.on = true
      let p = await t.tk.authenticate(secret)
      assert.equal(p.renewed, false)
      assert.equal(p.expiresAt, token.expiresAt)
      fail.on = false
      p = await t.tk.authenticate(secret)
      assert.equal(p.renewed, true)
      assert.equal(p.expiresAt, new Date(t.clock.ms + 86_400_000).toISOString())
    } finally {
      await t.close()
    }
  })
})
