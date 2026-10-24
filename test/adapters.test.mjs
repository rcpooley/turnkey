// The web adapters, the Quiver commands and the admin CLI. Each adapter serves the token API
// (docs/api.md) exactly as a client calls it; these run on SQLite (adapters don't touch SQL).
import { describe, test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import express from 'express'
import { runAdminCli } from '../dist/index.js'
import * as ex from '../dist/adapters/express.js'
import * as nd from '../dist/adapters/node.js'
import * as ft from '../dist/adapters/fetch.js'
import { tokenCommands } from '../dist/quiver.js'
import { backends, fresh } from './helpers.mjs'

const sqlite = backends.find((b) => b.name === 'sqlite')

/** Serve a node request handler on a random port. */
async function serve(handler) {
  const server = createServer(handler)
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const base = `http://127.0.0.1:${server.address().port}`
  return { base, close: () => new Promise((r) => server.close(r)) }
}

const call = async (base, method, path, { token, body, headers = {} } = {}) => {
  const res = await fetch(base + path, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  })
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null, headers: res.headers }
}

const ADAPTERS = {
  express: (tk) => {
    const app = express()
    app.use(express.json())
    app.use('/turnkey', ex.turnkeyRouter(tk))
    app.get('/elsewhere', (_req, res) => res.json({ ok: true }))
    // A real app's own JSON 404 and error handler (express.json() rejects bad JSON before Turnkey sees it).
    app.use((_req, res) => res.status(404).json({ error: 'app 404' }))
    app.use((err, _req, res, _next) => res.status(err.status ?? 500).json({ error: err.message }))
    return app
  },
  'express (no body parser)': (tk) => {
    const app = express()
    app.use('/turnkey', ex.turnkeyRouter(tk))
    app.use((_req, res) => res.status(404).json({ error: 'app 404' }))
    return app
  },
  node: (tk) => {
    const handle = nd.turnkeyHandler(tk)
    return async (req, res) => {
      if (await handle(req, res)) return
      nd.sendJson(res, 404, { error: 'app 404' })
    }
  },
  fetch: (tk) => {
    const handle = ft.turnkeyHandler(tk)
    // Bridge node → Request/Response, the way a fetch-style server would call it.
    return async (req, res) => {
      const chunks = []
      for await (const c of req) chunks.push(c)
      const request = new Request(`http://${req.headers.host}${req.url}`, {
        method: req.method,
        headers: req.headers,
        body: req.method === 'POST' ? Buffer.concat(chunks) : undefined,
      })
      const response = (await handle(request)) ?? ft.json(404, { error: 'app 404' })
      res.writeHead(response.status, Object.fromEntries(response.headers))
      res.end(await response.text())
    }
  },
}

for (const [name, make] of Object.entries(ADAPTERS)) {
  describe(`token API over ${name}`, () => {
    let t, srv, admin, issuer, plain
    before(async () => {
      t = await fresh(sqlite, { children: { maxTtlSeconds: 1800 } })
      srv = await serve(make(t.tk))
      admin = (await t.tk.tokens.create({ label: 'admin', grants: ['turnkey:manage', 'write:*'] }, 'x')).secret
      issuer = (await t.tk.tokens.create({ label: 'lp', grants: ['turnkey:issue', 'write:sessions', 'read:*'] }, 'x')).secret
      plain = (await t.tk.tokens.create({ label: 'plain', grants: ['write:*'] }, 'x')).secret
    })
    after(async () => {
      await srv.close()
      await t.close()
    })
    const api = (method, path, opts) => call(srv.base, method, '/turnkey' + path, opts)

    test('every call needs a token', async () => {
      assert.equal((await api('GET', '/self')).status, 401)
      const bad = await api('GET', '/tokens', { token: 'tt_nope' })
      assert.equal(bad.status, 401)
      assert.equal(bad.body.code, 'unauthorized')
    })

    test('self: who the caller is, what it holds, and the child cap', async () => {
      const r = await api('GET', '/self', { token: issuer })
      assert.equal(r.status, 200)
      assert.equal(r.body.label, 'lp')
      assert.deepEqual(r.body.grants, ['read:*', 'turnkey:issue', 'write:sessions'])
      assert.equal(r.body.maxChildTtlSeconds, 1800)
      assert.equal((await api('GET', '/self', { token: plain })).body.label, 'plain', 'any token may see itself')
    })

    test('a child: dry run, create, use, extend, revoke, and 404 after', async () => {
      const dry = await api('POST', '/tokens', { token: issuer, body: { child: true, name: 'sess-1', grants: ['write:sessions/sess-1'], dryRun: true } })
      assert.equal(dry.status, 200)
      assert.deepEqual(dry.body, { dryRun: true, label: 'lp.sess-1', grants: ['write:sessions/sess-1'], parent: dry.body.parent, expiresAt: new Date(t.clock.ms + 1800_000).toISOString() })
      for (const body of [{ child: true }, { child: true, grants: 'read:*' }, { child: true, grants: [] }, { child: true, grants: ['bogus:x'] }, { child: true, grants: [5] }, { child: true, grants: ['read:*'], extra: 1 }, { child: 'yes', grants: ['read:*'] }]) {
        assert.equal((await api('POST', '/tokens', { token: issuer, body: { ...body, dryRun: true } })).status, 400, JSON.stringify(body))
      }
      assert.equal((await api('POST', '/tokens', { token: issuer, body: { child: true, grants: ['write:projects'], dryRun: true } })).status, 403)
      assert.equal((await api('POST', '/tokens', { token: issuer, body: { child: true, grants: ['turnkey:issue'], dryRun: true } })).status, 403)
      assert.equal((await api('POST', '/tokens', { token: plain, body: { child: true, grants: ['read:x'], dryRun: true } })).status, 403)
      assert.equal((await api('POST', '/tokens', { token: issuer, body: '{not json' })).status, 400)

      const made = await api('POST', '/tokens', {
        token: issuer,
        body: { child: true, name: 'sess-1', grants: ['write:sessions/sess-1'], ttlSeconds: 99999, subject: { session: 'sess-1', agent: 'dev', host: 'h' } },
      })
      assert.equal(made.status, 201)
      assert.deepEqual(Object.keys(made.body).sort(), ['secret', 'token'])
      assert.equal(made.body.token.label, 'lp.sess-1')
      assert.ok(Date.parse(made.body.token.expiresAt) - t.clock.ms <= 1800_000, 'capped')
      const { id } = made.body.token
      const p = await t.tk.authenticate(made.body.secret)
      assert.ok(t.tk.can(p, 'write', 'sessions/sess-1'))
      assert.deepEqual((await api('GET', '/tokens', { token: issuer })).body.tokens.map((x) => x.label).sort(), ['lp', 'lp.sess-1'])
      assert.equal((await api('GET', `/tokens?parent=lp`, { token: admin })).body.tokens.length, 1)

      t.clock.advance(600)
      const extended = await api('POST', `/tokens/${id}/extend`, { token: issuer, body: { ttlSeconds: 1800 } })
      assert.equal(extended.status, 200)
      assert.equal(extended.body.expiresAt, new Date(t.clock.ms + 1800_000).toISOString())
      assert.equal((await api('POST', `/tokens/${id}/extend`, { token: plain, body: { ttlSeconds: 60 } })).status, 404, 'plain cannot see it')
      assert.equal((await api('POST', `/tokens/${id}/extend`, { token: issuer, body: { ttl: 60 } })).status, 400, 'unknown field')

      const revoked = await api('POST', `/tokens/${id}/revoke`, { token: issuer })
      assert.equal(revoked.status, 200)
      assert.equal(revoked.body.active, false)
      assert.equal((await api('POST', `/tokens/${id}/revoke`, { token: issuer })).status, 200, 'idempotent')
      const gone = await api('POST', `/tokens/${id}/extend`, { token: issuer, body: { ttlSeconds: 1800 } })
      assert.equal(gone.status, 404)
      assert.equal(gone.body.code, 'not_found')
      assert.equal(await t.tk.authenticate(made.body.secret), null)
      assert.equal((await api('GET', '/tokens?all=true', { token: issuer })).body.tokens.length, 2)
    })

    test('a child cannot create, and expires on its own', async () => {
      const r = await api('POST', '/tokens', { token: issuer, body: { child: true, name: 'x', grants: ['read:*'], ttlSeconds: 60 } })
      const res = await api('POST', '/tokens', { token: r.body.secret, body: { child: true, name: 'y', grants: ['read:*'] } })
      assert.equal(res.status, 403)
      t.clock.advance(61)
      assert.equal((await api('POST', `/tokens/${r.body.token.id}/extend`, { token: issuer, body: {} })).status, 404)
    })

    test('managing: create, show, grant, ungrant, rotate, revoke, with the rules', async () => {
      const made = await api('POST', '/tokens', { token: admin, body: { label: 'host-1', grants: ['read:things'] } })
      assert.equal(made.status, 201)
      assert.equal(made.body.token.createdBy, 'admin')
      assert.equal((await api('POST', '/tokens', { token: admin, body: { label: 'root', grants: ['*:*'] } })).status, 403, 'only what it holds')
      assert.equal((await api('POST', '/tokens', { token: issuer, body: { label: 'host-2', grants: ['read:*'] } })).status, 403)
      assert.equal((await api('GET', '/tokens/host-1', { token: admin })).body.label, 'host-1')
      assert.equal((await api('GET', '/tokens/host-1', { token: plain })).status, 404)
      assert.deepEqual((await api('POST', '/tokens/host-1/grant', { token: admin, body: { grants: ['write:b'] } })).body.grants, ['read:things', 'write:b'])
      assert.deepEqual((await api('POST', '/tokens/host-1/ungrant', { token: admin, body: { grants: ['read:things'] } })).body.grants, ['write:b'])
      const rotated = await api('POST', '/tokens/host-1/rotate', { token: admin })
      assert.notEqual(rotated.body.secret, made.body.secret)
      assert.equal((await api('POST', '/tokens/host-1/revoke', { token: rotated.body.secret })).body.revokedBy, 'host-1', 'a token may revoke itself')
    })

    test('other paths fall through to the app; a wrong method is a 405', async () => {
      assert.equal((await api('GET', '/nope', { token: issuer })).body?.error, 'app 404')
      assert.equal((await api('GET', '/tokens/x/y/z', { token: issuer })).body?.error, 'app 404')
      assert.equal((await api('DELETE', '/tokens', { token: issuer })).status, 405)
      assert.equal((await api('GET', '/tokens/lp/extend', { token: issuer })).status, 405)
      assert.equal((await call(srv.base, 'GET', '/turnkey//evil.example/self', { token: issuer })).body?.error, 'app 404', 'a // path is not a host')
      assert.equal((await api('POST', '/tokens', { token: issuer, body: { child: true, grants: ['read:*'], ttlSeconds: '60' } })).status, 400)
      assert.equal((await api('POST', '/tokens/lp/extend', { token: admin, body: { ttlSeconds: [5] } })).status, 400)
    })
  })
}

describe('browser sessions over the adapters', () => {
  const cookie = { name: 'app_session', secure: false }
  let t
  before(async () => {
    t = await fresh(sqlite, { sessions: { ttlSeconds: 86_400 } })
  })
  after(async () => t.close())

  const login = async () => {
    const { secret, token } = await t.tk.sessions.create({ grants: ['read:*'] }, 'login')
    return { secret, token, header: `app_session=${encodeURIComponent(secret)}` }
  }

  test('sessionCookie and clearSessionCookie', () => {
    const exp = new Date(Date.now() + 3600_000).toISOString()
    const c = ex.sessionCookie('tt_abc', exp, { name: 's' })
    assert.match(c, /^s=tt_abc; Path=\/; HttpOnly; SameSite=Lax; Max-Age=(3599|3600); Secure$/)
    assert.equal(ex.clearSessionCookie({ name: 's', secure: false }), 's=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
    assert.equal(ex.readCookie('a=1; s=tt%5Fx; b=2', 's'), 'tt_x')
  })

  test('express middleware: cookie or Bearer, 401 when required, renewed cookie re-sent, cross-origin writes refused', async () => {
    const app = express()
    app.use(ex.authenticate(t.tk, { cookie }))
    app.get('/me', (req, res) => res.json({ label: req.principal.label, via: req.authVia }))
    app.post('/things', ex.requirePermission(t.tk, 'read', 'things'), (req, res) => res.json({ ok: true }))
    app.post('/admin', ex.requirePermission(t.tk, 'write', 'things'), (req, res) => res.json({ ok: true }))
    const srv = await serve(app)
    try {
      assert.equal((await call(srv.base, 'GET', '/me')).status, 401)
      const s = await login()
      const me = await call(srv.base, 'GET', '/me', { headers: { cookie: s.header } })
      assert.deepEqual(me.body, { label: s.token.label, via: 'cookie' })
      assert.equal(me.headers.get('set-cookie'), null)
      const tok = await t.tk.tokens.create({ label: 'cli', grants: ['read:*'] }, 'x')
      assert.equal((await call(srv.base, 'GET', '/me', { token: tok.secret, headers: { cookie: s.header } })).body.via, 'bearer', 'the header wins')

      t.clock.advance(4 * 3600)
      const later = await call(srv.base, 'GET', '/me', { headers: { cookie: s.header } })
      assert.match(later.headers.get('set-cookie'), /^app_session=tt_.*; Max-Age=\d+$/)

      const host = new URL(srv.base).host
      assert.equal((await call(srv.base, 'POST', '/things', { headers: { cookie: s.header, origin: `http://${host}` } })).status, 200)
      assert.equal((await call(srv.base, 'POST', '/things', { headers: { cookie: s.header } })).status, 200, 'no Origin header: allowed')
      const csrf = await call(srv.base, 'POST', '/things', { headers: { cookie: s.header, origin: 'https://evil.example' } })
      assert.equal(csrf.status, 403)
      assert.equal((await call(srv.base, 'POST', '/things', { token: tok.secret, headers: { origin: 'https://evil.example' } })).status, 200, 'Bearer is not a cookie')
      assert.equal((await call(srv.base, 'POST', '/admin', { headers: { cookie: s.header } })).status, 403)

      await t.tk.tokens.revoke(s.token.id, 'logout')
      const out = await call(srv.base, 'GET', '/me', { headers: { cookie: s.header } })
      assert.equal(out.status, 401)
      assert.match(out.body.error, /log in again/)
    } finally {
      await srv.close()
    }
  })

  test('express middleware with required: false leaves req.principal null', async () => {
    const app = express()
    app.use(ex.authenticate(t.tk, { cookie, required: false }))
    app.get('/', (req, res) => res.json({ principal: req.principal }))
    const srv = await serve(app)
    try {
      assert.deepEqual((await call(srv.base, 'GET', '/')).body, { principal: null })
    } finally {
      await srv.close()
    }
  })

  test('node principal() sets the renewed cookie on res', async () => {
    const srv = await serve(async (req, res) => {
      try {
        const p = await nd.principal(t.tk, req, res, { cookie, trustedOrigins: ['https://ui.example'] })
        nd.sendJson(res, p ? 200 : 401, { label: p?.label ?? null })
      } catch (err) {
        nd.sendError(res, err)
      }
    })
    try {
      const s = await login()
      assert.equal((await call(srv.base, 'GET', '/', { headers: { cookie: s.header } })).body.label, s.token.label)
      t.clock.advance(4 * 3600)
      assert.match((await call(srv.base, 'GET', '/', { headers: { cookie: s.header } })).headers.get('set-cookie'), /^app_session=/)
      assert.equal((await call(srv.base, 'POST', '/', { headers: { cookie: s.header, origin: 'https://ui.example' } })).status, 200, 'a trusted origin')
      assert.equal((await call(srv.base, 'POST', '/', { headers: { cookie: s.header, origin: 'https://other.example' } })).status, 403)
    } finally {
      await srv.close()
    }
  })

  test('fetch authenticate returns the cookie to send back', async () => {
    const s = await login()
    t.clock.advance(4 * 3600)
    const r = await ft.authenticate(t.tk, new Request('http://app.example/', { headers: { cookie: s.header } }), { cookie })
    assert.equal(r.principal.label, s.token.label)
    assert.match(r.headers.get('set-cookie'), /^app_session=/)
    const none = await ft.authenticate(t.tk, new Request('http://app.example/'), { cookie })
    assert.equal(none.principal, null)
  })
})

describe('Quiver token commands', () => {
  let t, cmds, admin, issuer, reader
  before(async () => {
    t = await fresh(sqlite)
    cmds = tokenCommands(t.tk)
    admin = await t.tk.authenticate((await t.tk.tokens.create({ label: 'admin', grants: ['turnkey:manage', 'read:*', 'write:*'] }, 'x')).secret)
    issuer = await t.tk.authenticate((await t.tk.tokens.create({ label: 'lp', grants: ['turnkey:issue', 'read:*'] }, 'x')).secret)
    reader = await t.tk.authenticate((await t.tk.tokens.create({ label: 'reader', grants: ['read:*'] }, 'x')).secret)
  })
  after(async () => t.close())

  test('the manifest group', () => {
    assert.equal(cmds.commands.length, 1)
    assert.equal(cmds.commands[0].name, 'tokens')
    assert.deepEqual(cmds.commands[0].commands.map((c) => c.name), ['list', 'show', 'create', 'extend', 'grant', 'ungrant', 'revoke', 'rotate'])
    assert.ok(cmds.handles(['tokens', 'list']))
    assert.ok(!cmds.handles(['tokens']))
    assert.ok(!cmds.handles(['other', 'list']))
  })

  test('the same rules as the library', async () => {
    await assert.rejects(() => cmds.run(['tokens', 'list'], {}, null), (e) => e.status === 401)
    assert.deepEqual((await cmds.run(['tokens', 'list'], {}, reader)).tokens.map((x) => x.label), ['reader'], 'any token sees itself')
    await assert.rejects(() => cmds.run(['tokens', 'create'], { label: 'x', grant: ['read:a'] }, reader), (e) => e.status === 403)
    await assert.rejects(() => cmds.run(['tokens', 'show'], { label: 'admin' }, reader), (e) => e.status === 404)
  })

  test('create, list, extend, grant, ungrant, rotate, revoke', async () => {
    const created = await cmds.run(['tokens', 'create'], { label: 'host1', grant: ['read:a'], session: 'abc' }, admin)
    assert.match(created.secret, /^tt_/)
    assert.equal(created.createdBy, 'session:abc@admin')
    assert.ok((await cmds.run(['tokens', 'list'], {}, admin)).tokens.some((x) => x.label === 'host1'))
    assert.deepEqual((await cmds.run(['tokens', 'grant'], { label: 'host1', grant: ['write:b'] }, admin)).grants, ['read:a', 'write:b'])
    assert.deepEqual((await cmds.run(['tokens', 'ungrant'], { label: 'host1', grant: ['read:a'] }, admin)).grants, ['write:b'])
    const rotated = await cmds.run(['tokens', 'rotate'], { label: 'host1' }, admin)
    assert.notEqual(rotated.secret, created.secret)
    assert.equal((await cmds.run(['tokens', 'show'], { label: 'host1' }, admin)).label, 'host1')
    assert.equal((await cmds.run(['tokens', 'extend'], { label: 'host1', ttl: 600 }, admin)).expiresAt, new Date(t.clock.ms + 600_000).toISOString())
    assert.equal((await cmds.run(['tokens', 'revoke'], { label: 'host1' }, admin)).active, false)
    assert.ok(!(await cmds.run(['tokens', 'list'], {}, admin)).tokens.some((x) => x.label === 'host1'))
    assert.ok((await cmds.run(['tokens', 'list'], { all: true }, admin)).tokens.some((x) => x.label === 'host1'))
    await assert.rejects(() => cmds.run(['tokens', 'create'], { label: 'x', grant: [] }, admin), (e) => e.status === 400)
  })

  test('children through the commands', async () => {
    const c = await cmds.run(['tokens', 'create'], { label: 'job-1', grant: ['read:x'], child: true, ttl: 120 }, issuer)
    assert.equal(c.label, 'lp.job-1')
    assert.equal(c.parent, issuer.id)
    assert.deepEqual((await cmds.run(['tokens', 'list'], { parent: 'lp' }, admin)).tokens.map((x) => x.label), ['lp.job-1'])
    assert.equal((await cmds.run(['tokens', 'extend'], { label: 'lp.job-1' }, issuer)).expiresAt, new Date(t.clock.ms + 3600_000).toISOString())
    assert.equal((await cmds.run(['tokens', 'revoke'], { label: 'lp.job-1' }, issuer)).active, false)
  })
})

describe('admin CLI', () => {
  test('create, list, grant, rotate, revoke; errors exit non-zero', async () => {
    const t = await fresh(sqlite)
    const out = []
    const err = []
    const io = { out: (l) => out.push(l), err: (l) => err.push(l) }
    const run = (...argv) => runAdminCli(t.tk, argv, io)
    try {
      assert.equal(await run('token', 'create', 'first', '--grant', 'turnkey:manage', '--grant=read:*'), 0)
      const created = JSON.parse(out.pop())
      assert.match(created.secret, /^tt_/)
      assert.deepEqual(created.grants, ['read:*', 'turnkey:manage'])
      assert.equal(created.createdBy, 'admin-cli')
      assert.equal((await t.tk.authenticate(created.secret)).label, 'first')
      assert.equal(await run('list'), 0)
      assert.equal(JSON.parse(out.pop()).length, 1)
      assert.equal(await run('extend', 'first', '--expires', new Date(t.clock.ms + 86_400_000).toISOString()), 0)
      assert.equal(JSON.parse(out.pop()).expiresAt, new Date(t.clock.ms + 86_400_000).toISOString())
      assert.equal(await run('grant', 'first', '--grant', 'write:x'), 0)
      assert.deepEqual(JSON.parse(out.pop()).grants, ['read:*', 'turnkey:manage', 'write:x'])
      assert.equal(await run('rotate', 'first'), 0)
      assert.match(JSON.parse(out.pop()).secret, /^tt_/)
      assert.equal(await run('revoke', 'first'), 0)
      assert.equal(JSON.parse(out.pop()).active, false)
      assert.equal(await run('show', 'missing'), 1)
      assert.match(err.pop(), /no token/)
      assert.equal(await run('create', 'x'), 1, 'no grant')
      assert.equal(await run('frobnicate'), 2)
      assert.equal(await run(), 0)
    } finally {
      await t.close()
    }
  })
})
