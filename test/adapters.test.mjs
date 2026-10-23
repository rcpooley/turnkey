// The web adapters, the Quiver commands and the admin CLI. Each adapter serves the credential
// contract exactly as an orchestrator calls it; these run on SQLite (adapters don't touch SQL).
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
    app.use('/credentials', ex.credentialsRouter(tk, { service: 'demo' }))
    app.get('/elsewhere', (_req, res) => res.json({ ok: true }))
    // A real app's own JSON 404 and error handler (express.json() rejects bad JSON before Turnkey sees it).
    app.use((_req, res) => res.status(404).json({ error: 'app 404' }))
    app.use((err, _req, res, _next) => res.status(err.status ?? 500).json({ error: err.message }))
    return app
  },
  'express (no body parser)': (tk) => {
    const app = express()
    app.use('/credentials', ex.credentialsRouter(tk, { service: 'demo' }))
    app.use((_req, res) => res.status(404).json({ error: 'app 404' }))
    return app
  },
  node: (tk) => {
    const handle = nd.credentialsHandler(tk, { service: 'demo' })
    return async (req, res) => {
      if (await handle(req, res)) return
      nd.sendJson(res, 404, { error: 'app 404' })
    }
  },
  fetch: (tk) => {
    const handle = ft.credentialsHandler(tk, { service: 'demo' })
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
  describe(`credential contract over ${name}`, () => {
    let t, srv, issuer, plain
    before(async () => {
      t = await fresh(sqlite, { credentials: { maxTtlSeconds: 1800 } })
      srv = await serve(make(t.tk))
      issuer = (await t.tk.tokens.create({ label: 'lp', grants: ['turnkey:issue', 'write:sessions', 'read:*'], createdBy: 'x' })).secret
      plain = (await t.tk.tokens.create({ label: 'plain', grants: ['write:*'], createdBy: 'x' })).secret
    })
    after(async () => {
      await srv.close()
      await t.close()
    })

    test('every call needs an issuer token', async () => {
      assert.equal((await call(srv.base, 'GET', '/credentials/describe')).status, 401)
      const bad = await call(srv.base, 'GET', '/credentials/describe', { token: 'tt_nope' })
      assert.equal(bad.status, 401)
      assert.equal(bad.body.code, 'unauthorized')
      const notIssuer = await call(srv.base, 'GET', '/credentials/describe', { token: plain })
      assert.equal(notIssuer.status, 403)
      assert.equal(typeof notIssuer.body.error, 'string')
    })

    test('describe', async () => {
      const r = await call(srv.base, 'GET', '/credentials/describe', { token: issuer })
      assert.equal(r.status, 200)
      assert.equal(r.body.service, 'demo')
      assert.equal(r.body.maxTtlSeconds, 1800)
      assert.deepEqual(Object.keys(r.body.values), ['token'])
      assert.deepEqual(r.body.grants, ['read:*', 'write:sessions'])
    })

    test('validate: 2xx, 400 for a bad shape, 403 beyond the issuer', async () => {
      const ok = await call(srv.base, 'POST', '/credentials/validate', { token: issuer, body: { permissions: { grants: ['write:sessions/abc', 'read:x'] } } })
      assert.equal(ok.status, 200)
      assert.deepEqual(ok.body.grants, ['read:x', 'write:sessions/abc'])
      for (const permissions of [undefined, [], { grants: 'read:*' }, { grants: [] }, { grants: ['read:*'], extra: 1 }, { grants: ['bogus:x'] }, { grants: [5] }]) {
        assert.equal((await call(srv.base, 'POST', '/credentials/validate', { token: issuer, body: { permissions } })).status, 400, JSON.stringify(permissions))
      }
      assert.equal((await call(srv.base, 'POST', '/credentials/validate', { token: issuer, body: { permissions: { grants: ['write:projects'] } } })).status, 403)
      assert.equal((await call(srv.base, 'POST', '/credentials/validate', { token: issuer, body: { permissions: { grants: ['turnkey:issue'] } } })).status, 403)
      assert.equal((await call(srv.base, 'POST', '/credentials/validate', { token: issuer, body: '{not json' })).status, 400)
    })

    test('issue → use → renew → revoke, and 404 after', async () => {
      const issued = await call(srv.base, 'POST', '/credentials/issue', {
        token: issuer,
        body: { subject: { session: 'sess-1', agent: 'dev', host: 'h' }, permissions: { grants: ['write:sessions/sess-1'] }, ttlSeconds: 99999 },
      })
      assert.equal(issued.status, 200)
      assert.deepEqual(Object.keys(issued.body).sort(), ['expiresAt', 'id', 'values'])
      assert.deepEqual(Object.keys(issued.body.values), ['token'])
      assert.ok(Date.parse(issued.body.expiresAt) - t.clock.ms <= 1800_000, 'capped at maxTtlSeconds')
      const { id } = issued.body
      const p = await t.tk.authenticate(issued.body.values.token)
      assert.equal(p.label, 'lp.sess-1')
      assert.ok(t.tk.can(p, 'write', 'sessions/sess-1'))

      t.clock.advance(600)
      const renewed = await call(srv.base, 'POST', '/credentials/renew', { token: issuer, body: { id, ttlSeconds: 1800 } })
      assert.equal(renewed.status, 200)
      assert.equal(renewed.body.expiresAt, new Date(t.clock.ms + 1800_000).toISOString())

      assert.equal((await call(srv.base, 'POST', '/credentials/revoke', { token: issuer, body: { id } })).status, 200)
      assert.equal((await call(srv.base, 'POST', '/credentials/revoke', { token: issuer, body: { id } })).status, 200, 'idempotent')
      const gone = await call(srv.base, 'POST', '/credentials/renew', { token: issuer, body: { id, ttlSeconds: 1800 } })
      assert.equal(gone.status, 404)
      assert.equal(gone.body.code, 'not_found')
      assert.equal(await t.tk.authenticate(issued.body.values.token), null)
    })

    test('issue needs subject.session; renew of an expired credential is a 404', async () => {
      assert.equal((await call(srv.base, 'POST', '/credentials/issue', { token: issuer, body: { permissions: { grants: ['read:x'] } } })).status, 400)
      assert.equal((await call(srv.base, 'POST', '/credentials/issue', { token: issuer, body: { subject: {}, permissions: { grants: ['read:x'] } } })).status, 400)
      const r = await call(srv.base, 'POST', '/credentials/issue', { token: issuer, body: { subject: { session: 's' }, permissions: { grants: ['read:x'] }, ttlSeconds: 60 } })
      t.clock.advance(61)
      const gone = await call(srv.base, 'POST', '/credentials/renew', { token: issuer, body: { id: r.body.id, ttlSeconds: 60 } })
      assert.equal(gone.status, 404)
      assert.equal(gone.body.code, 'not_found')
    })

    test('an issued credential cannot use the contract', async () => {
      const r = await call(srv.base, 'POST', '/credentials/issue', { token: issuer, body: { subject: { session: 'x' }, permissions: { grants: ['read:*'] } } })
      const res = await call(srv.base, 'POST', '/credentials/issue', { token: r.body.values.token, body: { subject: { session: 'y' }, permissions: { grants: ['read:*'] } } })
      assert.equal(res.status, 403)
    })

    test('other paths fall through to the app', async () => {
      const r = await call(srv.base, 'GET', '/credentials/nope', { token: issuer })
      assert.equal(r.status, 404)
      const wrongMethod = await call(srv.base, 'GET', '/credentials/issue', { token: issuer })
      assert.equal(wrongMethod.status, 405)
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
    const { secret, token } = await t.tk.sessions.create({ grants: ['read:*'], createdBy: 'login' })
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
      const tok = await t.tk.tokens.create({ label: 'cli', grants: ['read:*'], createdBy: 'x' })
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

      await t.tk.sessions.revoke(s.token.id, 'logout')
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
  let t, cmds, admin, reader
  before(async () => {
    t = await fresh(sqlite)
    cmds = tokenCommands(t.tk)
    admin = await t.tk.authenticate((await t.tk.tokens.create({ label: 'admin', grants: ['turnkey:manage', 'turnkey:issue', 'read:*'], createdBy: 'x' })).secret)
    reader = await t.tk.authenticate((await t.tk.tokens.create({ label: 'reader', grants: ['read:*'], createdBy: 'x' })).secret)
  })
  after(async () => t.close())

  test('the manifest group', () => {
    assert.equal(cmds.commands.length, 1)
    assert.equal(cmds.commands[0].name, 'tokens')
    assert.deepEqual(cmds.commands[0].commands.map((c) => c.name), ['list', 'show', 'create', 'grant', 'ungrant', 'revoke', 'rotate', 'credentials'])
    assert.ok(cmds.handles(['tokens', 'list']))
    assert.ok(!cmds.handles(['tokens']))
    assert.ok(!cmds.handles(['other', 'list']))
  })

  test('every command needs turnkey:manage', async () => {
    await assert.rejects(() => cmds.run(['tokens', 'list'], {}, reader), (e) => e.status === 403)
    await assert.rejects(() => cmds.run(['tokens', 'list'], {}, null), (e) => e.status === 401)
  })

  test('create, list, grant, ungrant, rotate, revoke, credentials', async () => {
    const created = await cmds.run(['tokens', 'create'], { label: 'host1', grant: ['read:a'], session: 'abc' }, admin)
    assert.match(created.secret, /^tt_/)
    assert.equal(created.createdBy, 'session:abc@admin')
    assert.ok((await cmds.run(['tokens', 'list'], {}, admin)).tokens.some((x) => x.label === 'host1'))
    assert.deepEqual((await cmds.run(['tokens', 'grant'], { label: 'host1', grant: ['write:b'] }, admin)).grants, ['read:a', 'write:b'])
    assert.deepEqual((await cmds.run(['tokens', 'ungrant'], { label: 'host1', grant: ['read:a'] }, admin)).grants, ['write:b'])
    const rotated = await cmds.run(['tokens', 'rotate'], { label: 'host1' }, admin)
    assert.notEqual(rotated.secret, created.secret)
    assert.equal((await cmds.run(['tokens', 'show'], { label: 'host1' }, admin)).label, 'host1')
    await t.tk.credentials.issue(admin, { grants: ['read:x'], subject: { session: 'q' } })
    assert.equal((await cmds.run(['tokens', 'credentials'], {}, admin)).credentials.length, 1)
    assert.equal((await cmds.run(['tokens', 'revoke'], { label: 'host1' }, admin)).active, false)
    assert.ok(!(await cmds.run(['tokens', 'list'], {}, admin)).tokens.some((x) => x.label === 'host1'))
    assert.ok((await cmds.run(['tokens', 'list'], { all: true }, admin)).tokens.some((x) => x.label === 'host1'))
    await assert.rejects(() => cmds.run(['tokens', 'create'], { label: 'x', grant: [] }, admin), (e) => e.status === 400)
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
