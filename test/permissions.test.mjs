// The permission grammar and coverage rules: pure, no database.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Actions, parsePermission, covers, canonical } from '../dist/index.js'

const actions = new Actions({ actions: ['read', 'write', 'admin', 'exec'], implies: { admin: ['write'], write: ['read'] } })
const p = (s) => parsePermission(s, actions)
const cov = (a, b) => covers(p(a), p(b), actions)

test('parses action:resource paths', () => {
  assert.deepEqual(p('read:*'), { action: 'read', resource: ['*'] })
  assert.deepEqual(p('write:sessions/abc'), { action: 'write', resource: ['sessions', 'abc'] })
  assert.deepEqual(p('*:*'), { action: '*', resource: ['*'] })
  assert.deepEqual(p('exec:tasks/*/add'), { action: 'exec', resource: ['tasks', '*', 'add'] })
  assert.deepEqual(p('turnkey:manage'), { action: 'turnkey', resource: ['manage'] })
  assert.deepEqual(p('read:Some.Thing@v2~x'), { action: 'read', resource: ['Some.Thing@v2~x'] })
})

test('rejects malformed permissions with a 400', () => {
  for (const bad of ['', 'read', 'read:', ':x', 'nope:x', 'read:a//b', 'read:/a', 'read:a/', 'read:a b', 'read:ab*', 'read:a:b', 'turnkey:other', 'turnkey:manage/x', 'READ:x']) {
    assert.throws(() => p(bad), (e) => e.status === 400 && e.code === 'bad_request', bad)
  }
})

test('action rules are validated', () => {
  assert.throws(() => new Actions({ actions: [] }))
  assert.throws(() => new Actions({ actions: ['turnkey'] }), /reserved/)
  assert.throws(() => new Actions({ actions: ['Read'] }))
  assert.throws(() => new Actions({ actions: ['read'], implies: { write: ['read'] } }), /not a declared/)
})

test('resources match hierarchically', () => {
  assert.ok(cov('read:sessions', 'read:sessions'))
  assert.ok(cov('read:sessions', 'read:sessions/abc'))
  assert.ok(cov('read:sessions', 'read:sessions/abc/files'))
  assert.ok(!cov('read:sessions/abc', 'read:sessions'))
  assert.ok(!cov('read:sessions/abc', 'read:sessions/abd'))
  assert.ok(!cov('read:sessions', 'read:sessionsx'))
  assert.ok(!cov('read:sessions', 'read:other'))
})

test('a * segment matches any one segment; * alone is everything', () => {
  assert.ok(cov('exec:tasks/*/add', 'exec:tasks/x/add'))
  assert.ok(cov('exec:tasks/*/add', 'exec:tasks/x/add/more'))
  assert.ok(!cov('exec:tasks/*/add', 'exec:tasks/x/rm'))
  assert.ok(!cov('exec:tasks/*/add', 'exec:tasks/x'))
  assert.ok(cov('exec:*', 'exec:anything/at/all'))
  assert.ok(cov('exec:*', 'exec:*'))
  assert.ok(cov('exec:tasks/*', 'exec:tasks/*'))
  assert.ok(!cov('exec:tasks', 'exec:*'), 'a narrower grant never covers a wider one')
  assert.ok(!cov('exec:tasks/x', 'exec:tasks/*'))
})

test('implies is transitive; * covers every action', () => {
  assert.ok(cov('write:x', 'read:x'))
  assert.ok(cov('admin:x', 'read:x/y'), 'admin → write → read')
  assert.ok(!cov('read:x', 'write:x'))
  assert.ok(!cov('write:x', 'admin:x'))
  assert.ok(!cov('write:x', 'exec:x'))
  assert.ok(cov('*:x', 'exec:x/y'))
  assert.ok(cov('*:*', 'turnkey:manage'))
  assert.ok(cov('turnkey:*', 'turnkey:issue'))
  assert.ok(!cov('turnkey:manage', 'turnkey:issue'))
  assert.ok(!cov('*:x', '*:*'))
})

test('canonical de-duplicates and sorts', () => {
  assert.deepEqual(canonical(['write:b', ' read:a ', 'write:b'], actions), ['read:a', 'write:b'])
})
