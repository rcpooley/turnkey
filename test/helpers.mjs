// Test databases. Every dialect runs the same behaviour suite; each test gets its own table prefix
// (and, on Dolt, its own database), so tests never see each other's rows.
//   TURNKEY_TEST_PG     Postgres URL (default postgres://turnkey_test@127.0.0.1:5432/turnkey_test)
//   TURNKEY_TEST_DOLT   MySQL-protocol URL of a Dolt server (default mysql://root@127.0.0.1:3518)
//   TURNKEY_TEST_ONLY   comma-separated dialects to run (pg,postgresjs,dolt,sqlite)
// A dialect whose server isn't reachable is skipped with a note, unless CI=true (then it fails).
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import pgLib from 'pg'
import postgres from 'postgres'
import mysql from 'mysql2/promise'
import { createTurnkey } from '../dist/index.js'
import * as db from '../dist/db/index.js'

export const PG_URL = process.env.TURNKEY_TEST_PG ?? 'postgres://turnkey_test@127.0.0.1:5432/turnkey_test'
export const DOLT_URL = process.env.TURNKEY_TEST_DOLT ?? 'mysql://root@127.0.0.1:3518'
const ONLY = process.env.TURNKEY_TEST_ONLY?.split(',').map((s) => s.trim())

export const PERMISSIONS = { actions: ['read', 'write', 'admin', 'spawn'], implies: { admin: ['write'], write: ['read'] } }

export const uid = () => randomBytes(5).toString('hex')

/** A controllable clock. */
export function clock(start = Date.parse('2030-01-01T00:00:00.000Z')) {
  let t = start
  return { now: () => new Date(t), advance: (sec) => (t += sec * 1000), get ms() { return t } }
}

/**
 * Each backend: `open()` gives a fresh, isolated `{driver, prefix, raw, close}`; `raw` runs SQL
 * directly (`?` placeholders) for assertions and tampering.
 */
export const backends = [
  {
    name: 'pg',
    async probe() {
      const pool = new pgLib.Pool({ connectionString: PG_URL, max: 1 })
      try { await pool.query('SELECT 1') } finally { await pool.end() }
    },
    async open() {
      const pool = new pgLib.Pool({ connectionString: PG_URL, max: 8 })
      const prefix = `t${uid()}_`
      const driver = db.pg(pool)
      return { driver, prefix, raw: driver, async close() { await dropPrefix(driver, prefix); await pool.end() } }
    },
  },
  {
    name: 'postgresjs',
    async probe() {
      const sql = postgres(PG_URL, { max: 1, onnotice: () => {} })
      try { await sql`SELECT 1` } finally { await sql.end() }
    },
    async open() {
      const sql = postgres(PG_URL, { max: 8, onnotice: () => {} })
      const prefix = `t${uid()}_`
      const driver = db.postgresJs(sql)
      return { driver, prefix, raw: driver, async close() { await dropPrefix(driver, prefix); await sql.end() } }
    },
  },
  {
    name: 'dolt',
    async probe() {
      const c = await mysql.createConnection(DOLT_URL)
      try { await c.query('SELECT dolt_version()') } finally { await c.end() }
    },
    async open() {
      const name = `tk_${uid()}`
      const admin = await mysql.createConnection(DOLT_URL)
      await admin.query(`CREATE DATABASE ${name}`)
      await admin.end()
      const pool = mysql.createPool({ uri: `${DOLT_URL}/${name}`, connectionLimit: 8 })
      const driver = db.mysql2(pool)
      // A service's own committed table, so there is history to compare against.
      await driver.run('CREATE TABLE app_things (id INT PRIMARY KEY)')
      await driver.query("CALL DOLT_ADD('-A')")
      await driver.query("CALL DOLT_COMMIT('-m', 'app schema')")
      return {
        driver, prefix: 'turnkey_', raw: driver, database: name, pool,
        async close() {
          await pool.end()
          const a = await mysql.createConnection(DOLT_URL)
          await a.query(`DROP DATABASE ${name}`).catch(() => {})
          await a.end()
        },
      }
    },
  },
  {
    name: 'sqlite',
    async probe() {},
    async open() {
      const dir = mkdtempSync(join(tmpdir(), 'turnkey-'))
      const file = join(dir, 'test.db')
      const sqlite = new DatabaseSync(file)
      const driver = db.nodeSqlite(sqlite)
      return { driver, prefix: 'turnkey_', raw: driver, file, async close() { sqlite.close(); rmSync(dir, { recursive: true, force: true }) } }
    },
  },
]

async function dropPrefix(driver, prefix) {
  for (const t of ['tokens', 'migrations']) await driver.run(`DROP TABLE IF EXISTS ${prefix}${t}`).catch(() => {})
}

/** Backends to run, after checking each is reachable. */
export async function available() {
  const out = []
  for (const b of backends) {
    if (ONLY && !ONLY.includes(b.name)) continue
    try {
      await b.probe()
      out.push(b)
    } catch (err) {
      if (process.env.CI === 'true') throw new Error(`${b.name} is not reachable in CI: ${err.message}`)
      console.error(`# skipping ${b.name}: ${err.message}`)
    }
  }
  return out
}

/** A Turnkey on a fresh database. Extra options override the defaults. */
export async function fresh(backend, opts = {}) {
  const env = await backend.open()
  const c = opts.clock ?? clock()
  const tk = await createTurnkey({ db: env.driver, tablePrefix: env.prefix, tokenPrefix: 'tt_', permissions: PERMISSIONS, purgeIntervalMs: false, now: c.now, ...opts })
  return { tk, env, clock: c, async close() { await tk.close(); await env.close() } }
}

/** A permanent token with these grants, authenticated. */
export async function principalWith(tk, label, grants) {
  const { secret } = await tk.tokens.create({ label, grants, createdBy: 'test' })
  return { secret, principal: await tk.authenticate(secret) }
}
