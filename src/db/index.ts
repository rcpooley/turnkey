// Driver adapters. Each takes a client the service already created and owns; Turnkey never opens
// or closes the service's connections. Types are structural, so this file imports no driver.
import type { Driver, Queryable, Row } from './types.js'

export type { Dialect, Driver, Queryable, Row } from './types.js'

/** `?` → `$1, $2, …`. Turnkey's own SQL never has a `?` inside a string literal. */
function numbered(sql: string): string {
  let n = 0
  return sql.replace(/\?/g, () => `$${++n}`)
}

// ------------------------------------------------------------------ pg

interface PgResult {
  rows: Row[]
  rowCount: number | null
}
interface PgClientLike {
  query(text: string, values?: unknown[]): Promise<PgResult>
}
interface PgPoolLike extends PgClientLike {
  connect(): Promise<PgClientLike & { release(destroy?: boolean | Error): void }>
}

/** A `pg` Pool (or anything with its `query` and `connect`). */
export function pg(pool: PgPoolLike): Driver {
  const on = (c: PgClientLike): Queryable => ({
    async query(sql, params = []) {
      return (await c.query(numbered(sql), [...params])).rows
    },
    async run(sql, params = []) {
      return (await c.query(numbered(sql), [...params])).rowCount ?? 0
    },
  })
  return {
    dialect: 'postgres',
    ...on(pool),
    async locked(name, fn) {
      const client = await pool.connect()
      let failed: unknown
      try {
        await client.query('BEGIN')
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [name])
        const out = await fn(on(client))
        await client.query('COMMIT')
        return out
      } catch (err) {
        failed = err
        await client.query('ROLLBACK').catch(() => {})
        throw err
      } finally {
        // After a failure the connection's state is unknown: drop it rather than return it to the pool.
        client.release(failed ? true : undefined)
      }
    },
  }
}

// ------------------------------------------------------------------ postgres.js

interface PostgresJsLike {
  unsafe(query: string, params?: unknown[]): PromiseLike<Row[] & { count: number }>
  begin<T>(fn: (sql: PostgresJsLike) => T | Promise<T>): Promise<unknown>
}

/** A postgres.js `sql` instance. */
export function postgresJs(sql: PostgresJsLike): Driver {
  const on = (s: PostgresJsLike): Queryable => ({
    async query(q, params = []) {
      return [...(await s.unsafe(numbered(q), [...params]))]
    },
    async run(q, params = []) {
      return (await s.unsafe(numbered(q), [...params])).count ?? 0
    },
  })
  return {
    dialect: 'postgres',
    ...on(sql),
    async locked(name, fn) {
      let out: unknown
      await sql.begin(async (tx) => {
        await tx.unsafe('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [name])
        out = await fn(on(tx))
      })
      return out as Awaited<ReturnType<typeof fn>>
    },
  }
}

// ------------------------------------------------------------------ mysql2 (MySQL and Dolt)

interface MysqlConnLike {
  query(sql: string, values?: unknown[]): Promise<[unknown, unknown]>
}
interface MysqlPoolLike extends MysqlConnLike {
  getConnection(): Promise<MysqlConnLike & { release(): void }>
}

/** A `mysql2/promise` Pool. Works for MySQL 8 and Dolt. */
export function mysql2(pool: MysqlPoolLike): Driver {
  const on = (c: MysqlConnLike): Queryable => ({
    async query(sql, params = []) {
      const [rows] = await c.query(sql, [...params])
      return Array.isArray(rows) ? (rows as Row[]) : []
    },
    async run(sql, params = []) {
      const [res] = await c.query(sql, [...params])
      return (res as { affectedRows?: number }).affectedRows ?? 0
    },
  })
  return {
    dialect: 'mysql',
    ...on(pool),
    async locked(name, fn) {
      const conn = await pool.getConnection()
      try {
        const q = on(conn)
        const [row] = await q.query('SELECT GET_LOCK(?, 60) AS ok', [name])
        if (Number(row?.ok) !== 1) throw new Error(`timed out waiting for lock "${name}"`)
        try {
          return await fn(q)
        } finally {
          await q.query('SELECT RELEASE_LOCK(?)', [name]).catch(() => {})
        }
      } finally {
        conn.release()
      }
    },
  }
}

// ------------------------------------------------------------------ node:sqlite

interface SqliteStatementLike {
  all(...params: unknown[]): unknown[]
  run(...params: unknown[]): { changes: number | bigint }
}
interface SqliteDbLike {
  prepare(sql: string): SqliteStatementLike
  exec(sql: string): void
}

/** A `node:sqlite` DatabaseSync. (better-sqlite3 has the same shape.) */
export function nodeSqlite(db: SqliteDbLike): Driver {
  // node:sqlite binds numbers, strings, bigints, null and buffers; booleans become 0/1.
  const bind = (params: readonly unknown[]) => params.map((p) => (typeof p === 'boolean' ? (p ? 1 : 0) : p === undefined ? null : p))
  const q: Queryable = {
    async query(sql, params = []) {
      return db.prepare(sql).all(...bind(params)) as Row[]
    },
    async run(sql, params = []) {
      return Number(db.prepare(sql).run(...bind(params)).changes)
    },
  }
  let chain: Promise<unknown> = Promise.resolve()
  return {
    dialect: 'sqlite',
    ...q,
    locked(_name, fn) {
      // One connection: serialise callers in this process; BEGIN IMMEDIATE excludes other processes.
      const next = chain.then(async () => {
        db.exec('BEGIN IMMEDIATE')
        try {
          const out = await fn(q)
          db.exec('COMMIT')
          return out
        } catch (err) {
          try {
            db.exec('ROLLBACK')
          } catch {}
          throw err
        }
      })
      chain = next.catch(() => {})
      return next
    },
  }
}
