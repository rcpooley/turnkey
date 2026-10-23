// The database contract Turnkey's core runs on. Each driver adapter (./index.ts) wraps a client the
// service already has. SQL is written with `?` placeholders; a Postgres driver renumbers them.

export type Dialect = 'postgres' | 'mysql' | 'sqlite'
export type Row = Record<string, unknown>

/** One connection's worth of query methods. */
export interface Queryable {
  query(sql: string, params?: readonly unknown[]): Promise<Row[]>
  /** Runs a statement and returns how many rows it changed or matched. */
  run(sql: string, params?: readonly unknown[]): Promise<number>
}

export interface Driver extends Queryable {
  readonly dialect: Dialect
  /**
   * Runs `fn` on one connection while holding a lock named `name`, so two processes starting at
   * once take turns. Postgres runs it in a transaction (its DDL is transactional); SQLite in
   * `BEGIN IMMEDIATE`; MySQL holds `GET_LOCK` (its DDL commits on its own).
   */
  locked<T>(name: string, fn: (q: Queryable) => Promise<T>): Promise<T>
}
