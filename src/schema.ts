// Turnkey's tables, as numbered migrations per dialect. A fresh database replays every migration
// in order; there is no separate "full schema" to drift from them. `{p}` is the table prefix.
// Timestamps are ISO 8601 UTC strings of fixed width (`2026-01-02T03:04:05.678Z`): they sort and
// compare as text the same way in every dialect, and stay readable in a SQL console.
import { createHash } from 'node:crypto'
import type { Dialect } from './db/types.js'

export interface Migration {
  version: number
  name: string
  statements: Record<Dialect, string[]>
}

const TS = 'VARCHAR(24)'

function tokensTable(d: Dialect): string {
  const text = 'TEXT'
  const int = d === 'mysql' ? 'INT' : 'INTEGER'
  return `CREATE TABLE {p}tokens (
  id VARCHAR(40) NOT NULL PRIMARY KEY,
  label VARCHAR(128) NOT NULL,
  kind VARCHAR(16) NOT NULL,
  secret_hash CHAR(64) NOT NULL,
  grants ${text} NOT NULL,
  subject ${text} NULL,
  issued_by VARCHAR(40) NULL,
  expires_at ${TS} NULL,
  slide_seconds ${int} NULL,
  created_at ${TS} NOT NULL,
  created_by VARCHAR(128) NOT NULL,
  rotated_at ${TS} NULL,
  rotated_by VARCHAR(128) NULL,
  revoked_at ${TS} NULL,
  revoked_by VARCHAR(128) NULL,
  last_used_at ${TS} NULL,
  CONSTRAINT {p}tokens_label UNIQUE (label),
  CONSTRAINT {p}tokens_secret_hash UNIQUE (secret_hash)
)`
}

const migrationsTable = (d: Dialect) => `CREATE TABLE IF NOT EXISTS {p}migrations (
  version ${d === 'mysql' ? 'INT' : 'INTEGER'} NOT NULL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  checksum CHAR(64) NOT NULL,
  applied_at ${TS} NOT NULL
)`

const forAll = (f: (d: Dialect) => string[]): Record<Dialect, string[]> => ({ postgres: f('postgres'), mysql: f('mysql'), sqlite: f('sqlite') })

/** Every migration, oldest first. Never edit one that has shipped: add the next. */
export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    name: 'tokens',
    statements: forAll((d) => [tokensTable(d), 'CREATE INDEX {p}tokens_issued_by ON {p}tokens (issued_by)']),
  },
  {
    // 0.2.0: one token concept. An issued credential is now a child of the token that created it,
    // and a token's kind is no longer stored (a child has a parent; a session has a sliding expiry).
    version: 2,
    name: 'parent',
    // MySQL commits each DDL statement on its own, so there it is one ALTER (atomic): a crash can't
    // leave it half done. Postgres and SQLite run the migration in a transaction.
    statements: forAll((d) =>
      d === 'mysql'
        ? ['ALTER TABLE {p}tokens DROP INDEX {p}tokens_issued_by, RENAME COLUMN issued_by TO parent, ADD INDEX {p}tokens_parent (parent), DROP COLUMN kind']
        : [
            'DROP INDEX {p}tokens_issued_by',
            'ALTER TABLE {p}tokens RENAME COLUMN issued_by TO parent',
            'CREATE INDEX {p}tokens_parent ON {p}tokens (parent)',
            'ALTER TABLE {p}tokens DROP COLUMN kind',
          ],
    ),
  },
]

/** The bookkeeping table. Created before anything else, outside the numbered migrations. */
export const MIGRATIONS_TABLE = migrationsTable

/** The columns each table has after the latest migration. The startup check compares against this. */
export const EXPECTED_COLUMNS: Record<string, string[]> = {
  tokens: [
    'id', 'label', 'secret_hash', 'grants', 'subject', 'parent', 'expires_at', 'slide_seconds',
    'created_at', 'created_by', 'rotated_at', 'rotated_by', 'revoked_at', 'revoked_by', 'last_used_at',
  ],
  migrations: ['version', 'name', 'checksum', 'applied_at'],
}

export const LATEST_VERSION = MIGRATIONS[MIGRATIONS.length - 1]!.version

/** A migration's checksum for one dialect: sha256 of its statements before the prefix is filled in. */
export function checksum(m: Migration, d: Dialect): string {
  return createHash('sha256').update(m.statements[d].join(';\n')).digest('hex')
}

export const withPrefix = (sql: string, prefix: string) => sql.replaceAll('{p}', prefix)
