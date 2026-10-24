// Startup: take a lock, keep Turnkey's tables out of Dolt's history, apply pending migrations, and
// check the result. Refuses to start on a changed migration, a newer database or a missing column.
import type { Driver, Queryable } from './db/types.js'
import { schemaError } from './errors.js'
import { checksum, EXPECTED_COLUMNS, LATEST_VERSION, MIGRATIONS, MIGRATIONS_TABLE, withPrefix } from './schema.js'
import { isoNow } from './util.js'

export interface MigrateOptions {
  prefix: string
  /** Commit author for the one Dolt commit that adds the ignore rule. */
  doltAuthor: string
  log: (msg: string) => void
}

export interface MigrateResult {
  dolt: boolean
  applied: number[]
}

export async function migrate(db: Driver, opts: MigrateOptions): Promise<MigrateResult> {
  const { prefix } = opts
  return db.locked(`turnkey:${prefix}`, async (q) => {
    const dolt = db.dialect === 'mysql' && (await isDolt(q))
    if (dolt) await ensureDoltIgnore(q, prefix, opts)

    await q.run(withPrefix(MIGRATIONS_TABLE(db.dialect), prefix))
    const applied = new Map<number, string>()
    for (const r of await q.query(`SELECT version, checksum FROM ${prefix}migrations ORDER BY version`)) {
      applied.set(Number(r.version), String(r.checksum))
    }
    const newest = Math.max(0, ...applied.keys())
    if (newest > LATEST_VERSION) {
      throw schemaError(
        `the database's Turnkey tables (prefix "${prefix}") are at version ${newest}, newer than this library knows (${LATEST_VERSION}): upgrade the library, don't downgrade it`,
      )
    }
    const done: number[] = []
    for (const m of MIGRATIONS) {
      const sum = checksum(m, db.dialect)
      const had = applied.get(m.version)
      if (had !== undefined) {
        if (had !== sum) throw schemaError(`Turnkey migration ${m.version} (${m.name}) changed after it was applied (checksum mismatch)`)
        continue
      }
      for (const s of m.statements[db.dialect]) await q.run(withPrefix(s, prefix))
      await q.run(`INSERT INTO ${prefix}migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`, [m.version, m.name, sum, isoNow()])
      done.push(m.version)
      opts.log(`turnkey: applied migration ${m.version} (${m.name})`)
    }
    await checkColumns(q, db.dialect, prefix)
    return { dolt, applied: done }
  })
}

async function isDolt(q: Queryable): Promise<boolean> {
  try {
    await q.query('SELECT dolt_version() AS v')
    return true
  } catch {
    return false
  }
}

/**
 * Dolt commits every change, and extending child tokens would flood the service's history. So
 * Turnkey's tables are listed in `dolt_ignore` before any of them exists, and only that change is
 * committed. Ignored tables live in the working set and never enter a commit.
 */
async function ensureDoltIgnore(q: Queryable, prefix: string, opts: MigrateOptions): Promise<void> {
  const pattern = `${prefix}%`
  const rows = await q.query('SELECT ignored FROM dolt_ignore WHERE pattern = ?', [pattern])
  if (rows.length && Number(rows[0]!.ignored) === 1) return
  if (rows.length) await q.run('UPDATE dolt_ignore SET ignored = 1 WHERE pattern = ?', [pattern])
  else await q.run('INSERT INTO dolt_ignore (pattern, ignored) VALUES (?, 1)', [pattern])
  await q.query("CALL DOLT_ADD('dolt_ignore')")
  await q.query('CALL DOLT_COMMIT(?, ?, ?, ?)', ['-m', `turnkey: keep ${pattern} tables out of version control`, '--author', opts.doltAuthor])
  opts.log(`turnkey: added ${pattern} to dolt_ignore`)
}

async function checkColumns(q: Queryable, dialect: Driver['dialect'], prefix: string): Promise<void> {
  for (const [table, expected] of Object.entries(EXPECTED_COLUMNS)) {
    const name = prefix + table
    const rows =
      dialect === 'sqlite'
        ? await q.query('SELECT name AS col FROM pragma_table_info(?)', [name])
        : dialect === 'postgres'
          ? await q.query('SELECT column_name AS col FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ?', [name])
          : await q.query('SELECT column_name AS col FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?', [name])
    const have = new Set(rows.map((r) => String(r.col ?? r.COLUMN_NAME ?? r.column_name).toLowerCase()))
    const missing = expected.filter((c) => !have.has(c))
    if (missing.length) throw schemaError(`table ${name} is missing column(s) ${missing.join(', ')}: it does not match Turnkey version ${LATEST_VERSION}`)
  }
}
