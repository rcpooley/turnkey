// The core: one table of tokens (permanent tokens, browser sessions and issued credentials), the
// permission checks, and the credential contract's semantics. Framework-neutral; the adapters in
// ./adapters wrap it. Design: docs/design.md.
import type { Driver, Row } from './db/types.js'
import { badRequest, conflict, forbidden, notFound, TurnkeyError } from './errors.js'
import { migrate } from './migrate.js'
import { Actions, anyCovers, canonical, formatPermission, ISSUE, MANAGE, parsePermission, TURNKEY, type ActionRules, type Permission } from './permissions.js'
import { randomId, randomSecret, sha256Hex } from './util.js'

export type TokenKind = 'token' | 'session' | 'credential'

/** Who is calling: what `authenticate` returns. Never holds the secret. */
export interface Principal {
  id: string
  label: string
  kind: TokenKind
  /** Canonical permissions, sorted. */
  grants: string[]
  subject: Record<string, unknown> | null
  /** Set for an issued credential: the id of the token that issued it. */
  issuedBy: string | null
  expiresAt: string | null
  /** A sliding session's expiry was just extended: re-send its cookie. */
  renewed: boolean
}

/** A token as listed. Never holds the secret. */
export interface TokenInfo {
  id: string
  label: string
  kind: TokenKind
  grants: string[]
  subject: Record<string, unknown> | null
  issuedBy: string | null
  expiresAt: string | null
  slideSeconds: number | null
  createdAt: string
  createdBy: string
  rotatedAt: string | null
  rotatedBy: string | null
  revokedAt: string | null
  revokedBy: string | null
  lastUsedAt: string | null
  /** Not revoked and not expired. */
  active: boolean
}

export interface TurnkeyOptions {
  /** A driver from `@rcpooley/turnkey/db`, wrapping the service's own client. */
  db: Driver
  /** The service's actions, and which include which. */
  permissions: ActionRules
  /** Every secret starts with this, so the service's tokens are recognisable (`cx_`, `lp_`). Default `tk_`. */
  tokenPrefix?: string
  /** Turnkey's tables are `<prefix>tokens` and `<prefix>migrations`. Default `turnkey_`. */
  tablePrefix?: string
  /** Revoked and expired rows are deleted this long after they stop working. Default 30 days. */
  retentionDays?: number
  /** How often to purge them. `false` turns the timer off (call `purge()` yourself). Default hourly. */
  purgeIntervalMs?: number | false
  credentials?: {
    /** The longest an issued credential lives before it must be renewed. Default 3600. */
    maxTtlSeconds?: number
  }
  sessions?: {
    /** A browser session's lifetime; it slides forward while used. Default 30 days. */
    ttlSeconds?: number
    /** Session labels are `<labelPrefix>.<random>`. Default `session`. */
    labelPrefix?: string
  }
  /** Commit author for the one Dolt commit Turnkey makes (adding its tables to `dolt_ignore`). */
  doltAuthor?: string
  /** Startup messages. Default: none. */
  log?: (msg: string) => void
  /** The clock, for tests. */
  now?: () => Date
}

export interface CreateTokenInput {
  label: string
  grants: readonly string[]
  /** Who did it, for the record (a label, a person, `admin-cli`). */
  createdBy: string
  expiresAt?: Date | string | null
  subject?: Record<string, unknown> | null
}

export interface ImportTokenInput extends CreateTokenInput {
  /** sha256 of the secret, lowercase hex: the token keeps working with its existing secret. */
  secretHash: string
  createdAt?: Date | string
}

export interface IssueInput {
  grants: readonly string[]
  ttlSeconds?: number
  /** What the credential is for. `session` names it: `<issuer label>.<session>`. */
  subject?: Record<string, unknown> | null
}

export interface IssuedCredential {
  id: string
  label: string
  expiresAt: string
  grants: string[]
  /** Shown once. */
  secret: string
}

export interface CreateSessionInput {
  grants: readonly string[]
  createdBy: string
  /** Default: the `sessions.ttlSeconds` option. */
  ttlSeconds?: number
  /** Extend the expiry while the session is used. Default true. */
  slide?: boolean
  subject?: Record<string, unknown> | null
}

const LABEL_RE = /^[a-z0-9][a-z0-9._@-]{0,127}$/
const LAST_USED_EVERY_MS = 5 * 60_000
const DAY = 86_400
const COLUMNS =
  'id, label, kind, secret_hash, grants, subject, issued_by, expires_at, slide_seconds, created_at, created_by, rotated_at, rotated_by, revoked_at, revoked_by, last_used_at'

export async function createTurnkey(opts: TurnkeyOptions): Promise<Turnkey> {
  const tk = new Turnkey(opts)
  await tk.init()
  return tk
}

export class Turnkey {
  readonly actions: Actions
  readonly tokenPrefix: string
  readonly tablePrefix: string
  readonly maxCredentialTtl: number
  readonly sessionTtl: number
  /** Whether the database turned out to be Dolt. */
  dolt = false

  readonly tokens: TokenApi
  readonly credentials: CredentialApi
  readonly sessions: SessionApi

  private readonly db: Driver
  private readonly table: string
  private readonly clock: () => Date
  private readonly retentionMs: number
  private readonly sessionLabelPrefix: string
  private timer: ReturnType<typeof setInterval> | undefined

  constructor(private readonly opts: TurnkeyOptions) {
    this.db = opts.db
    this.actions = new Actions(opts.permissions)
    this.tokenPrefix = opts.tokenPrefix ?? 'tk_'
    if (!/^[A-Za-z0-9_-]{1,16}$/.test(this.tokenPrefix)) throw badRequest('tokenPrefix: 1-16 letters, digits, "_" or "-"')
    this.tablePrefix = opts.tablePrefix ?? 'turnkey_'
    if (!/^[a-z][a-z0-9_]{0,30}$/.test(this.tablePrefix)) throw badRequest('tablePrefix: lowercase letters, digits and "_", starting with a letter')
    this.table = `${this.tablePrefix}tokens`
    this.clock = opts.now ?? (() => new Date())
    this.retentionMs = (opts.retentionDays ?? 30) * DAY * 1000
    this.maxCredentialTtl = positiveInt(opts.credentials?.maxTtlSeconds ?? 3600, 'credentials.maxTtlSeconds')
    this.sessionTtl = positiveInt(opts.sessions?.ttlSeconds ?? 30 * DAY, 'sessions.ttlSeconds')
    this.sessionLabelPrefix = opts.sessions?.labelPrefix ?? 'session'
    if (!LABEL_RE.test(this.sessionLabelPrefix)) throw badRequest('sessions.labelPrefix: lowercase letters, digits, ".", "_", "@" or "-"')
    this.tokens = new TokenApi(this)
    this.credentials = new CredentialApi(this)
    this.sessions = new SessionApi(this)
  }

  /** Called by `createTurnkey`: migrate, check, start the purge timer. */
  async init(): Promise<void> {
    const r = await migrate(this.db, { prefix: this.tablePrefix, doltAuthor: this.opts.doltAuthor ?? 'Turnkey <turnkey@localhost>', log: this.opts.log ?? (() => {}) })
    this.dolt = r.dolt
    const every = this.opts.purgeIntervalMs ?? 3_600_000
    if (every !== false) {
      this.timer = setInterval(() => void this.purge().catch((e) => this.opts.log?.(`turnkey: purge failed: ${e}`)), every)
      this.timer.unref?.()
    }
  }

  /** Stops the purge timer. The database client is the service's to close. */
  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer)
    this.timer = undefined
  }

  // ---------------------------------------------------------------- authenticate and check

  /**
   * The principal behind a secret, or null if it is unknown, revoked or expired. Accepts the bare
   * secret or an `Authorization` header value (`Bearer …`). Reads the database every time, so a
   * revoke applies on the very next request.
   */
  async authenticate(secretOrHeader: string | null | undefined): Promise<Principal | null> {
    const secret = bareSecret(secretOrHeader)
    if (!secret || !secret.startsWith(this.tokenPrefix) || secret.length > 256) return null
    const row = await this.one(`SELECT ${COLUMNS} FROM ${this.table} WHERE secret_hash = ?`, [sha256Hex(secret)])
    if (!row || row.revoked_at) return null
    const now = this.clock()
    const nowIso = now.toISOString()
    if (row.expires_at && String(row.expires_at) <= nowIso) return null

    let expiresAt = row.expires_at ? String(row.expires_at) : null
    let renewed = false
    const slide = row.slide_seconds === null || row.slide_seconds === undefined ? null : Number(row.slide_seconds)
    const sets: string[] = []
    const params: unknown[] = []
    if (slide && expiresAt) {
      // Extend at most every slide/10 (capped at an hour), so a busy session isn't a write per request.
      const step = Math.min(3600, Math.floor(slide / 10)) * 1000
      const target = new Date(now.getTime() + slide * 1000)
      if (target.getTime() - Date.parse(expiresAt) >= step) {
        expiresAt = target.toISOString()
        renewed = true
        sets.push('expires_at = ?')
        params.push(expiresAt)
      }
    }
    if (!row.last_used_at || now.getTime() - Date.parse(String(row.last_used_at)) >= LAST_USED_EVERY_MS || sets.length) {
      sets.push('last_used_at = ?')
      params.push(nowIso)
    }
    if (sets.length) await this.db.run(`UPDATE ${this.table} SET ${sets.join(', ')} WHERE id = ? AND revoked_at IS NULL`, [...params, row.id])
    return {
      id: String(row.id),
      label: String(row.label),
      kind: row.kind as TokenKind,
      grants: splitGrants(row.grants),
      subject: parseSubject(row.subject),
      issuedBy: row.issued_by ? String(row.issued_by) : null,
      expiresAt,
      renewed,
    }
  }

  /** Whether the principal may do `action` on `resource` (a path like `sessions/abc`). */
  can(principal: Principal | null | undefined, action: string, resource: string): boolean {
    if (!principal) return false
    let wanted: Permission
    try {
      wanted = parsePermission(`${action}:${resource}`, this.actions)
    } catch {
      return false
    }
    // An issued credential never passes a Turnkey check, so a leaked one can't mint a token that outlives it.
    if (wanted.action === TURNKEY && principal.issuedBy) return false
    return anyCovers(this.parse(principal.grants), wanted, this.actions)
  }

  /** `can`, or throw a 403 `TurnkeyError` (401 if there is no principal). */
  require(principal: Principal | null | undefined, action: string, resource: string): asserts principal is Principal {
    if (!principal) throw new TurnkeyError(401, 'authentication required', 'unauthorized')
    if (!this.can(principal, action, resource)) {
      const extra = action === TURNKEY && principal.issuedBy ? ' (an issued credential never may)' : ''
      throw forbidden(`token "${principal.label}" may not ${action} ${resource}${extra}`)
    }
  }

  /** Whether `held` (a principal or a list of permissions) covers every permission in `wanted`. */
  coversAll(held: Principal | readonly string[], wanted: readonly string[]): boolean {
    const have = this.parse(Array.isArray(held) ? (held as string[]) : (held as Principal).grants)
    return wanted.every((w) => anyCovers(have, parsePermission(w, this.actions), this.actions))
  }

  /** Parse, de-duplicate and sort permissions; throws a 400 on a bad one. */
  canonical(grants: readonly string[]): string[] {
    return canonical(grants, this.actions)
  }

  // ---------------------------------------------------------------- maintenance

  /** Deletes rows revoked or expired more than `retentionDays` ago. Returns how many. */
  async purge(): Promise<number> {
    const cutoff = new Date(this.clock().getTime() - this.retentionMs).toISOString()
    return this.db.run(`DELETE FROM ${this.table} WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR (expires_at IS NOT NULL AND expires_at < ?)`, [cutoff, cutoff])
  }

  // ---------------------------------------------------------------- internals shared by the APIs

  /** @internal */
  now(): Date {
    return this.clock()
  }

  /** @internal */
  parse(grants: readonly string[]): Permission[] {
    return grants.map((g) => parsePermission(g, this.actions))
  }

  /** @internal */
  async one(sql: string, params: unknown[] = []): Promise<Row | undefined> {
    return (await this.db.query(sql, params))[0]
  }

  /** @internal */
  query(sql: string, params: unknown[] = []): Promise<Row[]> {
    return this.db.query(sql, params)
  }

  /** @internal */
  run(sql: string, params: unknown[] = []): Promise<number> {
    return this.db.run(sql, params)
  }

  /** @internal */
  get tableName(): string {
    return this.table
  }

  /** @internal */
  get sessionPrefix(): string {
    return this.sessionLabelPrefix
  }

  /** @internal */
  async row(idOrLabel: string): Promise<Row> {
    const row = await this.one(`SELECT ${COLUMNS} FROM ${this.table} WHERE id = ? OR label = ?`, [String(idOrLabel), String(idOrLabel)])
    if (!row) throw notFound(`no token "${idOrLabel}"`)
    return row
  }

  /** @internal */
  info(row: Row): TokenInfo {
    const expiresAt = row.expires_at ? String(row.expires_at) : null
    const revokedAt = row.revoked_at ? String(row.revoked_at) : null
    return {
      id: String(row.id),
      label: String(row.label),
      kind: row.kind as TokenKind,
      grants: splitGrants(row.grants),
      subject: parseSubject(row.subject),
      issuedBy: row.issued_by ? String(row.issued_by) : null,
      expiresAt,
      slideSeconds: row.slide_seconds === null || row.slide_seconds === undefined ? null : Number(row.slide_seconds),
      createdAt: String(row.created_at),
      createdBy: String(row.created_by),
      rotatedAt: nullable(row.rotated_at),
      rotatedBy: nullable(row.rotated_by),
      revokedAt,
      revokedBy: nullable(row.revoked_by),
      lastUsedAt: nullable(row.last_used_at),
      active: !revokedAt && (!expiresAt || expiresAt > this.clock().toISOString()),
    }
  }

  /**
   * Inserts a token row. A label held only by a revoked or expired row is taken over (that row is
   * deleted); a live one is a 409.
   * @internal
   */
  async insert(r: {
    label: string
    kind: TokenKind
    secretHash: string
    grants: string[]
    subject: Record<string, unknown> | null
    issuedBy: string | null
    expiresAt: string | null
    slideSeconds: number | null
    createdAt?: string
    createdBy: string
  }): Promise<TokenInfo> {
    if (!LABEL_RE.test(r.label)) throw badRequest(`bad label "${r.label}": lowercase letters, digits, ".", "_", "@" and "-", at most 128`)
    if (!r.grants.length) throw badRequest('a token needs at least one permission (e.g. read:*)')
    const by = actor(r.createdBy)
    const now = this.clock().toISOString()
    const existing = await this.one(`SELECT id, revoked_at, expires_at FROM ${this.table} WHERE label = ?`, [r.label])
    if (existing) {
      const dead = existing.revoked_at || (existing.expires_at && String(existing.expires_at) <= now)
      if (!dead) throw conflict(`a token labelled "${r.label}" already exists`)
      await this.run(`DELETE FROM ${this.table} WHERE id = ?`, [existing.id])
    }
    const id = randomId('tok_')
    try {
      await this.run(
        `INSERT INTO ${this.table} (id, label, kind, secret_hash, grants, subject, issued_by, expires_at, slide_seconds, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, r.label, r.kind, r.secretHash, r.grants.join(' '), r.subject ? JSON.stringify(r.subject) : null, r.issuedBy, r.expiresAt, r.slideSeconds, r.createdAt ?? now, by],
      )
    } catch (err) {
      if (/unique|duplicate|constraint/i.test(String((err as Error)?.message))) {
        throw conflict(`a token labelled "${r.label}" (or with that secret) already exists`)
      }
      throw err
    }
    return this.info(await this.row(id))
  }
}

// -------------------------------------------------------------------- tokens

/** Permanent (or fixed-expiry) tokens for hosts, scripts and people. The caller checks `turnkey:manage`. */
export class TokenApi {
  constructor(private readonly tk: Turnkey) {}

  /** A new token. The secret is returned once; only its hash is stored. */
  async create(input: CreateTokenInput): Promise<{ token: TokenInfo; secret: string }> {
    const secret = randomSecret(this.tk.tokenPrefix)
    const token = await this.tk.insert({
      label: String(input.label ?? ''),
      kind: 'token',
      secretHash: sha256Hex(secret),
      grants: this.tk.canonical(input.grants ?? []),
      subject: subjectOf(input.subject),
      issuedBy: null,
      expiresAt: expiryOf(input.expiresAt, this.tk.now()),
      slideSeconds: null,
      createdBy: input.createdBy,
    })
    return { token, secret }
  }

  /** Brings in another system's token by its secret's sha256, so the existing secret keeps working. */
  async import(input: ImportTokenInput): Promise<TokenInfo> {
    const hash = String(input.secretHash ?? '').toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(hash)) throw badRequest('secretHash must be the sha256 of the secret, as 64 hex characters')
    return this.tk.insert({
      label: String(input.label ?? ''),
      kind: 'token',
      secretHash: hash,
      grants: this.tk.canonical(input.grants ?? []),
      subject: subjectOf(input.subject),
      issuedBy: null,
      expiresAt: expiryOf(input.expiresAt, this.tk.now()),
      slideSeconds: null,
      createdAt: input.createdAt ? new Date(input.createdAt).toISOString() : undefined,
      createdBy: input.createdBy,
    })
  }

  /** Every token, newest first. Revoked and expired ones only with `all`. */
  async list(opts: { kind?: TokenKind; all?: boolean } = {}): Promise<TokenInfo[]> {
    const where: string[] = []
    const params: unknown[] = []
    if (opts.kind) where.push('kind = ?'), params.push(opts.kind)
    if (!opts.all) {
      where.push('revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)')
      params.push(this.tk.now().toISOString())
    }
    const rows = await this.tk.query(`SELECT ${COLUMNS} FROM ${this.tk.tableName}${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at DESC, label`, params)
    return rows.map((r) => this.tk.info(r))
  }

  /** One token by id or label (404 if none). */
  async get(idOrLabel: string): Promise<TokenInfo> {
    return this.tk.info(await this.tk.row(idOrLabel))
  }

  /** Adds permissions. */
  async grant(idOrLabel: string, grants: readonly string[]): Promise<TokenInfo> {
    const row = await this.live(idOrLabel)
    const next = this.tk.canonical([...splitGrants(row.grants), ...grants])
    await this.tk.run(`UPDATE ${this.tk.tableName} SET grants = ? WHERE id = ?`, [next.join(' '), row.id])
    return this.get(String(row.id))
  }

  /** Removes permissions (each must be held exactly as written, in canonical form). */
  async ungrant(idOrLabel: string, grants: readonly string[]): Promise<TokenInfo> {
    const row = await this.live(idOrLabel)
    const current = splitGrants(row.grants)
    const drop = new Set(this.tk.canonical(grants))
    for (const d of drop) if (!current.includes(d)) throw badRequest(`token "${row.label}" has no permission ${d}`)
    const next = current.filter((g) => !drop.has(g))
    if (!next.length) throw badRequest(`token "${row.label}" would have no permissions left; revoke it instead`)
    await this.tk.run(`UPDATE ${this.tk.tableName} SET grants = ? WHERE id = ?`, [next.join(' '), row.id])
    return this.get(String(row.id))
  }

  /**
   * Stops a token working at once. Credentials it issued are revoked with it. Idempotent on an
   * already-revoked token.
   */
  async revoke(idOrLabel: string, by: string): Promise<TokenInfo> {
    const row = await this.tk.row(idOrLabel)
    const now = this.tk.now().toISOString()
    const who = actor(by)
    await this.tk.run(`UPDATE ${this.tk.tableName} SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`, [now, who, row.id])
    await this.tk.run(`UPDATE ${this.tk.tableName} SET revoked_at = ?, revoked_by = ? WHERE issued_by = ? AND revoked_at IS NULL`, [now, who, row.id])
    return this.get(String(row.id))
  }

  /** A new secret for the same token (label, permissions, expiry). The old secret stops working. */
  async rotate(idOrLabel: string, by: string): Promise<{ token: TokenInfo; secret: string }> {
    const row = await this.live(idOrLabel)
    if (row.issued_by) throw badRequest('an issued credential is never rotated: renewing keeps its secret, by contract')
    const secret = randomSecret(this.tk.tokenPrefix)
    await this.tk.run(`UPDATE ${this.tk.tableName} SET secret_hash = ?, rotated_at = ?, rotated_by = ? WHERE id = ?`, [
      sha256Hex(secret),
      this.tk.now().toISOString(),
      actor(by),
      row.id,
    ])
    return { token: await this.get(String(row.id)), secret }
  }

  private async live(idOrLabel: string): Promise<Row> {
    const row = await this.tk.row(idOrLabel)
    if (!this.tk.info(row).active) throw notFound(`token "${row.label}" is revoked or expired`)
    return row
  }
}

// -------------------------------------------------------------------- credentials

/**
 * Short-lived credentials an orchestrator issues per session: the semantics of the
 * credential contract. Every call takes the issuing principal and checks it.
 */
export class CredentialApi {
  constructor(private readonly tk: Turnkey) {}

  /** Throws unless `issuer` may issue credentials at all. */
  assertIssuer(issuer: Principal | null | undefined): asserts issuer is Principal {
    this.tk.require(issuer, 'turnkey', 'issue')
  }

  /** Checks requested permissions: canonical form, 400 if malformed, 403 beyond what the issuer holds. */
  check(issuer: Principal, grants: readonly string[]): string[] {
    this.assertIssuer(issuer)
    if (!Array.isArray(grants) || !grants.length) throw badRequest('ask for at least one permission, e.g. {"grants": ["read:*"]}')
    const wanted = this.tk.canonical(grants.map(String))
    const reserved = wanted.filter((g) => g.startsWith(`${TURNKEY}:`))
    if (reserved.length) throw forbidden(`an issued credential may not hold ${reserved.join(', ')}`)
    const held = this.tk.parse(issuer.grants)
    const over = wanted.filter((g) => !anyCovers(held, parsePermission(g, this.tk.actions), this.tk.actions))
    if (over.length) throw forbidden(`"${issuer.label}" may not issue ${over.join(', ')}: it does not hold them`)
    return wanted
  }

  /** Issues a credential labelled `<issuer label>.<subject.session>`, for at most `maxTtlSeconds`. */
  async issue(issuer: Principal, input: IssueInput): Promise<IssuedCredential> {
    const grants = this.check(issuer, input.grants)
    const subject = subjectOf(input.subject)
    const ttl = this.ttl(input.ttlSeconds)
    const base = credentialLabel(issuer.label, subject?.session)
    const secret = randomSecret(this.tk.tokenPrefix)
    const expiresAt = new Date(this.tk.now().getTime() + ttl * 1000).toISOString()
    // A retried issue for the same session gets its own label rather than failing.
    for (let attempt = 0; ; attempt++) {
      const label = attempt === 0 ? base : `${base.slice(0, 119)}.${Math.random().toString(36).slice(2, 8)}`
      try {
        const t = await this.tk.insert({ label, kind: 'credential', secretHash: sha256Hex(secret), grants, subject, issuedBy: issuer.id, expiresAt, slideSeconds: null, createdBy: issuer.label })
        return { id: t.id, label: t.label, expiresAt, grants, secret }
      } catch (err) {
        if (!(err instanceof TurnkeyError && err.code === 'conflict') || attempt >= 3) throw err
      }
    }
  }

  /**
   * Moves only the expiry; the secret never changes. 404 once revoked or expired. Refused if the
   * issuer no longer holds the credential's permissions.
   */
  async renew(issuer: Principal, id: string, ttlSeconds?: number): Promise<{ id: string; expiresAt: string }> {
    this.assertIssuer(issuer)
    const row = await this.mine(issuer, id)
    const info = this.tk.info(row)
    if (!info.active) throw gone(id)
    if (!this.tk.coversAll(issuer, info.grants)) {
      throw forbidden(`"${issuer.label}" may no longer issue ${info.grants.filter((g) => !this.tk.coversAll(issuer, [g])).join(', ')}`)
    }
    const now = this.tk.now()
    const expiresAt = new Date(now.getTime() + this.ttl(ttlSeconds) * 1000).toISOString()
    const n = await this.tk.run(`UPDATE ${this.tk.tableName} SET expires_at = ? WHERE id = ? AND issued_by = ? AND revoked_at IS NULL AND expires_at > ?`, [
      expiresAt,
      row.id,
      issuer.id,
      now.toISOString(),
    ])
    if (!n) throw gone(id)
    return { id: String(row.id), expiresAt }
  }

  /** Idempotent: `revoked` is false if it was already revoked, expired or unknown. */
  async revoke(issuer: Principal, id: string): Promise<{ id: string; revoked: boolean }> {
    this.assertIssuer(issuer)
    const n = await this.tk.run(`UPDATE ${this.tk.tableName} SET revoked_at = ?, revoked_by = ? WHERE id = ? AND issued_by = ? AND revoked_at IS NULL AND expires_at > ?`, [
      this.tk.now().toISOString(),
      issuer.label,
      String(id ?? ''),
      issuer.id,
      this.tk.now().toISOString(),
    ])
    return { id: String(id ?? ''), revoked: n > 0 }
  }

  /** Active credentials: all of them, or only those `issuer` issued. */
  async list(issuer?: Principal): Promise<TokenInfo[]> {
    const all = await this.tk.tokens.list({ kind: 'credential' })
    return issuer ? all.filter((t) => t.issuedBy === issuer.id) : all
  }

  private async mine(issuer: Principal, id: string): Promise<Row> {
    const row = await this.tk.one(`SELECT ${COLUMNS} FROM ${this.tk.tableName} WHERE id = ? AND issued_by = ?`, [String(id ?? ''), issuer.id])
    if (!row) throw gone(id)
    return row
  }

  private ttl(v: unknown): number {
    if (v === undefined || v === null) return this.tk.maxCredentialTtl
    const n = Number(v)
    if (!Number.isInteger(n) || n < 1) throw badRequest('ttlSeconds must be a positive integer')
    return Math.min(n, this.tk.maxCredentialTtl)
  }
}

// -------------------------------------------------------------------- sessions

/**
 * Browser sessions for an app that does its own login (a master password, or Logto). The cookie's
 * value is a Turnkey secret; the session slides forward while used. Turnkey never checks a password.
 */
export class SessionApi {
  constructor(private readonly tk: Turnkey) {}

  /** Call after your login succeeds. Put `secret` in the cookie (`sessionCookie`). */
  async create(input: CreateSessionInput): Promise<{ token: TokenInfo; secret: string }> {
    const ttl = input.ttlSeconds === undefined ? this.tk.sessionTtl : positiveInt(input.ttlSeconds, 'ttlSeconds')
    const secret = randomSecret(this.tk.tokenPrefix)
    const label = `${this.tk.sessionPrefix}.${randomId('').slice(0, 12)}`
    const token = await this.tk.insert({
      label,
      kind: 'session',
      secretHash: sha256Hex(secret),
      grants: this.tk.canonical(input.grants ?? []),
      subject: subjectOf(input.subject),
      issuedBy: null,
      expiresAt: new Date(this.tk.now().getTime() + ttl * 1000).toISOString(),
      slideSeconds: input.slide === false ? null : ttl,
      createdBy: input.createdBy,
    })
    return { token, secret }
  }

  /** Logs one session out (by principal, id or label). */
  async revoke(session: Principal | string, by: string): Promise<void> {
    const id = typeof session === 'string' ? session : session.id
    const row = await this.tk.row(id)
    if (row.kind !== 'session') throw badRequest(`"${row.label}" is not a session`)
    await this.tk.tokens.revoke(String(row.id), by)
  }

  /** Logs every browser out, e.g. after the password changes. Returns how many. */
  async revokeAll(by: string): Promise<number> {
    const now = this.tk.now().toISOString()
    return this.tk.run(
      `UPDATE ${this.tk.tableName} SET revoked_at = ?, revoked_by = ? WHERE kind = 'session' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
      [now, actor(by), now],
    )
  }

  /** Active sessions. */
  list(): Promise<TokenInfo[]> {
    return this.tk.tokens.list({ kind: 'session' })
  }
}

// -------------------------------------------------------------------- helpers

const gone = (id: string) => notFound(`no credential ${id}: it was revoked or has expired`)

function bareSecret(v: string | null | undefined): string | null {
  if (typeof v !== 'string') return null
  const s = v.trim()
  const m = /^Bearer\s+(.+)$/i.exec(s)
  return (m ? m[1]! : s).trim() || null
}

function splitGrants(v: unknown): string[] {
  return String(v ?? '')
    .split(/\s+/)
    .filter(Boolean)
}

function parseSubject(v: unknown): Record<string, unknown> | null {
  if (v === null || v === undefined || v === '') return null
  try {
    const o = JSON.parse(String(v))
    return o && typeof o === 'object' && !Array.isArray(o) ? o : null
  } catch {
    return null
  }
}

function subjectOf(v: unknown): Record<string, unknown> | null {
  if (v === null || v === undefined) return null
  if (typeof v !== 'object' || Array.isArray(v)) throw badRequest('subject must be a JSON object')
  if (JSON.stringify(v).length > 2048) throw badRequest('subject is too large (2 KB at most)')
  return v as Record<string, unknown>
}

function expiryOf(v: Date | string | null | undefined, now: Date): string | null {
  if (v === null || v === undefined || v === '') return null
  const d = v instanceof Date ? v : new Date(v)
  if (Number.isNaN(d.getTime())) throw badRequest(`bad expiry "${v}": use an ISO 8601 time`)
  if (d <= now) throw badRequest('the expiry is in the past')
  return d.toISOString()
}

function actor(by: string): string {
  const s = String(by ?? '').trim()
  if (!s) throw badRequest('say who is doing this (createdBy / by)')
  return s.slice(0, 128)
}

function positiveInt(n: number, what: string): number {
  if (!Number.isInteger(n) || n < 1) throw badRequest(`${what} must be a positive whole number of seconds`)
  return n
}

/** `<issuer>.<session>`, squeezed into the label alphabet. */
function credentialLabel(issuer: string, session: unknown): string {
  const slug = String(session ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9._@-]+/g, '-')
    .replace(/^[^a-z0-9]+/, '')
  const label = `${issuer}.${slug || randomId('').slice(0, 8)}`.slice(0, 120).replace(/[^a-z0-9]+$/, '')
  if (!LABEL_RE.test(label)) throw badRequest(`cannot make a label from "${issuer}" and session "${String(session)}"`)
  return label
}

function nullable(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v)
}

export { MANAGE, ISSUE, formatPermission }
