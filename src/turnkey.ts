// The core: one table of tokens, the permission checks, and the token operations with their rules.
// A token may have a parent (the token that created it: a child) or a sliding expiry (a browser
// session); otherwise every token is the same. Framework-neutral; the adapters in ./adapters and
// the HTTP routes in ./http.ts wrap it. Design: docs/design.md. Rules: docs/permissions.md.
import type { Driver, Row } from './db/types.js'
import { badRequest, conflict, forbidden, notFound, TurnkeyError } from './errors.js'
import { migrate } from './migrate.js'
import { Actions, anyCovers, canonical, formatPermission, ISSUE, MANAGE, parsePermission, TURNKEY, type ActionRules, type Permission } from './permissions.js'
import { randomId, randomSecret, sha256Hex } from './util.js'

/** Who is calling: what `authenticate` returns. Never holds the secret. */
export interface Principal {
  id: string
  label: string
  /**
   * What the token may do now, canonical and sorted. A child's are its own grants that its
   * parent still covers.
   */
  grants: string[]
  subject: Record<string, unknown> | null
  /** A child's parent: the id of the token that created it. */
  parent: string | null
  expiresAt: string | null
  /** Set for a browser session: its expiry slides forward this far while it is used. */
  slideSeconds: number | null
  /** A sliding session's expiry was just extended: re-send its cookie. */
  renewed: boolean
  /** Who to record as doing things (default the label), e.g. `session:<id>@<label>`. Not checked. */
  actor?: string
}

/** A token as listed. Never holds the secret. */
export interface TokenInfo {
  id: string
  label: string
  grants: string[]
  subject: Record<string, unknown> | null
  parent: string | null
  expiresAt: string | null
  slideSeconds: number | null
  createdAt: string
  createdBy: string
  rotatedAt: string | null
  rotatedBy: string | null
  revokedAt: string | null
  revokedBy: string | null
  lastUsedAt: string | null
  /** Not revoked, not expired, and (for a child) its parent is neither. */
  active: boolean
}

/**
 * Who is asking for an operation. A principal is held to the rules (docs/permissions.md). A
 * string is the service's own code, or its break-glass CLI: trusted, and recorded as is.
 */
export type Actor = Principal | string

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
  children?: {
    /** The longest a child lives before its parent must extend it. Default 3600. */
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
  /** An independent token's label. A child's is made from its parent's and `name`. */
  label?: string
  /** A child's name: its label is `<parent label>.<name>`. Default random. */
  name?: string
  grants: readonly string[]
  /** When it stops working. Give this or `ttlSeconds`, or neither: a token then never expires. A child always expires. */
  expiresAt?: Date | string | null
  ttlSeconds?: number | null
  /** What it is for, kept with it (a child's `{session, agent, host}`). */
  subject?: Record<string, unknown> | null
  /** Make it a child of the calling token (needs `turnkey:issue`). */
  child?: boolean
}

/** What `check` and a dry run say a create would make. */
export interface CreatePlan {
  label: string
  grants: string[]
  parent: string | null
  expiresAt: string | null
}

export interface ExtendInput {
  /** From now. A child's default, and cap, is `children.maxTtlSeconds`. */
  ttlSeconds?: number | null
  expiresAt?: Date | string | null
}

export interface ImportTokenInput {
  label: string
  grants: readonly string[]
  /** sha256 of the secret, lowercase hex: the token keeps working with its existing secret. */
  secretHash: string
  expiresAt?: Date | string | null
  subject?: Record<string, unknown> | null
  createdAt?: Date | string
  createdBy?: string
}

/** A token as `export` saves it for a backup: enough for `import` to bring it back. */
export interface ExportedToken {
  label: string
  secretHash: string
  grants: string[]
  subject: Record<string, unknown> | null
  expiresAt: string | null
  createdAt: string
  createdBy: string
}

export interface CreateSessionInput {
  grants: readonly string[]
  /** Default: the `sessions.ttlSeconds` option. */
  ttlSeconds?: number
  /** Extend the expiry while the session is used. Default true. */
  slide?: boolean
  subject?: Record<string, unknown> | null
}

const LABEL_RE = /^[a-z0-9][a-z0-9._@-]{0,127}$/
const LAST_USED_EVERY_MS = 5 * 60_000
const MAX_TTL = 100 * 365 * 86_400
const DAY = 86_400
const COLUMNS = [
  'id', 'label', 'secret_hash', 'grants', 'subject', 'parent', 'expires_at', 'slide_seconds',
  'created_at', 'created_by', 'rotated_at', 'rotated_by', 'revoked_at', 'revoked_by', 'last_used_at',
]
const ISSUE_PERMISSION: Permission = { action: TURNKEY, resource: ['issue'] }

export async function createTurnkey(opts: TurnkeyOptions): Promise<Turnkey> {
  const tk = new Turnkey(opts)
  await tk.init()
  return tk
}

export class Turnkey {
  readonly actions: Actions
  readonly tokenPrefix: string
  readonly tablePrefix: string
  readonly maxChildTtl: number
  readonly sessionTtl: number
  /** Whether the database turned out to be Dolt. */
  dolt = false

  readonly tokens: TokenApi
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
    this.maxChildTtl = positiveInt(opts.children?.maxTtlSeconds ?? 3600, 'children.maxTtlSeconds')
    this.sessionTtl = positiveInt(opts.sessions?.ttlSeconds ?? 30 * DAY, 'sessions.ttlSeconds')
    this.sessionLabelPrefix = opts.sessions?.labelPrefix ?? 'session'
    if (!LABEL_RE.test(this.sessionLabelPrefix)) throw badRequest('sessions.labelPrefix: lowercase letters, digits, ".", "_", "@" or "-"')
    this.tokens = new TokenApi(this)
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
   * The principal behind a secret, or null if it is unknown, revoked or expired, or a child whose
   * parent is, or whose parent no longer covers any of its grants or no longer holds
   * `turnkey:issue`. Accepts the bare secret or an `Authorization` header value (`Bearer …`).
   * Reads the database every time, so a revoke applies on the very next request.
   */
  async authenticate(secretOrHeader: string | null | undefined): Promise<Principal | null> {
    const secret = bareSecret(secretOrHeader)
    if (!secret || !secret.startsWith(this.tokenPrefix) || secret.length > 256) return null
    const row = await this.one(`${this.select()} WHERE t.secret_hash = ?`, [sha256Hex(secret)])
    if (!row || !this.alive(row)) return null
    const grants = row.parent ? this.childGrants(row) : splitGrants(row.grants)

    const now = this.clock()
    const nowIso = now.toISOString()
    let expiresAt = nullable(row.expires_at)
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
      grants,
      subject: parseSubject(row.subject),
      parent: nullable(row.parent),
      expiresAt,
      slideSeconds: slide,
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
    // A child never passes a Turnkey check, so a leaked one can't create a token that outlives it.
    if (wanted.action === TURNKEY && principal.parent) return false
    return anyCovers(this.parse(principal.grants), wanted, this.actions)
  }

  /** `can`, or throw a 403 `TurnkeyError` (401 if there is no principal). */
  require(principal: Principal | null | undefined, action: string, resource: string): asserts principal is Principal {
    if (!principal) throw new TurnkeyError(401, 'authentication required', 'unauthorized')
    if (!this.can(principal, action, resource)) {
      const extra = action === TURNKEY && principal.parent ? ' (a child token never may)' : ''
      throw forbidden(`token "${principal.label}" may not ${action} ${resource}${extra}`)
    }
  }

  /** Whether `held` (a principal or a list of permissions) covers every permission in `wanted`. */
  coversAll(held: Principal | readonly string[], wanted: readonly string[]): boolean {
    const child = !Array.isArray(held) && !!(held as Principal).parent
    const have = this.parse(Array.isArray(held) ? (held as string[]) : (held as Principal).grants)
    return wanted.every((w) => {
      const p = parsePermission(w, this.actions)
      return !(child && p.action === TURNKEY) && anyCovers(have, p, this.actions)
    })
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

  /** Every column of `t`, plus what a child's checks need from its parent `p`. @internal */
  select(): string {
    return `SELECT ${COLUMNS.map((c) => `t.${c}`).join(', ')}, p.id AS p_id, p.grants AS p_grants, p.revoked_at AS p_revoked_at, p.expires_at AS p_expires_at FROM ${this.table} t LEFT JOIN ${this.table} p ON p.id = t.parent`
  }

  /** @internal */
  async find(idOrLabel: string): Promise<Row | undefined> {
    return this.one(`${this.select()} WHERE t.id = ? OR t.label = ?`, [String(idOrLabel ?? ''), String(idOrLabel ?? '')])
  }

  /**
   * Not revoked, not expired, and for a child: its parent is neither, still holds `turnkey:issue`,
   * and still covers at least one of its grants. Exactly when `authenticate` accepts it. @internal
   */
  alive(row: Row): boolean {
    const now = this.clock().toISOString()
    const live = (revoked: unknown, expires: unknown) => !revoked && (!expires || String(expires) > now)
    if (!live(row.revoked_at, row.expires_at)) return false
    if (!row.parent) return true
    if (!row.p_id || !live(row.p_revoked_at, row.p_expires_at)) return false
    return !!this.childGrants(row).length
  }

  /** A child's grants that its parent still covers; none if the parent no longer holds `turnkey:issue`. @internal */
  childGrants(row: Row): string[] {
    const held = this.parse(splitGrants(row.p_grants))
    if (!anyCovers(held, ISSUE_PERMISSION, this.actions)) return []
    return splitGrants(row.grants).filter((g) => anyCovers(held, parsePermission(g, this.actions), this.actions))
  }

  /** @internal */
  info(row: Row): TokenInfo {
    return {
      id: String(row.id),
      label: String(row.label),
      grants: splitGrants(row.grants),
      subject: parseSubject(row.subject),
      parent: nullable(row.parent),
      expiresAt: nullable(row.expires_at),
      slideSeconds: row.slide_seconds === null || row.slide_seconds === undefined ? null : Number(row.slide_seconds),
      createdAt: String(row.created_at),
      createdBy: String(row.created_by),
      rotatedAt: nullable(row.rotated_at),
      rotatedBy: nullable(row.rotated_by),
      revokedAt: nullable(row.revoked_at),
      revokedBy: nullable(row.revoked_by),
      lastUsedAt: nullable(row.last_used_at),
      active: this.alive(row),
    }
  }

  /**
   * Inserts a token row. A label held only by a revoked or expired row is taken over (that row is
   * deleted); a live one is a 409.
   * @internal
   */
  async insert(r: {
    label: string
    secretHash: string
    grants: string[]
    subject: Record<string, unknown> | null
    parent: string | null
    expiresAt: string | null
    slideSeconds: number | null
    createdAt?: string
    createdBy: string
  }): Promise<TokenInfo> {
    // A child's label is chosen by its parent, so it may only reuse a dead child's label of the same parent.
    if (!LABEL_RE.test(r.label)) throw badRequest(`bad label "${r.label}": lowercase letters, digits, ".", "_", "@" and "-", at most 128`)
    if (!r.grants.length) throw badRequest('a token needs at least one permission (e.g. read:*)')
    const now = this.clock().toISOString()
    const existing = await this.one(`SELECT id, parent, revoked_at, expires_at FROM ${this.table} WHERE label = ?`, [r.label])
    if (existing) {
      const dead = existing.revoked_at || (existing.expires_at && String(existing.expires_at) <= now)
      if (!dead || (r.parent && existing.parent !== r.parent)) throw conflict(`a token labelled "${r.label}" already exists`)
      await this.run(`DELETE FROM ${this.table} WHERE id = ?`, [existing.id])
    }
    const id = randomId('tok_')
    try {
      await this.run(
        `INSERT INTO ${this.table} (id, label, secret_hash, grants, subject, parent, expires_at, slide_seconds, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [id, r.label, r.secretHash, r.grants.join(' '), r.subject ? JSON.stringify(r.subject) : null, r.parent, r.expiresAt, r.slideSeconds, r.createdAt ?? now, r.createdBy],
      )
    } catch (err) {
      if (/unique|duplicate|constraint/i.test(String((err as Error)?.message))) {
        throw conflict(`a token labelled "${r.label}" (or with that secret) already exists`)
      }
      throw err
    }
    return this.info((await this.find(id))!)
  }
}

// -------------------------------------------------------------------- tokens

/**
 * Every operation on tokens. Each takes the actor asking, and holds a principal to the rules:
 * - `turnkey:manage` may do anything to any token;
 * - `turnkey:issue` may create children, and extend or revoke its own;
 * - any token may see and revoke itself;
 * - whoever creates or grants can give only what they hold.
 * Anything an actor may not see is a 404.
 */
export class TokenApi {
  constructor(private readonly tk: Turnkey) {}

  /** What `create` would make, after every check, without making it (a dry run). */
  async check(input: CreateTokenInput, actor: Actor): Promise<CreatePlan> {
    const tk: Turnkey = this.tk
    if (!input || typeof input !== 'object') throw badRequest('expected {label, grants, ...}')
    if (!Array.isArray(input.grants) || !input.grants.length) throw badRequest('give at least one permission, e.g. {"grants": ["read:*"]}')
    const grants = tk.canonical(input.grants.map(String))
    if (input.expiresAt !== undefined && input.expiresAt !== null && input.ttlSeconds !== undefined && input.ttlSeconds !== null) {
      throw badRequest('give expiresAt or ttlSeconds, not both')
    }
    const now = tk.now()

    if (input.child) {
      if (typeof actor === 'string') throw badRequest('a child is created by its parent: call this with the parent principal')
      tk.require(actor, 'turnkey', 'issue')
      if (input.label !== undefined && input.label !== null) throw badRequest("a child's label is made from its parent's and its name: give name, not label")
      const reserved = grants.filter((g) => g.startsWith(`${TURNKEY}:`))
      if (reserved.length) throw forbidden(`a child token may not hold ${reserved.join(', ')}`)
      this.within(actor, grants)
      const max = new Date(now.getTime() + tk.maxChildTtl * 1000)
      let expires = input.expiresAt ? new Date(expiryOf(input.expiresAt, now)!) : new Date(now.getTime() + ttlOf(input.ttlSeconds, tk.maxChildTtl) * 1000)
      if (expires > max) expires = max
      return { label: childLabel(actor.label, input.name), grants, parent: actor.id, expiresAt: expires.toISOString() }
    }

    if (input.name !== undefined && input.name !== null) throw badRequest('name is for a child; an independent token takes a label')
    if (typeof actor !== 'string') {
      tk.require(actor, 'turnkey', 'manage')
      this.within(actor, grants)
    }
    const label = String(input.label ?? '')
    if (!LABEL_RE.test(label)) throw badRequest(`bad label "${label}": lowercase letters, digits, ".", "_", "@" and "-", at most 128`)
    if (label.startsWith(`${tk.sessionPrefix}.`)) throw badRequest(`labels starting "${tk.sessionPrefix}." are for browser sessions`)
    const taken = await tk.one(`SELECT revoked_at, expires_at FROM ${tk.tableName} WHERE label = ?`, [label])
    if (taken && !taken.revoked_at && (!taken.expires_at || String(taken.expires_at) > now.toISOString())) throw conflict(`a token labelled "${label}" already exists`)
    const expiresAt =
      input.ttlSeconds !== undefined && input.ttlSeconds !== null
        ? new Date(now.getTime() + ttlOf(input.ttlSeconds, 0) * 1000).toISOString()
        : expiryOf(input.expiresAt, now)
    return { label, grants, parent: null, expiresAt }
  }

  /** A new token, or a child of the calling token. The secret is returned once; only its hash is stored. */
  async create(input: CreateTokenInput, actor: Actor): Promise<{ token: TokenInfo; secret: string }> {
    const plan = await this.check(input, actor)
    const subject = subjectOf(input.subject)
    const secret = randomSecret(this.tk.tokenPrefix)
    // A child retried for the same name gets its own label rather than failing.
    for (let attempt = 0; ; attempt++) {
      const label = attempt === 0 || !plan.parent ? plan.label : `${plan.label.slice(0, 119)}.${Math.random().toString(36).slice(2, 8)}`
      try {
        const token = await this.tk.insert({ ...plan, label, secretHash: sha256Hex(secret), subject, slideSeconds: null, createdBy: actorName(actor) })
        return { token, secret }
      } catch (err) {
        if (!plan.parent || !(err instanceof TurnkeyError && err.code === 'conflict') || attempt >= 3) throw err
      }
    }
  }

  /** The tokens `actor` may see, newest first: all of them with `turnkey:manage`, else itself and its children. */
  async list(actor: Actor, opts: { all?: boolean; parent?: string } = {}): Promise<TokenInfo[]> {
    const where: string[] = []
    const params: unknown[] = []
    if (!this.manages(actor)) {
      where.push('(t.id = ? OR t.parent = ?)')
      params.push((actor as Principal).id, (actor as Principal).id)
    }
    if (opts.parent) {
      const p = await this.tk.find(opts.parent)
      if (!p || !this.sees(p, actor)) throw notFound(`no token "${opts.parent}"`)
      where.push('t.parent = ?')
      params.push(p.id)
    }
    const rows = await this.tk.query(`${this.tk.select()}${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY t.created_at DESC, t.label`, params)
    const out = rows.map((r) => this.tk.info(r))
    return opts.all ? out : out.filter((t) => t.active)
  }

  /** One token by id or label (404 if there is none the actor may see). */
  async get(idOrLabel: string, actor: Actor): Promise<TokenInfo> {
    return this.tk.info(await this.visible(idOrLabel, actor))
  }

  /**
   * Moves a live token's expiry; the secret never changes. A child's parent may extend it, by at
   * most `children.maxTtlSeconds` from now; `turnkey:manage` may extend any token.
   */
  async extend(idOrLabel: string, input: ExtendInput, actor: Actor): Promise<TokenInfo> {
    const row = await this.visible(idOrLabel, actor)
    const isParent = typeof actor !== 'string' && row.parent === actor.id
    if (!this.manages(actor)) {
      if (!isParent) throw forbidden(`token "${(actor as Principal).label}" may not extend "${row.label}": only its parent or turnkey:manage may`)
      this.tk.require(actor as Principal, 'turnkey', 'issue')
    } else if (typeof actor !== 'string' && !isParent) {
      // Keeping a token alive is giving its access for longer: only what you hold.
      this.within(actor, splitGrants(row.grants), `extend "${row.label}"`)
    }
    if (!this.tk.alive(row)) throw notFound(`token "${row.label}" is revoked or expired`)
    const ttl = input?.ttlSeconds
    const at = input?.expiresAt
    if (at !== undefined && at !== null && ttl !== undefined && ttl !== null) throw badRequest('give expiresAt or ttlSeconds, not both')
    const now = this.tk.now()
    let expires: Date
    if (at !== undefined && at !== null) expires = new Date(expiryOf(at, now)!)
    else if (row.parent) expires = new Date(now.getTime() + ttlOf(ttl, this.tk.maxChildTtl) * 1000)
    else if (ttl !== undefined && ttl !== null) expires = new Date(now.getTime() + ttlOf(ttl, 0) * 1000)
    else throw badRequest('give ttlSeconds or expiresAt')
    if (row.parent) {
      const max = new Date(now.getTime() + this.tk.maxChildTtl * 1000)
      if (expires > max) expires = max
    }
    const n = await this.tk.run(`UPDATE ${this.tk.tableName} SET expires_at = ? WHERE id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, [
      expires.toISOString(),
      row.id,
      now.toISOString(),
    ])
    if (!n) throw notFound(`token "${row.label}" is revoked or expired`)
    return this.get(String(row.id), actor)
  }

  /**
   * Stops a token working at once, and with it every child it created. `turnkey:manage`, its
   * parent, or the token itself may. Idempotent: the first revoke stays on record.
   */
  async revoke(idOrLabel: string, actor: Actor): Promise<TokenInfo> {
    const row = await this.visible(idOrLabel, actor)
    // Seeing a token means being it, its parent or a manager: each may revoke it.
    await this.tk.run(`UPDATE ${this.tk.tableName} SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`, [
      this.tk.now().toISOString(),
      actorName(actor),
      row.id,
    ])
    return this.get(String(row.id), actor)
  }

  /** Adds permissions (needs `turnkey:manage`, and the actor must hold them). A child's are fixed. */
  async grant(idOrLabel: string, grants: readonly string[], actor: Actor): Promise<TokenInfo> {
    const row = await this.changeable(idOrLabel, actor)
    const add = this.tk.canonical(grantList(grants))
    if (typeof actor !== 'string') this.within(actor, add)
    const next = this.tk.canonical([...splitGrants(row.grants), ...add])
    await this.tk.run(`UPDATE ${this.tk.tableName} SET grants = ? WHERE id = ?`, [next.join(' '), row.id])
    return this.get(String(row.id), actor)
  }

  /** Removes permissions (each must be held exactly as written, in canonical form). Needs `turnkey:manage`. */
  async ungrant(idOrLabel: string, grants: readonly string[], actor: Actor): Promise<TokenInfo> {
    const row = await this.changeable(idOrLabel, actor)
    const current = splitGrants(row.grants)
    const drop = new Set(this.tk.canonical(grantList(grants)))
    for (const d of drop) if (!current.includes(d)) throw badRequest(`token "${row.label}" has no permission ${d}`)
    const next = current.filter((g) => !drop.has(g))
    if (!next.length) throw badRequest(`token "${row.label}" would have no permissions left; revoke it instead`)
    await this.tk.run(`UPDATE ${this.tk.tableName} SET grants = ? WHERE id = ?`, [next.join(' '), row.id])
    return this.get(String(row.id), actor)
  }

  /**
   * A new secret for the same token (label, permissions, expiry); the old one stops working. Needs
   * `turnkey:manage`, and the actor must hold everything the token holds: it gets the secret.
   */
  async rotate(idOrLabel: string, actor: Actor): Promise<{ token: TokenInfo; secret: string }> {
    const row = await this.changeable(idOrLabel, actor)
    if (typeof actor !== 'string') this.within(actor, splitGrants(row.grants), `rotate "${row.label}"`)
    const secret = randomSecret(this.tk.tokenPrefix)
    await this.tk.run(`UPDATE ${this.tk.tableName} SET secret_hash = ?, rotated_at = ?, rotated_by = ? WHERE id = ?`, [
      sha256Hex(secret),
      this.tk.now().toISOString(),
      actorName(actor),
      row.id,
    ])
    return { token: await this.get(String(row.id), actor), secret }
  }

  /**
   * The live independent tokens (no parent, no sliding expiry) with their hashes, for a service's
   * backup. Turnkey's tables are often left out of the service's own dumps (always on Dolt).
   */
  async export(): Promise<ExportedToken[]> {
    const rows = await this.tk.query(`${this.tk.select()} WHERE t.parent IS NULL AND t.slide_seconds IS NULL ORDER BY t.label`)
    return rows
      .filter((r) => this.tk.alive(r))
      .map((r) => {
        const t = this.tk.info(r)
        return { label: t.label, secretHash: String(r.secret_hash), grants: t.grants, subject: t.subject, expiresAt: t.expiresAt, createdAt: t.createdAt, createdBy: t.createdBy }
      })
  }

  /** Brings back an exported token, or another system's, by its secret's sha256: the existing secret keeps working. */
  async import(input: ImportTokenInput, by: string): Promise<TokenInfo> {
    const hash = String(input.secretHash ?? '').toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(hash)) throw badRequest('secretHash must be the sha256 of the secret, as 64 hex characters')
    return this.tk.insert({
      label: String(input.label ?? ''),
      secretHash: hash,
      grants: this.tk.canonical(grantList(input.grants)),
      subject: subjectOf(input.subject),
      parent: null,
      expiresAt: expiryOf(input.expiresAt, this.tk.now()),
      slideSeconds: null,
      createdAt: input.createdAt ? new Date(input.createdAt).toISOString() : undefined,
      createdBy: actorName(input.createdBy ?? by),
    })
  }

  // ---------------------------------------------------------------- rules

  private manages(actor: Actor): boolean {
    return typeof actor === 'string' || this.tk.can(actor, 'turnkey', 'manage')
  }

  private sees(row: Row, actor: Actor): boolean {
    if (this.manages(actor)) return true
    const id = (actor as Principal).id
    return row.id === id || row.parent === id
  }

  private async visible(idOrLabel: string, actor: Actor): Promise<Row> {
    const row = await this.tk.find(idOrLabel)
    if (!row || !this.sees(row, actor)) throw notFound(`no token "${idOrLabel}"`)
    return row
  }

  /** A live, independent token that `actor` may change (grant, ungrant, rotate). */
  private async changeable(idOrLabel: string, actor: Actor): Promise<Row> {
    const row = await this.visible(idOrLabel, actor)
    if (row.parent) throw badRequest(`"${row.label}" is a child token: its permissions and secret are fixed (revoke it, or extend it)`)
    if (typeof actor !== 'string') this.tk.require(actor, 'turnkey', 'manage')
    if (!this.tk.alive(row)) throw notFound(`token "${row.label}" is revoked or expired`)
    return row
  }

  /** You can give only what you hold. */
  private within(actor: Principal, grants: readonly string[], what?: string): void {
    const held = this.tk.parse(actor.grants)
    const over = grants.filter((g) => !anyCovers(held, parsePermission(g, this.tk.actions), this.tk.actions))
    if (!over.length) return
    throw forbidden(
      what
        ? `token "${actor.label}" may not ${what}: it holds ${over.join(', ')}, which "${actor.label}" does not`
        : `token "${actor.label}" may not give ${over.join(', ')}: it does not hold them`,
    )
  }
}

// -------------------------------------------------------------------- sessions

/**
 * Browser sessions for an app that does its own login (a master password, or an OIDC provider):
 * tokens whose expiry slides forward while used. The cookie's value is the secret. Turnkey never
 * checks a password. Logging out is revoking the session (`tokens.revoke(p.id, p)`).
 */
export class SessionApi {
  constructor(private readonly tk: Turnkey) {}

  /** Call after your login succeeds. Put `secret` in the cookie (`sessionCookie`). */
  async create(input: CreateSessionInput, by: string): Promise<{ token: TokenInfo; secret: string }> {
    const ttl = input.ttlSeconds === undefined ? this.tk.sessionTtl : positiveInt(input.ttlSeconds, 'ttlSeconds')
    const secret = randomSecret(this.tk.tokenPrefix)
    const token = await this.tk.insert({
      label: `${this.tk.sessionPrefix}.${randomId('').slice(0, 12)}`,
      secretHash: sha256Hex(secret),
      grants: this.tk.canonical(grantList(input.grants)),
      subject: subjectOf(input.subject),
      parent: null,
      expiresAt: new Date(this.tk.now().getTime() + ttl * 1000).toISOString(),
      slideSeconds: input.slide === false ? null : ttl,
      createdBy: actorName(by),
    })
    return { token, secret }
  }

  /** Active sessions (live tokens labelled with the session prefix). */
  async list(): Promise<TokenInfo[]> {
    return (await this.tk.tokens.list('sessions')).filter((t) => t.label.startsWith(`${this.tk.sessionPrefix}.`) && !t.parent)
  }

  /** Logs every browser out, e.g. after the password changes. Returns how many. */
  async revokeAll(by: string): Promise<number> {
    let n = 0
    for (const s of await this.list()) {
      n += await this.tk.run(`UPDATE ${this.tk.tableName} SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL`, [this.tk.now().toISOString(), actorName(by), s.id])
    }
    return n
  }
}

// -------------------------------------------------------------------- helpers

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

function grantList(v: unknown): string[] {
  if (!Array.isArray(v)) throw badRequest('grants must be a list of permissions')
  return v.map(String)
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

/** A ttl in seconds; `fallback` when absent (0: absent is not allowed). */
function ttlOf(v: unknown, fallback: number): number {
  if ((v === undefined || v === null) && fallback) return fallback
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > MAX_TTL) throw badRequest(`ttlSeconds must be a whole number of seconds from 1 to ${MAX_TTL} (100 years)`)
  return v
}

function actorName(actor: Actor): string {
  const s = (typeof actor === 'string' ? actor : (actor.actor ?? actor.label)).trim()
  if (!s) throw badRequest('say who is doing this')
  return s.slice(0, 128)
}

function positiveInt(n: number, what: string): number {
  if (!Number.isInteger(n) || n < 1) throw badRequest(`${what} must be a positive whole number of seconds`)
  return n
}

/** `<parent>.<name>`, the name squeezed into the label alphabet and shortened to fit (room is kept for a retry suffix). */
function childLabel(parent: string, name: unknown): string {
  const room = 120 - parent.length - 1
  if (room < 8) throw badRequest(`token "${parent}" has too long a label to name children (at most 111 characters)`)
  const slug = String(name ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9._@-]+/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .slice(0, room)
    .replace(/[^a-z0-9]+$/, '')
  const label = `${parent}.${slug || randomId('').slice(0, 8)}`
  if (!LABEL_RE.test(label)) throw badRequest(`cannot make a label from "${parent}" and name "${String(name)}"`)
  return label
}

function nullable(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v)
}

export { MANAGE, ISSUE, formatPermission }
