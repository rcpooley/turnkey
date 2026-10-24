// Framework-neutral HTTP pieces the adapters share: reading a request's credentials (a Bearer
// header or a session cookie), session cookies, and Turnkey's token API as a plain function from a
// request to a status and JSON body.
import { TurnkeyError, unauthorized, badRequest, forbidden } from './errors.js'
import type { CreateTokenInput, Principal, Turnkey } from './turnkey.js'

// -------------------------------------------------------------------- cookies

export interface CookieOptions {
  /** The cookie's name. */
  name: string
  /** Default true. Turn off only for local development over plain http. */
  secure?: boolean
  /** Default `Lax`. */
  sameSite?: 'Strict' | 'Lax' | 'None'
  /** Default `/`. */
  path?: string
  domain?: string
}

/** A `Set-Cookie` value carrying a session secret: HttpOnly, Secure, SameSite=Lax unless told otherwise. */
export function sessionCookie(secret: string, expiresAt: string | Date | null, opts: CookieOptions): string {
  const maxAge = expiresAt ? Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000)) : undefined
  return cookieString(opts, encodeURIComponent(secret), maxAge)
}

/** A `Set-Cookie` value that deletes the session cookie (for logout). */
export function clearSessionCookie(opts: CookieOptions): string {
  return cookieString(opts, '', 0)
}

function cookieString(opts: CookieOptions, value: string, maxAge: number | undefined): string {
  if (!/^[A-Za-z0-9_.-]+$/.test(opts.name)) throw badRequest(`bad cookie name "${opts.name}"`)
  return [
    `${opts.name}=${value}`,
    `Path=${opts.path ?? '/'}`,
    ...(opts.domain ? [`Domain=${opts.domain}`] : []),
    'HttpOnly',
    `SameSite=${opts.sameSite ?? 'Lax'}`,
    ...(maxAge !== undefined ? [`Max-Age=${maxAge}`] : []),
    ...(opts.secure === false ? [] : ['Secure']),
  ].join('; ')
}

/** One cookie's value from a `Cookie` header. */
export function readCookie(header: string | null | undefined, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const i = part.indexOf('=')
    if (i > 0 && part.slice(0, i).trim() === name) {
      try {
        return decodeURIComponent(part.slice(i + 1).trim())
      } catch {
        return ''
      }
    }
  }
  return undefined
}

// -------------------------------------------------------------------- authenticating a request

/** What an adapter reads off a request. */
export interface RequestCredentials {
  method?: string
  authorization?: string | null
  cookie?: string | null
  origin?: string | null
  /** The `Host` the browser used (or `X-Forwarded-Host` behind a proxy that rewrites it). */
  host?: string | null
}

export interface AuthOptions {
  /** Read a session from this cookie when there is no `Authorization` header. */
  cookie?: CookieOptions
  /**
   * Origins (scheme://host[:port]) besides the request's own host that may send cookie-authenticated
   * writes. A cookie-authenticated request that is not GET/HEAD/OPTIONS and carries an `Origin`
   * from anywhere else is refused, so a sibling site can't ride the cookie.
   */
  trustedOrigins?: string[]
}

export interface AuthResult {
  principal: Principal | null
  via: 'bearer' | 'cookie' | null
  /** Set when a sliding session was extended: send it as `Set-Cookie`. */
  setCookie?: string
}

/** The principal behind a request's `Authorization` header, or its session cookie. */
export async function authenticateRequest(tk: Turnkey, c: RequestCredentials, opts: AuthOptions = {}): Promise<AuthResult> {
  if (c.authorization && c.authorization.trim()) {
    return { principal: await tk.authenticate(c.authorization), via: 'bearer' }
  }
  if (!opts.cookie) return { principal: null, via: null }
  const secret = readCookie(c.cookie, opts.cookie.name)
  if (!secret) return { principal: null, via: null }
  const principal = await tk.authenticate(secret)
  if (!principal) return { principal: null, via: 'cookie' }
  const method = (c.method ?? 'GET').toUpperCase()
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && c.origin && !sameOrigin(c.origin, c.host, opts.trustedOrigins)) {
    throw forbidden(`a cookie-authenticated ${method} from ${c.origin} is not allowed`)
  }
  return {
    principal,
    via: 'cookie',
    ...(principal.renewed ? { setCookie: sessionCookie(secret, principal.expiresAt, opts.cookie) } : {}),
  }
}

function sameOrigin(origin: string, host: string | null | undefined, trusted: string[] = []): boolean {
  if (trusted.includes(origin)) return true
  try {
    return !!host && new URL(origin).host === host.split(',')[0]!.trim()
  } catch {
    return false
  }
}

// -------------------------------------------------------------------- errors

export interface JsonResponse {
  status: number
  body: unknown
  headers?: Record<string, string>
}

/** A thrown error as a JSON response: a `TurnkeyError` keeps its status; anything else is a 500. */
export function errorResponse(err: unknown, log?: (msg: string) => void): JsonResponse {
  if (err instanceof TurnkeyError) return { status: err.status, body: err.toJSON() }
  log?.(`turnkey: internal error: ${(err as Error)?.stack ?? err}`)
  return { status: 500, body: { error: 'internal error', code: 'internal' } }
}

// -------------------------------------------------------------------- the token API

export interface RoutesOptions {
  /** Where unexpected errors are logged. Default `console.error`. */
  log?: (msg: string) => void
}

export interface ApiRequest {
  method: string
  /** The path below the mount point, with any query string: `/tokens?all=true`, `/tokens/ci/extend`. */
  url: string
  authorization?: string | null
  /** The parsed JSON body (POST only). */
  body?: unknown
}

/**
 * Turnkey's HTTP API (docs/api.md) as one function. Every call needs a token as
 * `Authorization: Bearer`, and gets the same rules as the library. Returns null for a path it
 * doesn't serve, so the caller can fall through.
 */
export function turnkeyRoutes(tk: Turnkey, opts: RoutesOptions = {}): (req: ApiRequest) => Promise<JsonResponse | null> {
  const log = opts.log ?? ((m: string) => console.error(m))
  type Handler = (who: Principal, body: Record<string, unknown>, ref: string, query: URLSearchParams) => Promise<JsonResponse>
  const ok = async (body: Promise<unknown> | unknown): Promise<JsonResponse> => ({ status: 200, body: await body })
  const routes: Record<string, Handler> = {
    'GET /self': async (who) => ok({ ...(await tk.tokens.get(who.id, who)), grants: who.grants, maxChildTtlSeconds: tk.maxChildTtl }),
    'GET /tokens': async (who, _b, _r, q) =>
      ok({ tokens: await tk.tokens.list(who, { all: q.get('all') === 'true', ...(q.get('parent') ? { parent: q.get('parent')! } : {}) }) }),
    'POST /tokens': async (who, body) => {
      const input = createInput(body)
      if (body.dryRun === true) return ok({ dryRun: true, ...(await tk.tokens.check(input, who)) })
      return { status: 201, body: await tk.tokens.create(input, who) }
    },
    'GET /tokens/:ref': async (who, _b, ref) => ok(tk.tokens.get(ref, who)),
    'POST /tokens/:ref/extend': async (who, body, ref) => {
      only(body, ['ttlSeconds', 'expiresAt'])
      ttlField(body)
      if (body.expiresAt != null && typeof body.expiresAt !== 'string') throw badRequest('expiresAt must be a string')
      return ok(tk.tokens.extend(ref, { ttlSeconds: body.ttlSeconds as number | undefined, expiresAt: body.expiresAt as string | undefined }, who))
    },
    'POST /tokens/:ref/revoke': async (who, body, ref) => (only(body, []), ok(tk.tokens.revoke(ref, who))),
    'POST /tokens/:ref/grant': async (who, body, ref) => (only(body, ['grants']), ok(tk.tokens.grant(ref, grantsOf(body), who))),
    'POST /tokens/:ref/ungrant': async (who, body, ref) => (only(body, ['grants']), ok(tk.tokens.ungrant(ref, grantsOf(body), who))),
    'POST /tokens/:ref/rotate': async (who, body, ref) => (only(body, []), ok(tk.tokens.rotate(ref, who))),
  }
  const match = (method: string, path: string): { key: string; ref: string } | null | 'method' => {
    const parts = path.split('/').filter(Boolean)
    let ref = ''
    let shape = '/' + parts.join('/')
    if (parts[0] === 'tokens' && parts.length >= 2 && parts.length <= 3) {
      try {
        ref = decodeURIComponent(parts[1]!)
      } catch {
        return null
      }
      shape = ['', 'tokens', ':ref', ...parts.slice(2)].join('/')
    }
    const key = `${method.toUpperCase()} ${shape}`
    if (key in routes) return { key, ref }
    return Object.keys(routes).some((k) => k.endsWith(` ${shape}`)) ? 'method' : null
  }
  return async (req) => {
    // Prefixed, so a path starting `//` stays a path rather than becoming a host.
    const u = new URL('http://x' + (req.url?.startsWith('/') ? req.url : `/${req.url ?? ''}`))
    const m = match(req.method, u.pathname.replace(/\/+$/, '') || '/')
    if (!m) return null
    if (m === 'method') return { status: 405, body: { error: `method ${req.method} not allowed here`, code: 'method_not_allowed' } }
    try {
      const who = await tk.authenticate(req.authorization)
      if (!who) throw unauthorized('send a token: Authorization: Bearer <token>')
      const body = req.body === undefined || req.body === null ? {} : req.body
      if (typeof body !== 'object' || Array.isArray(body)) throw badRequest('the body must be a JSON object')
      return await routes[m.key]!(who, body as Record<string, unknown>, m.ref, u.searchParams)
    } catch (err) {
      return errorResponse(err, log)
    }
  }
}

const CREATE_FIELDS = ['label', 'name', 'grants', 'expiresAt', 'ttlSeconds', 'subject', 'child', 'dryRun']

function createInput(body: Record<string, unknown>): CreateTokenInput {
  only(body, CREATE_FIELDS)
  if (body.child !== undefined && typeof body.child !== 'boolean') throw badRequest('child must be true or false')
  if (body.dryRun !== undefined && typeof body.dryRun !== 'boolean') throw badRequest('dryRun must be true or false')
  ttlField(body)
  for (const k of ['label', 'name', 'expiresAt'] as const) {
    if (body[k] !== undefined && body[k] !== null && typeof body[k] !== 'string') throw badRequest(`${k} must be a string`)
  }
  return {
    grants: grantsOf(body),
    ...(body.label != null ? { label: body.label as string } : {}),
    ...(body.name != null ? { name: body.name as string } : {}),
    ...(body.expiresAt != null ? { expiresAt: body.expiresAt as string } : {}),
    ...(body.ttlSeconds != null ? { ttlSeconds: body.ttlSeconds as number } : {}),
    ...(body.subject !== undefined ? { subject: body.subject as Record<string, unknown> | null } : {}),
    child: body.child === true,
  }
}

function ttlField(body: Record<string, unknown>): void {
  if (body.ttlSeconds != null && typeof body.ttlSeconds !== 'number') throw badRequest('ttlSeconds must be a number')
}

function grantsOf(body: Record<string, unknown>): string[] {
  const g = body.grants
  if (!Array.isArray(g) || g.some((x) => typeof x !== 'string')) throw badRequest('grants must be a list of permissions, e.g. ["read:*"]')
  return g as string[]
}

/** Unknown fields are refused, so a typo isn't silently ignored. */
function only(body: Record<string, unknown>, allowed: string[]): void {
  const extra = Object.keys(body).filter((k) => !allowed.includes(k))
  if (extra.length) throw badRequest(`unknown field(s): ${extra.join(', ')}`)
}

/** Reads a JSON body from a Node stream, up to `limit` bytes. Empty → undefined. */
export async function readJson(stream: AsyncIterable<unknown>, limit = 64 * 1024): Promise<unknown> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of stream) {
    const b = typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer)
    size += b.length
    if (size > limit) throw new TurnkeyError(413, 'request body too large', 'too_large')
    chunks.push(b)
  }
  const text = Buffer.concat(chunks).toString('utf8').trim()
  if (!text) return undefined
  try {
    return JSON.parse(text)
  } catch {
    throw badRequest('the body is not valid JSON')
  }
}
