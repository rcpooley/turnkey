// Framework-neutral HTTP pieces the adapters share: reading a request's credentials (a Bearer
// header or a session cookie), session cookies, and the credential contract's five routes as a
// plain function from a request to a status and JSON body.
import { TurnkeyError, unauthorized, badRequest, forbidden } from './errors.js'
import type { Principal, Turnkey } from './turnkey.js'

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

// -------------------------------------------------------------------- the credential contract

export interface CredentialRoutesOptions {
  /** The service's name, returned by `describe`. */
  service: string
  /** What the `token` value is, for `describe`. */
  tokenDescription?: string
  /** How to write permissions, for `describe`. */
  permissionsHelp?: string
  /** Where unexpected errors are logged. Default `console.error`. */
  log?: (msg: string) => void
}

export interface ContractRequest {
  method: string
  /** The path below the mount point: `/describe`, `/issue`, … */
  path: string
  authorization?: string | null
  /** The parsed JSON body (POST only). */
  body?: unknown
}

/**
 * The credential contract's routes (`describe`, `validate`, `issue`, `renew`, `revoke`) as one
 * function. Returns null for a path it doesn't serve, so the caller can fall through.
 */
export function credentialRoutes(tk: Turnkey, opts: CredentialRoutesOptions): (req: ContractRequest) => Promise<JsonResponse | null> {
  const log = opts.log ?? ((m: string) => console.error(m))
  const routes: Record<string, (issuer: Principal, body: Record<string, unknown>) => Promise<unknown>> = {
    'GET /describe': async (issuer) => {
      tk.credentials.assertIssuer(issuer)
      return {
        service: opts.service,
        maxTtlSeconds: tk.maxCredentialTtl,
        values: { token: opts.tokenDescription ?? `A ${opts.service} token (Authorization: Bearer ${tk.tokenPrefix}…) with the granted permissions` },
        permissions: opts.permissionsHelp ?? '{"grants": ["<action>:<resource>", ...]}: each within what the issuer holds',
        grants: issuer.grants.filter((g) => !g.startsWith('turnkey:')),
      }
    },
    'POST /validate': async (issuer, body) => ({ ok: true, grants: tk.credentials.check(issuer, permissionGrants(body.permissions)) }),
    'POST /issue': async (issuer, body) => {
      const subject = body.subject
      if (!subject || typeof subject !== 'object' || Array.isArray(subject)) throw badRequest('subject must be {session, agent, host}')
      if (typeof (subject as Record<string, unknown>).session !== 'string' || !(subject as Record<string, unknown>).session) {
        throw badRequest('subject.session is required')
      }
      const c = await tk.credentials.issue(issuer, {
        grants: permissionGrants(body.permissions),
        ttlSeconds: body.ttlSeconds as number | undefined,
        subject: subject as Record<string, unknown>,
      })
      return { id: c.id, expiresAt: c.expiresAt, values: { token: c.secret } }
    },
    'POST /renew': async (issuer, body) => tk.credentials.renew(issuer, String(body.id ?? ''), body.ttlSeconds as number | undefined),
    'POST /revoke': async (issuer, body) => tk.credentials.revoke(issuer, String(body.id ?? '')),
  }
  return async (req) => {
    const path = '/' + req.path.replace(/^\/+|\/+$/g, '')
    const route = routes[`${req.method.toUpperCase()} ${path}`]
    if (!route) {
      const known = Object.keys(routes).some((k) => k.endsWith(` ${path}`))
      return known ? { status: 405, body: { error: `method ${req.method} not allowed here`, code: 'method_not_allowed' } } : null
    }
    try {
      const issuer = await tk.authenticate(req.authorization)
      if (!issuer) throw unauthorized('send an issuer token: Authorization: Bearer <token>')
      const body = req.body === undefined || req.body === null ? {} : req.body
      if (typeof body !== 'object' || Array.isArray(body)) throw badRequest('the body must be a JSON object')
      return { status: 200, body: await route(issuer, body as Record<string, unknown>) }
    } catch (err) {
      return errorResponse(err, log)
    }
  }
}

/** The contract's `permissions` for a Turnkey service: `{"grants": [...]}` and nothing else. */
function permissionGrants(p: unknown): string[] {
  if (!p || typeof p !== 'object' || Array.isArray(p) || !Array.isArray((p as { grants?: unknown }).grants)) {
    throw badRequest('permissions must be {"grants": ["<action>:<resource>", ...]}')
  }
  const extra = Object.keys(p).filter((k) => k !== 'grants')
  if (extra.length) throw badRequest(`unknown permission fields: ${extra.join(', ')}`)
  const grants = (p as { grants: unknown[] }).grants
  if (grants.some((g) => typeof g !== 'string')) throw badRequest('each grant must be a string')
  return grants as string[]
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
