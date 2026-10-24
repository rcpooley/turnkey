// Express (4 and 5) adapter. Structural types only: this file never imports express.
import { authenticateRequest, errorResponse, readJson, turnkeyRoutes, type AuthOptions, type RoutesOptions } from '../http.js'
import type { Principal, Turnkey } from '../turnkey.js'

export { sessionCookie, clearSessionCookie, readCookie } from '../http.js'
export type { AuthOptions, CookieOptions, RoutesOptions } from '../http.js'

interface Req extends AsyncIterable<unknown> {
  method: string
  path: string
  /** Below the mount point, with the query string. */
  url: string
  body?: unknown
  headers: Record<string, string | string[] | undefined>
  principal?: Principal | null
  params?: Record<string, string>
  authVia?: 'bearer' | 'cookie' | null
}
interface Res {
  status(code: number): Res
  json(body: unknown): unknown
  append(field: string, value: string): unknown
  headersSent?: boolean
}
type Next = (err?: unknown) => void

const header = (req: Req, name: string): string | undefined => {
  const v = req.headers[name]
  return Array.isArray(v) ? v[0] : v
}

export interface MiddlewareOptions extends AuthOptions {
  /** Answer 401 when there is no valid token. Default true. */
  required?: boolean
}

/**
 * Sets `req.principal` (and `req.authVia`) from the Bearer header or the session cookie. With
 * `required` (the default), a request without a valid token gets a 401 JSON answer.
 */
export function authenticate(tk: Turnkey, opts: MiddlewareOptions = {}) {
  return (req: Req, res: Res, next: Next): void => {
    authenticateRequest(
      tk,
      {
        method: req.method,
        authorization: header(req, 'authorization'),
        cookie: header(req, 'cookie'),
        origin: header(req, 'origin'),
        host: header(req, 'x-forwarded-host') ?? header(req, 'host'),
      },
      opts,
    ).then(
      (r) => {
        req.principal = r.principal
        req.authVia = r.via
        if (r.setCookie) res.append('Set-Cookie', r.setCookie)
        if (!r.principal && opts.required !== false) {
          res.status(401).json({ error: r.via === 'cookie' ? 'your session has expired or was revoked; log in again' : 'authentication required', code: 'unauthorized' })
          return
        }
        next()
      },
      (err) => sendError(res, err),
    )
  }
}

/** Middleware that answers 403 unless `req.principal` may do `action` on `resource`. */
export function requirePermission(tk: Turnkey, action: string, resource: string | ((req: Req) => string)) {
  return (req: Req, res: Res, next: Next): void => {
    try {
      tk.require(req.principal, action, typeof resource === 'function' ? resource(req) : resource)
      next()
    } catch (err) {
      sendError(res, err)
    }
  }
}

/**
 * Turnkey's token API (docs/api.md), to mount where you like: `app.use('/turnkey', turnkeyRouter(tk))`.
 * Parses JSON itself if no body parser ran. Other paths fall through to `next()`.
 */
export function turnkeyRouter(tk: Turnkey, opts: RoutesOptions = {}) {
  const handle = turnkeyRoutes(tk, opts)
  return (req: Req, res: Res, next: Next): void => {
    ;(async () => {
      const body = req.method === 'POST' ? (req.body !== undefined ? req.body : await readJson(req)) : undefined
      return handle({ method: req.method, url: req.url, authorization: header(req, 'authorization'), body })
    })().then(
      (out) => {
        if (!out) return next()
        res.status(out.status).json(out.body)
      },
      (err) => sendError(res, err),
    )
  }
}

/** Answers with a `TurnkeyError`'s status and `{error, code}`, or a 500. */
export function sendError(res: Res, err: unknown): void {
  if (res.headersSent) return
  const r = errorResponse(err, (m) => console.error(m))
  res.status(r.status).json(r.body)
}
