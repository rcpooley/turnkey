// node:http adapter: helpers for a plain `(req, res)` server.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { authenticateRequest, credentialRoutes, errorResponse, readJson, type AuthOptions, type CredentialRoutesOptions, type JsonResponse } from '../http.js'
import type { Principal, Turnkey } from '../turnkey.js'

export { sessionCookie, clearSessionCookie, readCookie } from '../http.js'
export type { AuthOptions, CookieOptions, CredentialRoutesOptions } from '../http.js'

const header = (req: IncomingMessage, name: string): string | undefined => {
  const v = req.headers[name]
  return Array.isArray(v) ? v[0] : v
}

/**
 * The principal behind the request, or null. Pass `res` so a sliding session's renewed cookie is
 * set on it. Throws a `TurnkeyError` (403) for a cross-origin cookie write.
 */
export async function principal(tk: Turnkey, req: IncomingMessage, res?: ServerResponse, opts: AuthOptions = {}): Promise<Principal | null> {
  const r = await authenticateRequest(
    tk,
    {
      method: req.method,
      authorization: header(req, 'authorization'),
      cookie: header(req, 'cookie'),
      origin: header(req, 'origin'),
      host: header(req, 'x-forwarded-host') ?? header(req, 'host'),
    },
    opts,
  )
  if (r.setCookie && res && !res.headersSent) res.appendHeader('Set-Cookie', r.setCookie)
  return r.principal
}

export interface CredentialsHandlerOptions extends CredentialRoutesOptions {
  /** Where the routes live. Default `/credentials`. */
  prefix?: string
}

/**
 * The credential contract's routes. Returns true if it answered the request, false if the path
 * isn't one of its routes (so your server carries on routing).
 */
export function credentialsHandler(tk: Turnkey, opts: CredentialsHandlerOptions) {
  const prefix = (opts.prefix ?? '/credentials').replace(/\/+$/, '')
  const handle = credentialRoutes(tk, opts)
  return async (req: IncomingMessage, res: ServerResponse): Promise<boolean> => {
    const path = new URL(req.url ?? '/', 'http://x').pathname
    if (path !== prefix && !path.startsWith(prefix + '/')) return false
    let out: JsonResponse | null
    try {
      const body = req.method === 'POST' ? await readJson(req) : undefined
      out = await handle({ method: req.method ?? 'GET', path: path.slice(prefix.length), authorization: header(req, 'authorization'), body })
    } catch (err) {
      out = errorResponse(err)
    }
    if (!out) return false
    sendJson(res, out.status, out.body)
    return true
  }
}

/** Writes a JSON response. */
export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(body))
}

/** Answers with a `TurnkeyError`'s status and `{error, code}`, or a 500. */
export function sendError(res: ServerResponse, err: unknown): void {
  const r = errorResponse(err, (m) => console.error(m))
  if (!res.headersSent) sendJson(res, r.status, r.body)
}
