// Adapter for the standard Request/Response: Hono, Bun, Deno, workers, anything modern.
import { authenticateRequest, credentialRoutes, errorResponse, type AuthOptions, type CredentialRoutesOptions } from '../http.js'
import { badRequest } from '../errors.js'
import type { Principal, Turnkey } from '../turnkey.js'

export { sessionCookie, clearSessionCookie, readCookie } from '../http.js'
export type { AuthOptions, CookieOptions, CredentialRoutesOptions } from '../http.js'

export interface FetchAuth {
  principal: Principal | null
  /** Headers to add to your response (a renewed session cookie). */
  headers: Headers
}

/** The principal behind a Request, plus any `Set-Cookie` to send back. */
export async function authenticate(tk: Turnkey, request: Request, opts: AuthOptions = {}): Promise<FetchAuth> {
  const h = request.headers
  const r = await authenticateRequest(
    tk,
    { method: request.method, authorization: h.get('authorization'), cookie: h.get('cookie'), origin: h.get('origin'), host: h.get('x-forwarded-host') ?? h.get('host') },
    opts,
  )
  const headers = new Headers()
  if (r.setCookie) headers.append('Set-Cookie', r.setCookie)
  return { principal: r.principal, headers }
}

export interface CredentialsHandlerOptions extends CredentialRoutesOptions {
  /** Where the routes live. Default `/credentials`. */
  prefix?: string
}

/** The credential contract's routes. Returns null for a request it doesn't serve. */
export function credentialsHandler(tk: Turnkey, opts: CredentialsHandlerOptions) {
  const prefix = (opts.prefix ?? '/credentials').replace(/\/+$/, '')
  const handle = credentialRoutes(tk, opts)
  return async (request: Request): Promise<Response | null> => {
    const path = new URL(request.url).pathname
    if (path !== prefix && !path.startsWith(prefix + '/')) return null
    let out
    try {
      let body: unknown
      if (request.method === 'POST') {
        const text = await request.text()
        if (text.length > 64 * 1024) throw badRequest('request body too large')
        try {
          body = text.trim() ? JSON.parse(text) : undefined
        } catch {
          throw badRequest('the body is not valid JSON')
        }
      }
      out = await handle({ method: request.method, path: path.slice(prefix.length), authorization: request.headers.get('authorization'), body })
    } catch (err) {
      out = errorResponse(err)
    }
    return out ? json(out.status, out.body) : null
  }
}

/** A JSON Response. */
export function json(status: number, body: unknown, headers?: HeadersInit): Response {
  const h = new Headers(headers)
  h.set('content-type', 'application/json; charset=utf-8')
  return new Response(JSON.stringify(body), { status, headers: h })
}

/** A `TurnkeyError` as its status and `{error, code}`, or a 500. */
export function errorJson(err: unknown): Response {
  const r = errorResponse(err, (m) => console.error(m))
  return json(r.status, r.body)
}
