// Adapter for the standard Request/Response: Hono, Bun, Deno, workers, anything modern.
import { authenticateRequest, errorResponse, turnkeyRoutes, type AuthOptions, type RoutesOptions } from '../http.js'
import { badRequest } from '../errors.js'
import type { Principal, Turnkey } from '../turnkey.js'

export { sessionCookie, clearSessionCookie, readCookie } from '../http.js'
export type { AuthOptions, CookieOptions, RoutesOptions } from '../http.js'

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

export interface HandlerOptions extends RoutesOptions {
  /** Where the API lives. Default `/turnkey`. */
  prefix?: string
}

/** Turnkey's token API (docs/api.md) under `prefix`. Returns null for a request it doesn't serve. */
export function turnkeyHandler(tk: Turnkey, opts: HandlerOptions = {}) {
  const prefix = (opts.prefix ?? '/turnkey').replace(/\/+$/, '')
  const handle = turnkeyRoutes(tk, opts)
  return async (request: Request): Promise<Response | null> => {
    const u = new URL(request.url)
    const path = u.pathname
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
      out = await handle({ method: request.method, url: path.slice(prefix.length) + u.search, authorization: request.headers.get('authorization'), body })
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
