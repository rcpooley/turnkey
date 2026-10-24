// Ready-made Quiver module commands for tokens. A service adds `commands` to its own module's
// manifest and routes those command paths to `run`. Each command is the library operation of the
// same name, with the same rules: `turnkey:manage` may do anything, `turnkey:issue` may create
// and look after children, and any token may see and revoke itself.
import { badRequest, unauthorized } from './errors.js'
import type { Principal, TokenInfo, Turnkey } from './turnkey.js'

/** Quiver manifest types (the shape of a module's command tree). */
export interface ParamDef {
  name: string
  type: 'string' | 'number' | 'boolean'
  description?: string
  positional?: boolean
  repeated?: boolean
  required?: boolean
  default?: string | number | boolean
  choices?: (string | number)[]
}
export interface CommandDef {
  name: string
  description: string
  params?: ParamDef[]
  commands?: CommandDef[]
  timeoutSeconds?: number
}

export interface TokenCommandsOptions {
  /** The group's name in your module. Default `tokens`. */
  group?: string
  /** How to write a permission, shown in help. */
  grantHelp?: string
}

export interface TokenCommands {
  /** Add these to your manifest's `commands`. */
  commands: CommandDef[]
  /** Whether a command path (`['tokens', 'list']`) is one of these. */
  handles(path: readonly string[]): boolean
  /** Runs one. Throws a `TurnkeyError` (401 without a caller, 403 when the rules refuse); returns the JSON result. */
  run(path: readonly string[], params: Record<string, unknown>, caller: Principal | null): Promise<unknown>
}

const SESSION: ParamDef = { name: 'session', type: 'string', description: 'Your session id, recorded as who made the change (filled in by the CLI).' }
const label: ParamDef = { name: 'label', type: 'string', positional: true, required: true, description: 'Token label (or id)' }

const view = (t: TokenInfo) => ({
  id: t.id,
  label: t.label,
  grants: t.grants,
  ...(t.parent ? { parent: t.parent } : {}),
  ...(t.subject ? { subject: t.subject } : {}),
  expiresAt: t.expiresAt,
  ...(t.slideSeconds !== null ? { slideSeconds: t.slideSeconds } : {}),
  createdAt: t.createdAt,
  createdBy: t.createdBy,
  ...(t.rotatedAt ? { rotatedAt: t.rotatedAt, rotatedBy: t.rotatedBy } : {}),
  ...(t.revokedAt ? { revokedAt: t.revokedAt, revokedBy: t.revokedBy } : {}),
  lastUsedAt: t.lastUsedAt,
  active: t.active,
})

export function tokenCommands(tk: Turnkey, opts: TokenCommandsOptions = {}): TokenCommands {
  const group = opts.group ?? 'tokens'
  const grantHelp =
    opts.grantHelp ?? `A permission, action:resource (actions: ${[...tk.actions.declared].join(', ')}, or *; e.g. read:* or write:things/abc); repeatable`
  const grant = (required: boolean): ParamDef => ({ name: 'grant', type: 'string', repeated: true, required, description: grantHelp })

  const ttl: ParamDef = { name: 'ttl', type: 'number', description: 'Lifetime in seconds from now' }
  const expires: ParamDef = { name: 'expires', type: 'string', description: 'When it stops working (ISO 8601)' }
  const commands: CommandDef[] = [
    {
      name: group,
      description:
        'Access tokens. turnkey:manage may do anything; turnkey:issue may create child tokens and extend or revoke its own; any token may see and revoke itself. Secrets are shown once, at create and rotate.',
      commands: [
        {
          name: 'list',
          description: 'The tokens you may see, with their permissions (never the secrets).',
          params: [
            { name: 'all', type: 'boolean', description: 'Include revoked and expired ones (kept for the retention period)' },
            { name: 'parent', type: 'string', description: 'Only the children of this token (label or id)' },
          ],
        },
        { name: 'show', description: 'One token by label or id.', params: [label] },
        {
          name: 'create',
          description: 'Create a token, or with --child a child of yours. Prints the secret once.',
          params: [
            { ...label, description: "The token's label; with --child, its name (the label is <your label>.<name>)" },
            grant(true),
            expires,
            ttl,
            { name: 'child', type: 'boolean', description: 'A child of the calling token: it expires within the cap, and works only while yours does' },
            SESSION,
          ],
        },
        { name: 'extend', description: 'Move a token\'s expiry (a child\'s by at most the cap). The secret stays the same.', params: [label, ttl, expires] },
        { name: 'grant', description: 'Add permissions to a token (only ones you hold).', params: [label, grant(true)] },
        { name: 'ungrant', description: 'Remove permissions from a token.', params: [label, { ...grant(true), description: 'A permission it holds; repeatable' }] },
        { name: 'revoke', description: 'Stop a token working now. Its children stop with it.', params: [label, SESSION] },
        { name: 'rotate', description: "Replace a token's secret, keeping its label and permissions. Prints the new secret once.", params: [label, SESSION] },
      ],
    },
  ]

  /** The caller, recorded as `session:<id>@<label>` when the CLI passed its session. */
  const as = (caller: Principal, p: Record<string, unknown>): Principal =>
    typeof p.session === 'string' && p.session ? { ...caller, actor: `session:${p.session}@${caller.label}` } : caller
  const grants = (p: Record<string, unknown>) => {
    const g = p.grant
    const list = Array.isArray(g) ? g.map(String) : g === undefined || g === null ? [] : [String(g)]
    if (!list.length) throw badRequest('give at least one --grant')
    return list
  }
  const num = (v: unknown) => (v === undefined || v === null || v === '' ? undefined : typeof v === 'number' ? v : Number(v))
  const str = (v: unknown) => (typeof v === 'string' && v ? v : undefined)

  const handlers: Record<string, (p: Record<string, unknown>, caller: Principal) => Promise<unknown>> = {
    list: async (p, caller) => ({ tokens: (await tk.tokens.list(caller, { all: p.all === true, ...(str(p.parent) ? { parent: str(p.parent)! } : {}) })).map(view) }),
    show: async (p, caller) => view(await tk.tokens.get(String(p.label), caller)),
    create: async (p, caller) => {
      const child = p.child === true
      const { token, secret } = await tk.tokens.create(
        {
          ...(child ? { name: String(p.label) } : { label: String(p.label) }),
          grants: grants(p),
          expiresAt: str(p.expires) ?? null,
          ttlSeconds: num(p.ttl) ?? null,
          child,
        },
        as(caller, p),
      )
      return { ...view(token), secret }
    },
    extend: async (p, caller) => view(await tk.tokens.extend(String(p.label), { ttlSeconds: num(p.ttl) ?? null, expiresAt: str(p.expires) ?? null }, caller)),
    grant: async (p, caller) => view(await tk.tokens.grant(String(p.label), grants(p), caller)),
    ungrant: async (p, caller) => view(await tk.tokens.ungrant(String(p.label), grants(p), caller)),
    revoke: async (p, caller) => view(await tk.tokens.revoke(String(p.label), as(caller, p))),
    rotate: async (p, caller) => {
      const { token, secret } = await tk.tokens.rotate(String(p.label), as(caller, p))
      return { ...view(token), secret }
    },
  }

  return {
    commands,
    handles: (path) => path.length === 2 && path[0] === group && path[1]! in handlers,
    async run(path, params, caller) {
      if (path[0] !== group || !(path[1]! in handlers)) throw badRequest(`not a Turnkey command: ${path.join(' ')}`)
      if (!caller) throw unauthorized()
      return handlers[path[1]!]!(params, caller)
    },
  }
}
