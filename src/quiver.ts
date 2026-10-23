// Ready-made Quiver module commands for token management. A service adds `commands` to its own
// module's manifest and routes those command paths to `run`. Every command needs `turnkey:manage`.
import { badRequest } from './errors.js'
import type { Principal, TokenInfo, TokenKind, Turnkey } from './turnkey.js'

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
  /** Runs one. Throws a `TurnkeyError` (403 without `turnkey:manage`); returns the JSON result. */
  run(path: readonly string[], params: Record<string, unknown>, caller: Principal | null): Promise<unknown>
}

const SESSION: ParamDef = { name: 'session', type: 'string', description: 'Your session id, recorded as who made the change (filled in by the CLI).' }
const label: ParamDef = { name: 'label', type: 'string', positional: true, required: true, description: 'Token label (or id)' }

const view = (t: TokenInfo) => ({
  id: t.id,
  label: t.label,
  kind: t.kind,
  grants: t.grants,
  ...(t.subject ? { subject: t.subject } : {}),
  ...(t.issuedBy ? { issuedBy: t.issuedBy } : {}),
  expiresAt: t.expiresAt,
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

  const commands: CommandDef[] = [
    {
      name: group,
      description: 'Manage access tokens (needs turnkey:manage). Secrets are shown once, at create and rotate.',
      commands: [
        {
          name: 'list',
          description: 'Active tokens, browser sessions and issued credentials, with their permissions (never the secrets).',
          params: [
            { name: 'all', type: 'boolean', description: 'Include revoked and expired ones (kept for the retention period)' },
            { name: 'kind', type: 'string', choices: ['token', 'session', 'credential'], description: 'Only this kind' },
          ],
        },
        { name: 'show', description: 'One token by label or id.', params: [label] },
        {
          name: 'create',
          description: 'Create a token. Prints the secret once.',
          params: [
            { ...label, description: 'Name for the token: the host, agent or script that holds it' },
            grant(true),
            { name: 'expires', type: 'string', description: 'When it stops working (ISO 8601); default never' },
            SESSION,
          ],
        },
        { name: 'grant', description: 'Add permissions to a token.', params: [label, grant(true)] },
        { name: 'ungrant', description: 'Remove permissions from a token.', params: [label, { ...grant(true), description: 'A permission it holds; repeatable' }] },
        { name: 'revoke', description: 'Stop a token working now. Credentials it issued stop with it.', params: [label, SESSION] },
        { name: 'rotate', description: "Replace a token's secret, keeping its label and permissions. Prints the new secret once.", params: [label, SESSION] },
        { name: 'credentials', description: 'Active issued credentials: who issued them, for which session, until when.' },
      ],
    },
  ]

  const by = (caller: Principal, p: Record<string, unknown>) =>
    typeof p.session === 'string' && p.session ? `session:${p.session}@${caller.label}` : caller.label
  const grants = (p: Record<string, unknown>) => {
    const g = p.grant
    const list = Array.isArray(g) ? g.map(String) : g === undefined || g === null ? [] : [String(g)]
    if (!list.length) throw badRequest('give at least one --grant')
    return list
  }

  const handlers: Record<string, (p: Record<string, unknown>, caller: Principal) => Promise<unknown>> = {
    list: async (p) => ({ tokens: (await tk.tokens.list({ all: p.all === true, kind: p.kind as TokenKind | undefined })).map(view) }),
    show: async (p) => view(await tk.tokens.get(String(p.label))),
    create: async (p, caller) => {
      const { token, secret } = await tk.tokens.create({ label: String(p.label), grants: grants(p), expiresAt: (p.expires as string) || null, createdBy: by(caller, p) })
      return { ...view(token), secret }
    },
    grant: async (p) => view(await tk.tokens.grant(String(p.label), grants(p))),
    ungrant: async (p) => view(await tk.tokens.ungrant(String(p.label), grants(p))),
    revoke: async (p, caller) => view(await tk.tokens.revoke(String(p.label), by(caller, p))),
    rotate: async (p, caller) => {
      const { token, secret } = await tk.tokens.rotate(String(p.label), by(caller, p))
      return { ...view(token), secret }
    },
    credentials: async () => ({ credentials: (await tk.credentials.list()).map(view) }),
  }

  return {
    commands,
    handles: (path) => path.length === 2 && path[0] === group && path[1]! in handlers,
    async run(path, params, caller) {
      if (path[0] !== group || !(path[1]! in handlers)) throw badRequest(`not a Turnkey command: ${path.join(' ')}`)
      tk.require(caller, 'turnkey', 'manage')
      return handlers[path[1]!]!(params, caller)
    },
  }
}
