// Break-glass token commands for a service's own admin entry point: the first token, or a new one
// after you revoked your own. Runs with direct database access, so it checks no permission.
//   token list [--all] | show <label> | create <label> --grant <p>... [--expires <iso>]
//   token extend <label> --expires <iso> | grant|ungrant <label> --grant <p>... | revoke <label> | rotate <label>
import { TurnkeyError } from './errors.js'
import type { TokenInfo, Turnkey } from './turnkey.js'

export interface AdminIo {
  out: (line: string) => void
  err: (line: string) => void
}

const USAGE = `usage: token <command>
  list [--all]                                   every token, session and child
  show <label>
  create <label> --grant <perm>... [--expires <iso>]   prints the secret once
  extend <label> --expires <iso>
  grant <label> --grant <perm>...
  ungrant <label> --grant <perm>...
  revoke <label>
  rotate <label>                                 prints the new secret once`

/** Runs one admin command; prints JSON to `out`. Returns the exit code. */
export async function runAdminCli(tk: Turnkey, argv: readonly string[], io: AdminIo = { out: (l) => console.log(l), err: (l) => console.error(l) }): Promise<number> {
  const args = [...argv]
  if (args[0] === 'token' || args[0] === 'tokens') args.shift()
  const cmd = args.shift()
  const flags: Record<string, string[]> = {}
  const pos: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!
    if (a.startsWith('--')) {
      const [k, inline] = a.slice(2).split(/=(.*)/s, 2) as [string, string | undefined]
      const v = inline ?? (k === 'all' ? 'true' : args[++i])
      if (v === undefined) return fail(io, `--${k} needs a value`)
      ;(flags[k] ??= []).push(v)
    } else pos.push(a)
  }
  const by = 'admin-cli'
  const show = (t: TokenInfo, secret?: string) => io.out(JSON.stringify({ ...t, ...(secret ? { secret } : {}) }, null, 2))
  try {
    switch (cmd) {
      case 'list':
        io.out(JSON.stringify(await tk.tokens.list(by, { all: !!flags.all }), null, 2))
        return 0
      case 'show':
        show(await tk.tokens.get(need(pos[0], 'label'), by))
        return 0
      case 'create': {
        const r = await tk.tokens.create({ label: need(pos[0], 'label'), grants: flags.grant ?? [], expiresAt: flags.expires?.[0] ?? null }, by)
        show(r.token, r.secret)
        return 0
      }
      case 'extend':
        show(await tk.tokens.extend(need(pos[0], 'label'), { expiresAt: need(flags.expires?.[0], 'expires') }, by))
        return 0
      case 'grant':
        show(await tk.tokens.grant(need(pos[0], 'label'), flags.grant ?? [], by))
        return 0
      case 'ungrant':
        show(await tk.tokens.ungrant(need(pos[0], 'label'), flags.grant ?? [], by))
        return 0
      case 'revoke':
        show(await tk.tokens.revoke(need(pos[0], 'label'), by))
        return 0
      case 'rotate': {
        const r = await tk.tokens.rotate(need(pos[0], 'label'), by)
        show(r.token, r.secret)
        return 0
      }
      default:
        io.err(USAGE)
        return cmd === undefined || cmd === 'help' || cmd === '--help' ? 0 : 2
    }
  } catch (err) {
    if (err instanceof TurnkeyError) return fail(io, err.message)
    throw err
  }
}

function need(v: string | undefined, what: string): string {
  if (!v) throw new TurnkeyError(400, `missing <${what}>`, 'bad_request')
  return v
}

function fail(io: AdminIo, msg: string): number {
  io.err(JSON.stringify({ error: msg }))
  return 1
}
