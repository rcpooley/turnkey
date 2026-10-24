// Permissions are `action:resource`. Resources are `/`-separated paths matched hierarchically:
// `sessions` covers `sessions/abc`; a `*` segment matches any one segment; a resource of `*`
// alone covers everything. Grammar and coverage: docs/permissions.md.
import { badRequest } from './errors.js'

export interface Permission {
  /** A declared action, `*`, or the reserved `turnkey`. */
  action: string
  /** Path segments. `['*']` is everything. */
  resource: string[]
}

/** The reserved action for Turnkey's own permissions. */
export const TURNKEY = 'turnkey'
export const MANAGE = 'turnkey:manage'
export const ISSUE = 'turnkey:issue'
const TURNKEY_RESOURCES = new Set(['manage', 'issue', '*'])

const ACTION_RE = /^[a-z][a-z0-9_-]{0,31}$/
// A segment is any run of visible characters other than `/`, `:`, `*` and whitespace, or `*` alone.
const SEGMENT_RE = /^(?:\*|[^\s/:*]{1,128})$/
const MAX_LENGTH = 512

export interface ActionRules {
  /** The service's actions. `*` and `turnkey` are always valid. */
  actions: readonly string[]
  /** One action including others, e.g. `{write: ['read']}`. Applied transitively. */
  implies?: Readonly<Record<string, readonly string[]>>
}

/** Validated action rules with the transitive closure of `implies`. */
export class Actions {
  readonly declared: ReadonlySet<string>
  private readonly closure = new Map<string, Set<string>>()

  constructor(rules: ActionRules) {
    const declared = new Set<string>()
    for (const a of rules.actions) {
      if (!ACTION_RE.test(a)) throw badRequest(`bad action "${a}": lowercase letters, digits, "_" and "-", starting with a letter`)
      if (a === TURNKEY) throw badRequest(`"${TURNKEY}" is reserved for Turnkey's own permissions`)
      declared.add(a)
    }
    if (!declared.size) throw badRequest('declare at least one action')
    this.declared = declared
    const implies = rules.implies ?? {}
    for (const [a, list] of Object.entries(implies)) {
      for (const x of [a, ...list]) if (!declared.has(x)) throw badRequest(`implies names "${x}", which is not a declared action`)
    }
    for (const a of declared) {
      const seen = new Set<string>([a])
      const stack = [a]
      while (stack.length) for (const next of implies[stack.pop()!] ?? []) if (!seen.has(next)) seen.add(next), stack.push(next)
      this.closure.set(a, seen)
    }
  }

  /** Whether holding action `held` allows action `wanted`. */
  allows(held: string, wanted: string): boolean {
    if (held === '*') return true
    if (held === wanted) return true
    return this.closure.get(held)?.has(wanted) ?? false
  }

  isValid(action: string): boolean {
    return action === '*' || action === TURNKEY || this.declared.has(action)
  }
}

/** Parse one permission, or throw a 400 naming what is wrong. */
export function parsePermission(text: string, actions: Actions): Permission {
  const s = String(text).trim()
  if (!s || s.length > MAX_LENGTH) throw badRequest(`bad permission "${text}": expected action:resource`)
  const i = s.indexOf(':')
  if (i <= 0 || i === s.length - 1) throw badRequest(`bad permission "${text}": expected action:resource, e.g. read:*`)
  const action = s.slice(0, i)
  const resource = s.slice(i + 1).split('/')
  if (!actions.isValid(action)) {
    throw badRequest(`bad permission "${text}": unknown action "${action}" (known: ${['*', ...actions.declared, TURNKEY].join(', ')})`)
  }
  for (const seg of resource) {
    if (!SEGMENT_RE.test(seg)) throw badRequest(`bad permission "${text}": resource segment "${seg}" is empty or has a space, ":" or a partial "*"`)
  }
  if (action === TURNKEY && (resource.length !== 1 || !TURNKEY_RESOURCES.has(resource[0]!))) {
    throw badRequest(`bad permission "${text}": Turnkey's own permissions are turnkey:manage and turnkey:issue`)
  }
  // `x/*` at the end adds nothing over `x` under hierarchical matching, except that it no longer
  // covers `x` itself. Keep it as written; only a lone `*` means everything.
  return { action, resource }
}

export const formatPermission = (p: Permission) => `${p.action}:${p.resource.join('/')}`

/** Whether `a` allows everything `b` allows. `turnkey:manage` includes `turnkey:issue`. */
export function covers(a: Permission, b: Permission, actions: Actions): boolean {
  if ((a.action === TURNKEY || a.action === '*') && b.action === TURNKEY && a.resource.length === 1 && a.resource[0] === 'manage' && b.resource[0] === 'issue') return true
  if (!actions.allows(a.action, b.action)) return false
  if (a.resource.length === 1 && a.resource[0] === '*') return true
  if (a.resource.length > b.resource.length) return false
  return a.resource.every((seg, i) => seg === '*' || seg === b.resource[i])
}

/** Parse, de-duplicate and sort: the canonical form that is stored and returned. */
export function canonical(list: readonly string[], actions: Actions): string[] {
  return [...new Set(list.map((g) => formatPermission(parsePermission(g, actions))))].sort()
}

/** Whether any of `held` covers `wanted`. */
export function anyCovers(held: readonly Permission[], wanted: Permission, actions: Actions): boolean {
  return held.some((h) => covers(h, wanted, actions))
}
