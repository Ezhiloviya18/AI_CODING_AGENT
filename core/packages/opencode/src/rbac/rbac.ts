import z from "zod"
import { Log } from "../util/log"
import { Context } from "../util/context"

export namespace RBAC {
  const log = Log.create({ service: "rbac" })

  // ── Role hierarchy ─────────────────────────────────────────────────
  export const Role = z.enum(["viewer", "employee", "admin"]).meta({
    ref: "Role",
  })
  export type Role = z.infer<typeof Role>

  const HIERARCHY: Record<Role, number> = {
    viewer: 0,
    employee: 1,
    admin: 2,
  }

  // ── User identity (populated by auth middleware) ───────────────────
  export const User = z
    .object({
      id: z.string(),
      email: z.string().optional(),
      name: z.string().optional(),
      role: Role,
    })
    .meta({ ref: "User" })
  export type User = z.infer<typeof User>

  // ── Context for per-request user identity ──────────────────────────
  const userContext = Context.create<User>("rbac.user")

  export function provide<R>(user: User, fn: () => R): R {
    return userContext.provide(user, fn)
  }

  export function current(): User | undefined {
    try {
      return userContext.use()
    } catch {
      return undefined
    }
  }

  // ── Permission checks ──────────────────────────────────────────────
  export function hasRole(user: User, required: Role): boolean {
    return HIERARCHY[user.role] >= HIERARCHY[required]
  }

  export function assertRole(required: Role) {
    const user = current()
    if (!user) throw new AuthRequiredError()
    if (!hasRole(user, required)) throw new ForbiddenError(user.role, required)
  }

  // ── Capability-based permissions ───────────────────────────────────
  // Maps capabilities to the minimum role required
  const CAPABILITIES: Record<string, Role> = {
    // Session operations
    "session.create": "employee",
    "session.read": "viewer",
    "session.delete": "admin",

    // Audit operations
    "audit.read": "admin",

    // Config operations
    "config.read": "viewer",
    "config.write": "admin",

    // Tool operations – default is employee, but
    // specific tools can be overridden
    "tool.bash": "employee",
    "tool.write": "employee",
    "tool.edit": "employee",
    "tool.read": "viewer",
    "tool.grep": "viewer",
    "tool.glob": "viewer",
    "tool.list": "viewer",
    "tool.task": "employee",
    "tool.webfetch": "employee",
    "tool.websearch": "employee",

    // Provider / model operations
    "provider.read": "viewer",
    "provider.auth": "admin",

    // MCP operations
    "mcp.read": "viewer",
    "mcp.write": "admin",
  }

  export function can(capability: string): boolean {
    const user = current()
    if (!user) return false
    const required = CAPABILITIES[capability] ?? "employee"
    return hasRole(user, required)
  }

  export function assertCan(capability: string) {
    const user = current()
    if (!user) throw new AuthRequiredError()
    const required = CAPABILITIES[capability] ?? "employee"
    if (!hasRole(user, required)) {
      throw new ForbiddenError(user.role, required, capability)
    }
  }

  // ── Errors ─────────────────────────────────────────────────────────
  export class AuthRequiredError extends Error {
    constructor() {
      super("Authentication required")
    }
  }

  export class ForbiddenError extends Error {
    constructor(
      public readonly currentRole: Role,
      public readonly requiredRole: Role,
      public readonly capability?: string,
    ) {
      super(
        capability
          ? `Role '${currentRole}' cannot perform '${capability}' (requires '${requiredRole}')`
          : `Role '${currentRole}' insufficient (requires '${requiredRole}')`,
      )
    }
  }
}
