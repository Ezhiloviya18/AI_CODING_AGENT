import type { Hooks, PluginInput } from "@opencode-ai/plugin"
import { Log } from "../util/log"
import { RBAC } from "../rbac"
import { Audit } from "../audit"
import { Config } from "../config/config"

const log = Log.create({ service: "plugin.policy" })

/**
 * Policy configuration loaded from managed config (/etc/opencode/config.json)
 * or project config. This is the shape under `config.policy`.
 *
 * Example managed config:
 * ```json
 * {
 *   "policy": {
 *     "deny_tools": ["bash", "write"],
 *     "viewer_deny_tools": ["bash", "write", "edit", "patch", "task"],
 *     "employee_deny_tools": [],
 *     "deny_patterns": ["rm -rf /", "sudo"],
 *     "require_approval_tools": ["bash"],
 *     "max_tool_calls_per_session": 200
 *   }
 * }
 * ```
 */
export interface PolicyConfig {
  /** Tools denied for ALL roles */
  deny_tools?: string[]
  /** Tools denied for viewers (role: viewer) */
  viewer_deny_tools?: string[]
  /** Tools denied for employees (role: employee) */
  employee_deny_tools?: string[]
  /** Patterns in tool input that should be denied */
  deny_patterns?: string[]
  /** Tools that always require explicit approval regardless of role */
  require_approval_tools?: string[]
  /** Maximum tool calls per session (0 = unlimited) */
  max_tool_calls_per_session?: number
}

function getPolicy(): PolicyConfig {
  // Policy is read from the config system which already handles
  // layered merging: project → global → managed (/etc/opencode)
  // TODO: Add `policy` to the Config.Info schema in config.ts
  // For now, read from env var as a bootstrap mechanism
  const envPolicy = process.env["OPENCODE_POLICY"]
  if (envPolicy) {
    try {
      return JSON.parse(envPolicy)
    } catch {
      log.error("failed to parse OPENCODE_POLICY env var")
    }
  }
  return {}
}

function isToolDenied(toolName: string, role: RBAC.Role, policy: PolicyConfig): string | undefined {
  // Check global deny list
  if (policy.deny_tools?.includes(toolName)) {
    return `Tool "${toolName}" is denied by policy`
  }

  // Check role-specific deny lists
  if (role === "viewer" && policy.viewer_deny_tools?.includes(toolName)) {
    return `Tool "${toolName}" is denied for viewers`
  }

  if (role === "employee" && policy.employee_deny_tools?.includes(toolName)) {
    return `Tool "${toolName}" is denied for employees`
  }

  return undefined
}

function containsDeniedPattern(metadata: Record<string, any>, policy: PolicyConfig): string | undefined {
  if (!policy.deny_patterns?.length) return undefined

  // Check tool input/command for denied patterns
  const input = JSON.stringify(metadata).toLowerCase()
  for (const pattern of policy.deny_patterns) {
    if (input.includes(pattern.toLowerCase())) {
      return `Input contains denied pattern: "${pattern}"`
    }
  }
  return undefined
}

export async function PolicyPlugin(_input: PluginInput): Promise<Hooks> {
  log.info("policy plugin loaded")

  return {
    async "permission.ask"(input, output) {
      const policy = getPolicy()
      const user = RBAC.current()

      // Extract tool name from permission metadata or type
      const toolName = (input.metadata?.tool as string) ?? input.type

      // Check RBAC capability first
      if (user) {
        // Viewers should not be able to execute write tools
        if (user.role === "viewer" && !RBAC.can("tool.execute")) {
          const reason = `Role "${user.role}" cannot execute tools`
          log.info("policy denied", { tool: toolName, user: user.id, reason })
          await auditDeny(input, user, reason)
          output.status = "deny"
          return
        }
      }

      // Check policy deny lists
      const role = user?.role ?? "viewer"
      const denyReason = isToolDenied(toolName, role, policy)
      if (denyReason) {
        log.info("policy denied", { tool: toolName, user: user?.id, reason: denyReason })
        await auditDeny(input, user, denyReason)
        output.status = "deny"
        return
      }

      // Check denied patterns in metadata
      const patternReason = containsDeniedPattern(input.metadata, policy)
      if (patternReason) {
        log.info("policy denied pattern", { tool: toolName, user: user?.id, reason: patternReason })
        await auditDeny(input, user, patternReason)
        output.status = "deny"
        return
      }

      // If tool requires approval, let it propagate to user (status stays "ask")
      if (policy.require_approval_tools?.includes(toolName)) {
        log.info("policy requires approval", { tool: toolName, user: user?.id })
        return
      }

      // Admin role auto-approves everything not explicitly denied
      if (user?.role === "admin") {
        log.info("policy auto-approved (admin)", { tool: toolName, user: user.id })
        output.status = "allow"
        return
      }
    },

    async "tool.execute.before"(input, output) {
      const policy = getPolicy()
      const user = RBAC.current()
      const role = user?.role ?? "viewer"

      // Check deny lists before tool execution
      const denyReason = isToolDenied(input.tool, role, policy)
      if (denyReason) {
        log.warn("tool execution blocked by policy", {
          tool: input.tool,
          user: user?.id,
          reason: denyReason,
        })
        // Signal to caller that tool should not execute
        ;(output as any).__policyDenied = true
        ;(output as any).__policyReason = denyReason
      }
    },
  }
}

async function auditDeny(
  input: { sessionID: string; metadata: Record<string, any>; type: string },
  user: RBAC.User | undefined,
  reason: string,
) {
  try {
    await Audit.record({
      sessionID: input.sessionID,
      userID: user?.id,
      action: "policy.denied",
      resourceType: "tool",
      resourceID: (input.metadata?.tool as string) ?? input.type,
      tool: (input.metadata?.tool as string) ?? input.type,
      decision: "deny",
      metadata: {
        reason,
        role: user?.role,
        permissionType: input.type,
      },
    })
  } catch (e) {
    log.error("failed to audit policy denial", { error: e })
  }
}
