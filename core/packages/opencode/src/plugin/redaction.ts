import type { Hooks, PluginInput } from "@opencode-ai/plugin"
import { Log } from "../util/log"
import { Audit } from "../audit"
import { RBAC } from "../rbac"

const log = Log.create({ service: "plugin.redaction" })

/**
 * Secret patterns to detect and redact in tool output.
 * Each pattern includes a regex, the type label, and optional
 * group index for the actual secret portion.
 */
interface SecretPattern {
  name: string
  regex: RegExp
  /** Which capture group contains the secret value (default: 0 = full match) */
  group?: number
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  {
    name: "AWS Access Key",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
  },
  {
    name: "AWS Secret Key",
    regex: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    group: 1,
  },
  // GitHub
  {
    name: "GitHub Token",
    regex: /\b(gh[ps]_[A-Za-z0-9_]{36,255})\b/g,
  },
  {
    name: "GitHub Fine-Grained Token",
    regex: /\b(github_pat_[A-Za-z0-9_]{22,255})\b/g,
  },
  // Generic API keys and tokens
  {
    name: "Bearer Token",
    regex: /Bearer\s+([A-Za-z0-9\-._~+/]+=*)/gi,
    group: 1,
  },
  {
    name: "Generic API Key",
    regex: /(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token)\s*[=:]\s*['"]?([A-Za-z0-9\-._~+/]{20,})/gi,
    group: 1,
  },
  // Private keys
  {
    name: "Private Key",
    regex: /-----BEGIN\s+(RSA |EC |ED25519 |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA |EC |ED25519 |OPENSSH )?PRIVATE KEY-----/g,
  },
  // Database connection strings
  {
    name: "Database URL",
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"]+:[^\s'"@]+@[^\s'"]+/gi,
  },
  // Slack tokens
  {
    name: "Slack Token",
    regex: /\b(xox[bpras]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b/g,
  },
  // Stripe
  {
    name: "Stripe Key",
    regex: /\b([sr]k_(?:live|test)_[A-Za-z0-9]{20,})\b/g,
  },
  // OpenAI / Anthropic
  {
    name: "OpenAI API Key",
    regex: /\b(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})\b/g,
  },
  {
    name: "Anthropic API Key",
    regex: /\b(sk-ant-[A-Za-z0-9\-]{20,})\b/g,
  },
  // .env file format
  {
    name: "Env Secret",
    regex: /^(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY|DATABASE_URL|DB_PASSWORD|JWT_SECRET|ENCRYPTION_KEY)[_A-Z0-9]*\s*=\s*['"]?(.+?)['"]?$/gim,
    group: 1,
  },
]

/**
 * Redacts detected secrets from text, replacing them with [REDACTED:<type>]
 */
function redactSecrets(text: string): { redacted: string; findings: Array<{ type: string; offset: number }> } {
  const findings: Array<{ type: string; offset: number }> = []
  let result = text

  for (const pattern of SECRET_PATTERNS) {
    // Reset lastIndex for global regex
    pattern.regex.lastIndex = 0

    result = result.replace(pattern.regex, (...args) => {
      const fullMatch = args[0]
      const offset = args[args.length - 2] as number

      findings.push({ type: pattern.name, offset })

      if (pattern.group !== undefined) {
        // Replace only the capture group portion
        const groupValue = args[pattern.group]
        if (groupValue) {
          return fullMatch.replace(groupValue, `[REDACTED:${pattern.name}]`)
        }
      }
      return `[REDACTED:${pattern.name}]`
    })
  }

  return { redacted: result, findings }
}

export async function RedactionPlugin(_input: PluginInput): Promise<Hooks> {
  log.info("redaction plugin loaded")

  return {
    async "tool.execute.after"(input, output) {
      // Skip redaction for admin users (they're trusted)
      const user = RBAC.current()
      if (user?.role === "admin") return

      const { redacted, findings } = redactSecrets(output.output)
      if (findings.length > 0) {
        log.warn("secrets redacted from tool output", {
          tool: input.tool,
          sessionID: input.sessionID,
          callID: input.callID,
          count: findings.length,
          types: findings.map((f) => f.type),
        })

        output.output = redacted

        // Also redact metadata output if present
        if (output.metadata?.output && typeof output.metadata.output === "string") {
          const metaResult = redactSecrets(output.metadata.output)
          output.metadata.output = metaResult.redacted
        }

        // Audit the redaction event
        try {
          await Audit.record({
            sessionID: input.sessionID,
            userID: user?.id,
            action: "secret.redacted",
            resourceType: "tool",
            resourceID: input.callID,
            tool: input.tool,
            metadata: {
              count: findings.length,
              types: [...new Set(findings.map((f) => f.type))],
            },
          })
        } catch (e) {
          log.error("failed to audit redaction", { error: e })
        }
      }
    },
  }
}
