import { describe, expect, test } from "bun:test"

// We test the redaction logic directly since the plugin depends on
// runtime context (Audit, RBAC) that's hard to set up in isolation.
// Extract the same patterns the plugin uses and test them.

interface SecretPattern {
  name: string
  regex: RegExp
  group?: number
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS Access Key",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
  },
  {
    name: "AWS Secret Key",
    regex: /(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    group: 1,
  },
  {
    name: "GitHub Token",
    regex: /\b(gh[ps]_[A-Za-z0-9_]{36,255})\b/g,
  },
  {
    name: "GitHub Fine-Grained Token",
    regex: /\b(github_pat_[A-Za-z0-9_]{22,255})\b/g,
  },
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
  {
    name: "Private Key",
    regex: /-----BEGIN\s+(RSA |EC |ED25519 |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA |EC |ED25519 |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    name: "Database URL",
    regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"]+:[^\s'"@]+@[^\s'"]+/gi,
  },
  {
    name: "Slack Token",
    regex: /\b(xox[bpras]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b/g,
  },
  {
    name: "Stripe Key",
    regex: /\b([sr]k_(?:live|test)_[A-Za-z0-9]{20,})\b/g,
  },
  {
    name: "Env Secret",
    regex: /^(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY|DATABASE_URL|DB_PASSWORD|JWT_SECRET|ENCRYPTION_KEY)[_A-Z0-9]*\s*=\s*['"]?(.+?)['"]?$/gim,
    group: 1,
  },
]

function redactSecrets(text: string): { redacted: string; findings: Array<{ type: string; offset: number }> } {
  const findings: Array<{ type: string; offset: number }> = []
  let result = text

  for (const pattern of SECRET_PATTERNS) {
    pattern.regex.lastIndex = 0
    result = result.replace(pattern.regex, (...args) => {
      const fullMatch = args[0]
      const offset = args[args.length - 2] as number
      findings.push({ type: pattern.name, offset })
      if (pattern.group !== undefined) {
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

describe("Slice D: Secret scanning & redaction", () => {
  describe("AWS credentials", () => {
    test("detects and redacts AWS access key", () => {
      const input = "Found key: AKIAIOSFODNN7EXAMPLE"
      const { redacted, findings } = redactSecrets(input)
      expect(findings.length).toBe(1)
      expect(findings[0].type).toBe("AWS Access Key")
      expect(redacted).toContain("[REDACTED:AWS Access Key]")
      expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE")
    })

    test("detects AWS secret key in config format", () => {
      const input = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
      const { redacted, findings } = redactSecrets(input)
      expect(findings.length).toBe(1)
      expect(findings[0].type).toBe("AWS Secret Key")
      expect(redacted).toContain("[REDACTED:AWS Secret Key]")
    })
  })

  describe("GitHub tokens", () => {
    test("detects GitHub personal access token", () => {
      const token = "ghp_" + "A".repeat(36)
      const input = `Authorization: token ${token}`
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "GitHub Token")).toBe(true)
      expect(redacted).not.toContain(token)
    })

    test("detects GitHub fine-grained token", () => {
      const token = "github_pat_" + "A".repeat(22)
      const input = `GITHUB_TOKEN=${token}`
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "GitHub Fine-Grained Token")).toBe(true)
      expect(redacted).not.toContain(token)
    })
  })

  describe("Bearer tokens", () => {
    test("detects Bearer token in header", () => {
      const input = "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Bearer Token")).toBe(true)
      expect(redacted).toContain("[REDACTED:Bearer Token]")
    })
  })

  describe("Private keys", () => {
    test("detects RSA private key", () => {
      const input = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5AHAuSJ7FkRz
-----END RSA PRIVATE KEY-----`
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Private Key")).toBe(true)
      expect(redacted).toContain("[REDACTED:Private Key]")
      expect(redacted).not.toContain("MIIEpAIBAAKCAQEA")
    })
  })

  describe("Database URLs", () => {
    test("detects postgres connection string", () => {
      const input = "DATABASE_URL=postgresql://admin:secretpass@db.example.com:5432/mydb"
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Database URL")).toBe(true)
      expect(redacted).not.toContain("secretpass")
    })

    test("detects MongoDB connection string", () => {
      const input = "mongodb+srv://user:pass123@cluster0.mongodb.net/mydb"
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Database URL")).toBe(true)
    })
  })

  describe("Stripe keys", () => {
    test("detects Stripe secret key", () => {
      const key = "sk_live_" + "A".repeat(24)
      // Use input that doesn't trigger the Generic API Key pattern first
      const input = `STRIPE_SECRET=${key}`
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Stripe Key")).toBe(true)
      expect(redacted).not.toContain(key)
    })
  })

  describe("Env file patterns", () => {
    test("detects SECRET in env file", () => {
      const input = `SECRET_KEY=mysupersecretvalue123`
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Env Secret")).toBe(true)
      expect(redacted).not.toContain("mysupersecretvalue123")
    })

    test("detects PASSWORD in env file", () => {
      const input = `PASSWORD=hunter2`
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Env Secret")).toBe(true)
    })

    test("detects JWT_SECRET in env file", () => {
      const input = `JWT_SECRET=abc123def456ghi789`
      const { redacted, findings } = redactSecrets(input)
      expect(findings.some((f) => f.type === "Env Secret")).toBe(true)
    })
  })

  describe("No false positives", () => {
    test("does not redact normal code", () => {
      const input = `const x = 42;\nfunction hello() { return "world"; }\nconsole.log(process.env.NODE_ENV);`
      const { findings } = redactSecrets(input)
      expect(findings.length).toBe(0)
    })

    test("does not redact normal git output", () => {
      const input = `commit a1b2c3d4e5f6\nAuthor: John Doe <john@example.com>\nDate:   Mon Jan 1 00:00:00 2026 +0000`
      const { findings } = redactSecrets(input)
      expect(findings.length).toBe(0)
    })
  })

  describe("Multiple secrets in one output", () => {
    test("redacts all secrets found", () => {
      const input = [
        "AKIAIOSFODNN7EXAMPLE",
        "api_key = supersecretapikey1234567890",
        "PASSWORD=hunter2",
      ].join("\n")
      const { redacted, findings } = redactSecrets(input)
      expect(findings.length).toBeGreaterThanOrEqual(2)
      expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE")
    })
  })
})
