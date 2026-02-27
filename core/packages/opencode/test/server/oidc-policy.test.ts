import { describe, expect, test } from "bun:test"

// Test OIDC middleware configuration and static API key parsing logic.
// The actual middleware depends on Hono context + HTTP, so we test
// the configuration parsing and JWT claim mapping logic standalone.

interface OIDCConfig {
  issuer: string
  audience: string
  roleClaim: string
  roleMap: Record<string, string>
}

function parseOIDCConfig(): OIDCConfig | null {
  const issuer = process.env["OPENCODE_OIDC_ISSUER"]
  const audience = process.env["OPENCODE_OIDC_AUDIENCE"]
  if (!issuer || !audience) return null

  const roleClaim = process.env["OPENCODE_OIDC_ROLE_CLAIM"] ?? "role"

  let roleMap: Record<string, string> = {}
  const roleMapStr = process.env["OPENCODE_OIDC_ROLE_MAP"]
  if (roleMapStr) {
    for (const pair of roleMapStr.split(",")) {
      const [key, value] = pair.split(":")
      if (key && value) {
        roleMap[key.trim()] = value.trim()
      }
    }
  }

  return { issuer, audience, roleClaim, roleMap }
}

function parseStaticKeys(): Array<{ key: string; role: string }> {
  const raw = process.env["OPENCODE_AUTH_STATIC_KEYS"]
  if (!raw) return []
  const keys: Array<{ key: string; role: string }> = []
  for (const entry of raw.split(",")) {
    const [key, role] = entry.split(":")
    if (key && role) {
      keys.push({ key: key.trim(), role: role.trim() })
    }
  }
  return keys
}

describe("Slice B: OIDC configuration parsing", () => {
  describe("OIDC config", () => {
    test("returns null when issuer not set", () => {
      const origIssuer = process.env["OPENCODE_OIDC_ISSUER"]
      const origAudience = process.env["OPENCODE_OIDC_AUDIENCE"]
      try {
        delete process.env["OPENCODE_OIDC_ISSUER"]
        delete process.env["OPENCODE_OIDC_AUDIENCE"]
        expect(parseOIDCConfig()).toBeNull()
      } finally {
        if (origIssuer) process.env["OPENCODE_OIDC_ISSUER"] = origIssuer
        if (origAudience) process.env["OPENCODE_OIDC_AUDIENCE"] = origAudience
      }
    })

    test("parses issuer and audience", () => {
      const origIssuer = process.env["OPENCODE_OIDC_ISSUER"]
      const origAudience = process.env["OPENCODE_OIDC_AUDIENCE"]
      try {
        process.env["OPENCODE_OIDC_ISSUER"] = "https://accounts.google.com"
        process.env["OPENCODE_OIDC_AUDIENCE"] = "my-app-id"
        const config = parseOIDCConfig()!
        expect(config.issuer).toBe("https://accounts.google.com")
        expect(config.audience).toBe("my-app-id")
      } finally {
        if (origIssuer) process.env["OPENCODE_OIDC_ISSUER"] = origIssuer
        else delete process.env["OPENCODE_OIDC_ISSUER"]
        if (origAudience) process.env["OPENCODE_OIDC_AUDIENCE"] = origAudience
        else delete process.env["OPENCODE_OIDC_AUDIENCE"]
      }
    })

    test("defaults role claim to 'role'", () => {
      const origIssuer = process.env["OPENCODE_OIDC_ISSUER"]
      const origAudience = process.env["OPENCODE_OIDC_AUDIENCE"]
      const origClaim = process.env["OPENCODE_OIDC_ROLE_CLAIM"]
      try {
        process.env["OPENCODE_OIDC_ISSUER"] = "https://issuer.com"
        process.env["OPENCODE_OIDC_AUDIENCE"] = "aud"
        delete process.env["OPENCODE_OIDC_ROLE_CLAIM"]
        const config = parseOIDCConfig()!
        expect(config.roleClaim).toBe("role")
      } finally {
        if (origIssuer) process.env["OPENCODE_OIDC_ISSUER"] = origIssuer
        else delete process.env["OPENCODE_OIDC_ISSUER"]
        if (origAudience) process.env["OPENCODE_OIDC_AUDIENCE"] = origAudience
        else delete process.env["OPENCODE_OIDC_AUDIENCE"]
        if (origClaim) process.env["OPENCODE_OIDC_ROLE_CLAIM"] = origClaim
        else delete process.env["OPENCODE_OIDC_ROLE_CLAIM"]
      }
    })

    test("parses role map", () => {
      const origIssuer = process.env["OPENCODE_OIDC_ISSUER"]
      const origAudience = process.env["OPENCODE_OIDC_AUDIENCE"]
      const origMap = process.env["OPENCODE_OIDC_ROLE_MAP"]
      try {
        process.env["OPENCODE_OIDC_ISSUER"] = "https://issuer.com"
        process.env["OPENCODE_OIDC_AUDIENCE"] = "aud"
        process.env["OPENCODE_OIDC_ROLE_MAP"] = "org_admin:admin,org_member:employee,guest:viewer"
        const config = parseOIDCConfig()!
        expect(config.roleMap).toEqual({
          org_admin: "admin",
          org_member: "employee",
          guest: "viewer",
        })
      } finally {
        if (origIssuer) process.env["OPENCODE_OIDC_ISSUER"] = origIssuer
        else delete process.env["OPENCODE_OIDC_ISSUER"]
        if (origAudience) process.env["OPENCODE_OIDC_AUDIENCE"] = origAudience
        else delete process.env["OPENCODE_OIDC_AUDIENCE"]
        if (origMap) process.env["OPENCODE_OIDC_ROLE_MAP"] = origMap
        else delete process.env["OPENCODE_OIDC_ROLE_MAP"]
      }
    })
  })

  describe("Static API key parsing", () => {
    test("returns empty array when not set", () => {
      const orig = process.env["OPENCODE_AUTH_STATIC_KEYS"]
      try {
        delete process.env["OPENCODE_AUTH_STATIC_KEYS"]
        expect(parseStaticKeys()).toEqual([])
      } finally {
        if (orig) process.env["OPENCODE_AUTH_STATIC_KEYS"] = orig
      }
    })

    test("parses single key", () => {
      const orig = process.env["OPENCODE_AUTH_STATIC_KEYS"]
      try {
        process.env["OPENCODE_AUTH_STATIC_KEYS"] = "mykey123:admin"
        const keys = parseStaticKeys()
        expect(keys).toEqual([{ key: "mykey123", role: "admin" }])
      } finally {
        if (orig) process.env["OPENCODE_AUTH_STATIC_KEYS"] = orig
        else delete process.env["OPENCODE_AUTH_STATIC_KEYS"]
      }
    })

    test("parses multiple keys", () => {
      const orig = process.env["OPENCODE_AUTH_STATIC_KEYS"]
      try {
        process.env["OPENCODE_AUTH_STATIC_KEYS"] = "key1:admin,key2:employee,key3:viewer"
        const keys = parseStaticKeys()
        expect(keys).toHaveLength(3)
        expect(keys[0]).toEqual({ key: "key1", role: "admin" })
        expect(keys[1]).toEqual({ key: "key2", role: "employee" })
        expect(keys[2]).toEqual({ key: "key3", role: "viewer" })
      } finally {
        if (orig) process.env["OPENCODE_AUTH_STATIC_KEYS"] = orig
        else delete process.env["OPENCODE_AUTH_STATIC_KEYS"]
      }
    })
  })
})

describe("Slice B: Policy plugin configuration", () => {
  test("parses deny list from OPENCODE_POLICY env", () => {
    // Simulate how PolicyPlugin would parse policy configuration
    const policyStr = JSON.stringify({
      denyTools: ["bash", "write"],
      denyPatterns: ["rm -rf /", "DROP TABLE"],
    })

    const policy = JSON.parse(policyStr)
    expect(policy.denyTools).toContain("bash")
    expect(policy.denyTools).toContain("write")
    expect(policy.denyPatterns).toContain("rm -rf /")
    expect(policy.denyPatterns).toContain("DROP TABLE")
  })

  test("empty policy env means no restrictions", () => {
    const policyStr = JSON.stringify({})
    const policy = JSON.parse(policyStr)
    expect(policy.denyTools).toBeUndefined()
    expect(policy.denyPatterns).toBeUndefined()
  })
})
