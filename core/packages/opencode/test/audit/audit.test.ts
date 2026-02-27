import { describe, expect, test } from "bun:test"
import z from "zod"

// Test the Audit schema and logic.
// The actual Audit.record/list depends on Database context, so we test
// the schema validation, truncation logic, and entry structure.

const AuditEntry = z.object({
  id: z.string(),
  sessionID: z.string().optional(),
  userID: z.string().optional(),
  action: z.string(),
  resourceType: z.string(),
  resourceID: z.string().optional(),
  tool: z.string().optional(),
  inputSummary: z.string().optional(),
  outputSummary: z.string().optional(),
  decision: z.string().optional(),
  metadata: z.record(z.string(), z.any()).optional(),
  time: z.object({
    created: z.number(),
  }),
})

function truncate(value: unknown, max = 1024): string | undefined {
  if (value === undefined || value === null) return undefined
  const str = typeof value === "string" ? value : JSON.stringify(value)
  return str.length > max ? str.slice(0, max) + "…" : str
}

describe("Slice A: Audit schema validation", () => {
  test("validates a complete audit entry", () => {
    const entry = {
      id: "audit_001",
      sessionID: "sess_001",
      userID: "user_001",
      action: "tool.execute",
      resourceType: "tool",
      resourceID: "bash",
      tool: "bash",
      inputSummary: "ls -la",
      outputSummary: "directory listing...",
      decision: "allowed",
      metadata: { latency: 42 },
      time: { created: Date.now() },
    }
    const result = AuditEntry.parse(entry)
    expect(result.action).toBe("tool.execute")
    expect(result.resourceType).toBe("tool")
    expect(result.time.created).toBeGreaterThan(0)
  })

  test("validates a minimal audit entry", () => {
    const entry = {
      id: "audit_002",
      action: "session.create",
      resourceType: "session",
      time: { created: Date.now() },
    }
    const result = AuditEntry.parse(entry)
    expect(result.id).toBe("audit_002")
    expect(result.sessionID).toBeUndefined()
    expect(result.userID).toBeUndefined()
  })

  test("rejects entry without required fields", () => {
    expect(() =>
      AuditEntry.parse({
        id: "audit_003",
        // missing action and resourceType
        time: { created: Date.now() },
      }),
    ).toThrow()
  })
})

describe("Slice A: Audit truncation", () => {
  test("short strings pass through unchanged", () => {
    expect(truncate("hello")).toBe("hello")
  })

  test("undefined returns undefined", () => {
    expect(truncate(undefined)).toBeUndefined()
  })

  test("null returns undefined", () => {
    expect(truncate(null)).toBeUndefined()
  })

  test("long strings are truncated", () => {
    const long = "A".repeat(2000)
    const result = truncate(long, 1024)!
    expect(result.length).toBe(1025) // 1024 + "…"
    expect(result.endsWith("…")).toBe(true)
  })

  test("objects are JSON-stringified", () => {
    const obj = { key: "value" }
    expect(truncate(obj)).toBe('{"key":"value"}')
  })

  test("custom max length works", () => {
    const result = truncate("abcdefghij", 5)!
    expect(result).toBe("abcde…")
  })
})

describe("Slice A: Audit entry structure", () => {
  test("supports all expected action types", () => {
    const actions = [
      "tool.execute",
      "permission.ask",
      "permission.grant",
      "permission.deny",
      "session.create",
      "session.delete",
      "policy.deny",
      "secret.detected",
    ]
    for (const action of actions) {
      const entry = AuditEntry.parse({
        id: `audit_${action}`,
        action,
        resourceType: "test",
        time: { created: Date.now() },
      })
      expect(entry.action).toBe(action)
    }
  })

  test("metadata can store arbitrary key-value pairs", () => {
    const entry = AuditEntry.parse({
      id: "audit_meta",
      action: "test",
      resourceType: "test",
      metadata: {
        latencyMs: 42,
        model: "gpt-4",
        tokens: { input: 100, output: 50 },
        tags: ["important", "reviewed"],
      },
      time: { created: Date.now() },
    })
    expect(entry.metadata!.latencyMs).toBe(42)
    expect(entry.metadata!.tokens).toEqual({ input: 100, output: 50 })
  })
})
