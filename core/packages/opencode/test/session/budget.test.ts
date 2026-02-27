import { describe, expect, test, beforeEach } from "bun:test"
import { Budget } from "../../src/session/budget"

describe("Slice C: Budget tracker", () => {
  let state: Budget.State

  beforeEach(() => {
    state = Budget.create({
      maxToolCalls: 10,
      maxTokens: 50000,
      timeoutMs: 60000,
    })
  })

  describe("creation", () => {
    test("initializes with zero counters", () => {
      expect(state.toolCalls).toBe(0)
      expect(state.totalTokens).toBe(0)
      expect(state.startTime).toBeGreaterThan(0)
    })

    test("stores limits correctly", () => {
      expect(state.limits.maxToolCalls).toBe(10)
      expect(state.limits.maxTokens).toBe(50000)
      expect(state.limits.timeoutMs).toBe(60000)
    })
  })

  describe("tool call tracking", () => {
    test("increments tool call count", () => {
      Budget.recordToolCall(state)
      expect(state.toolCalls).toBe(1)
      Budget.recordToolCall(state)
      Budget.recordToolCall(state)
      expect(state.toolCalls).toBe(3)
    })

    test("check returns undefined when within budget", () => {
      Budget.recordToolCall(state)
      expect(Budget.check(state)).toBeUndefined()
    })

    test("check returns violation when tool calls exceed limit", () => {
      for (let i = 0; i < 10; i++) {
        Budget.recordToolCall(state)
      }
      const violation = Budget.check(state)
      expect(violation).toBeDefined()
      expect(violation).toContain("Tool call budget exceeded")
      expect(violation).toContain("10/10")
    })
  })

  describe("token tracking", () => {
    test("increments token count", () => {
      Budget.recordTokens(state, 1000)
      expect(state.totalTokens).toBe(1000)
      Budget.recordTokens(state, 2000)
      expect(state.totalTokens).toBe(3000)
    })

    test("check returns violation when tokens exceed limit", () => {
      Budget.recordTokens(state, 50001)
      const violation = Budget.check(state)
      expect(violation).toBeDefined()
      expect(violation).toContain("Token budget exceeded")
    })
  })

  describe("timeout tracking", () => {
    test("check returns undefined when within timeout", () => {
      expect(Budget.check(state)).toBeUndefined()
    })

    test("check returns violation when timeout exceeded", () => {
      // Simulate old start time
      state.startTime = Date.now() - 70000
      const violation = Budget.check(state)
      expect(violation).toBeDefined()
      expect(violation).toContain("Timeout budget exceeded")
    })
  })

  describe("summary", () => {
    test("returns current usage stats", () => {
      Budget.recordToolCall(state)
      Budget.recordToolCall(state)
      Budget.recordTokens(state, 5000)
      const s = Budget.summary(state)
      expect(s.toolCalls).toBe(2)
      expect(s.totalTokens).toBe(5000)
      expect(s.maxToolCalls).toBe(10)
      expect(s.maxTokens).toBe(50000)
      expect(s.timeoutMs).toBe(60000)
      expect(typeof s.elapsedMs).toBe("number")
    })
  })

  describe("no limits", () => {
    test("unlimited budget never triggers violation", () => {
      const unlimited = Budget.create({})
      for (let i = 0; i < 1000; i++) {
        Budget.recordToolCall(unlimited)
      }
      Budget.recordTokens(unlimited, 999999)
      expect(Budget.check(unlimited)).toBeUndefined()
    })
  })

  describe("fromAgent", () => {
    test("returns undefined when agent has no budget", () => {
      const result = Budget.fromAgent({ budget: undefined } as any)
      expect(result).toBeUndefined()
    })

    test("creates state from agent budget", () => {
      const result = Budget.fromAgent({
        budget: { maxToolCalls: 50, timeoutMs: 300000 },
      } as any)
      expect(result).toBeDefined()
      expect(result!.limits.maxToolCalls).toBe(50)
      expect(result!.limits.timeoutMs).toBe(300000)
      expect(result!.limits.maxTokens).toBeUndefined()
    })
  })
})
