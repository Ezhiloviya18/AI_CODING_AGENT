import { Log } from "@/util/log"
import type { Agent } from "@/agent/agent"

const log = Log.create({ service: "budget" })

/**
 * Budget tracker for subagent sessions. Enforces limits on tool calls,
 * tokens consumed, and wall-clock time per session.
 *
 * The budget is configured on Agent.Info.budget and checked after each
 * tool call or LLM step in the processor loop.
 */
export namespace Budget {
  export interface Limits {
    maxToolCalls?: number
    maxTokens?: number
    timeoutMs?: number
  }

  export interface State {
    toolCalls: number
    totalTokens: number
    startTime: number
    limits: Limits
  }

  export function create(limits: Limits): State {
    return {
      toolCalls: 0,
      totalTokens: 0,
      startTime: Date.now(),
      limits,
    }
  }

  export function fromAgent(agent: Agent.Info): State | undefined {
    if (!agent.budget) return undefined
    return create({
      maxToolCalls: agent.budget.maxToolCalls,
      maxTokens: agent.budget.maxTokens,
      timeoutMs: agent.budget.timeoutMs,
    })
  }

  export function recordToolCall(state: State): void {
    state.toolCalls++
  }

  export function recordTokens(state: State, tokens: number): void {
    state.totalTokens += tokens
  }

  /**
   * Check whether a budget limit has been exceeded.
   * Returns a string describing the violation, or undefined if within budget.
   */
  export function check(state: State): string | undefined {
    if (state.limits.maxToolCalls && state.toolCalls >= state.limits.maxToolCalls) {
      const msg = `Tool call budget exceeded: ${state.toolCalls}/${state.limits.maxToolCalls}`
      log.warn(msg)
      return msg
    }

    if (state.limits.maxTokens && state.totalTokens >= state.limits.maxTokens) {
      const msg = `Token budget exceeded: ${state.totalTokens}/${state.limits.maxTokens}`
      log.warn(msg)
      return msg
    }

    if (state.limits.timeoutMs) {
      const elapsed = Date.now() - state.startTime
      if (elapsed >= state.limits.timeoutMs) {
        const msg = `Timeout budget exceeded: ${elapsed}ms/${state.limits.timeoutMs}ms`
        log.warn(msg)
        return msg
      }
    }

    return undefined
  }

  /**
   * Get a summary of current budget usage.
   */
  export function summary(state: State): Record<string, string | number> {
    const result: Record<string, string | number> = {
      toolCalls: state.toolCalls,
      totalTokens: state.totalTokens,
      elapsedMs: Date.now() - state.startTime,
    }
    if (state.limits.maxToolCalls) result.maxToolCalls = state.limits.maxToolCalls
    if (state.limits.maxTokens) result.maxTokens = state.limits.maxTokens
    if (state.limits.timeoutMs) result.timeoutMs = state.limits.timeoutMs
    return result
  }
}
