import { Tool } from "./tool"
import z from "zod"
import { Session } from "../session"
import { MessageV2 } from "../session/message-v2"
import { Identifier } from "../id/id"
import { Agent } from "../agent/agent"
import { SessionPrompt } from "../session/prompt"
import { iife } from "@/util/iife"
import { defer } from "@/util/defer"
import { Config } from "../config/config"
import { PermissionNext } from "@/permission/next"
import { Log } from "@/util/log"

const log = Log.create({ service: "parallel-task" })

const MAX_CONCURRENT = 5

const parameters = z.object({
  tasks: z
    .array(
      z.object({
        description: z.string().describe("A short (3-5 words) description of the task"),
        prompt: z.string().describe("The task for the agent to perform"),
        subagent_type: z.string().describe("The type of specialized agent to use for this task"),
      }),
    )
    .min(1)
    .max(MAX_CONCURRENT)
    .describe("Array of tasks to execute in parallel (max 5)"),
})

const DESCRIPTION = `Launch multiple subagent tasks in parallel. Use this when you have independent work items that can be done concurrently - for example, researching multiple files, running independent searches, or performing read-only analysis across different parts of the codebase.

GUIDELINES:
- Maximum ${MAX_CONCURRENT} parallel tasks
- Each task runs as an independent subagent session
- Tasks should be independent - avoid tasks that depend on each other's output
- Best for read-heavy operations: searching, reading, analyzing
- Write operations may conflict - prefer sequential execution for writes
- All tasks share the same timeout budget`

export const ParallelTaskTool = Tool.define("parallel_task", async (ctx) => {
  const agents = await Agent.list().then((x) => x.filter((a) => a.mode !== "primary"))

  const caller = ctx?.agent
  const accessibleAgents = caller
    ? agents.filter((a) => PermissionNext.evaluate("task", a.name, caller.permission).action !== "deny")
    : agents

  const description =
    DESCRIPTION +
    "\n\nAvailable agents:\n" +
    accessibleAgents
      .map((a) => `- ${a.name}: ${a.description ?? "This subagent should only be called manually by the user."}`)
      .join("\n")

  return {
    description,
    parameters,
    async execute(params: z.infer<typeof parameters>, ctx) {
      const config = await Config.get()

      // Ask permission for parallel task execution
      await ctx.ask({
        permission: "task",
        patterns: params.tasks.map((t) => t.subagent_type),
        always: ["*"],
        metadata: {
          description: `Parallel: ${params.tasks.map((t) => t.description).join(", ")}`,
          subagent_types: params.tasks.map((t) => t.subagent_type),
          count: params.tasks.length,
        },
      })

      // Resolve all agents upfront
      const resolvedAgents = await Promise.all(
        params.tasks.map(async (t) => {
          const agent = await Agent.get(t.subagent_type)
          if (!agent) throw new Error(`Unknown agent type: ${t.subagent_type}`)
          return agent
        }),
      )

      // Get parent message info for model resolution
      const msg = await MessageV2.get({ sessionID: ctx.sessionID, messageID: ctx.messageID })
      if (msg.info.role !== "assistant") throw new Error("Not an assistant message")
      const parentModel = {
        modelID: msg.info.modelID,
        providerID: msg.info.providerID,
      }

      // Create sessions and launch in parallel
      const results = await Promise.allSettled(
        params.tasks.map(async (task, idx) => {
          const agent = resolvedAgents[idx]
          const hasTaskPermission = agent.permission.some((rule) => rule.permission === "task")

          const session = await Session.create({
            parentID: ctx.sessionID,
            title: task.description + ` (@${agent.name} subagent)`,
            permission: [
              {
                permission: "todowrite",
                pattern: "*",
                action: "deny",
              },
              {
                permission: "todoread",
                pattern: "*",
                action: "deny",
              },
              ...(hasTaskPermission
                ? []
                : [
                    {
                      permission: "task" as const,
                      pattern: "*" as const,
                      action: "deny" as const,
                    },
                  ]),
              ...(config.experimental?.primary_tools?.map((t) => ({
                pattern: "*",
                action: "allow" as const,
                permission: t,
              })) ?? []),
            ],
          })

          const model = agent.model ?? parentModel

          const messageID = Identifier.ascending("message")

          // Set up abort forwarding
          function cancel() {
            SessionPrompt.cancel(session.id)
          }
          ctx.abort.addEventListener("abort", cancel)

          // Set up timeout from agent budget
          let timeoutTimer: ReturnType<typeof setTimeout> | undefined
          const timeoutMs = agent.budget?.timeoutMs
          if (timeoutMs) {
            timeoutTimer = setTimeout(() => {
              log.warn("subagent timeout", {
                sessionID: session.id,
                agent: agent.name,
                timeoutMs,
              })
              SessionPrompt.cancel(session.id)
            }, timeoutMs)
          }

          try {
            const promptParts = await SessionPrompt.resolvePromptParts(task.prompt)
            const result = await SessionPrompt.prompt({
              messageID,
              sessionID: session.id,
              model: {
                modelID: model.modelID,
                providerID: model.providerID,
              },
              agent: agent.name,
              tools: {
                todowrite: false,
                todoread: false,
                ...(hasTaskPermission ? {} : { task: false }),
                ...Object.fromEntries((config.experimental?.primary_tools ?? []).map((t) => [t, false])),
              },
              parts: promptParts,
            })

            const text = result.parts.findLast((x) => x.type === "text")?.text ?? ""
            return {
              sessionID: session.id,
              description: task.description,
              agent: agent.name,
              text,
            }
          } finally {
            ctx.abort.removeEventListener("abort", cancel)
            if (timeoutTimer) clearTimeout(timeoutTimer)
          }
        }),
      )

      // Collect results
      const output: string[] = [`Parallel execution of ${params.tasks.length} tasks:`]
      const sessionIds: string[] = []

      for (let i = 0; i < results.length; i++) {
        const result = results[i]
        const task = params.tasks[i]
        output.push("")
        output.push(`--- Task ${i + 1}: ${task.description} (@${task.subagent_type}) ---`)

        if (result.status === "fulfilled") {
          sessionIds.push(result.value.sessionID)
          output.push(`task_id: ${result.value.sessionID}`)
          output.push("")
          output.push("<task_result>")
          output.push(result.value.text)
          output.push("</task_result>")
        } else {
          const error = result.reason instanceof Error ? result.reason.message : String(result.reason)
          output.push(`ERROR: ${error}`)
          log.error("parallel task failed", {
            task: task.description,
            agent: task.subagent_type,
            error,
          })
        }
      }

      const succeeded = results.filter((r) => r.status === "fulfilled").length
      const failed = results.filter((r) => r.status === "rejected").length

      return {
        title: `Parallel: ${succeeded}/${params.tasks.length} succeeded${failed > 0 ? `, ${failed} failed` : ""}`,
        metadata: {
          sessionIds,
          tasks: params.tasks.length,
          succeeded,
          failed,
        },
        output: output.join("\n"),
      }
    },
  }
})
