import z from "zod"
import { Log } from "../util/log"
import { Database, desc, eq, and, gte, lte } from "../storage/db"
import { AuditLogTable } from "./audit.sql"
import { Identifier } from "../id/id"
import { Bus } from "../bus"
import { BusEvent } from "../bus/bus-event"
import { Session } from "../session"
import { PermissionNext } from "../permission/next"
import { Instance } from "../project/instance"
import { Scheduler } from "../scheduler"

export namespace Audit {
  const log = Log.create({ service: "audit" })

  // ── Zod schema for external consumers ──────────────────────────────
  export const Entry = z
    .object({
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
    .meta({ ref: "AuditEntry" })
  export type Entry = z.infer<typeof Entry>

  // ── Bus events ─────────────────────────────────────────────────────
  export const Event = {
    Created: BusEvent.define("audit.created", Entry),
  }

  // ── Internal helpers ───────────────────────────────────────────────
  function truncate(value: unknown, max = 1024): string | undefined {
    if (value === undefined || value === null) return undefined
    const str = typeof value === "string" ? value : JSON.stringify(value)
    return str.length > max ? str.slice(0, max) + "…" : str
  }

  // ── Write ──────────────────────────────────────────────────────────
  export async function record(input: {
    sessionID?: string
    userID?: string
    action: string
    resourceType: string
    resourceID?: string
    tool?: string
    inputSummary?: unknown
    outputSummary?: unknown
    decision?: string
    metadata?: Record<string, any>
  }) {
    const id = Identifier.ascending("tool")
    const now = Date.now()
    const entry: Entry = {
      id,
      sessionID: input.sessionID,
      userID: input.userID,
      action: input.action,
      resourceType: input.resourceType,
      resourceID: input.resourceID,
      tool: input.tool,
      inputSummary: truncate(input.inputSummary),
      outputSummary: truncate(input.outputSummary),
      decision: input.decision,
      metadata: input.metadata,
      time: { created: now },
    }
    try {
      Database.use((db) => {
        db.insert(AuditLogTable)
          .values({
            id,
            session_id: input.sessionID,
            user_id: input.userID,
            action: input.action,
            resource_type: input.resourceType,
            resource_id: input.resourceID,
            tool: input.tool,
            input_summary: truncate(input.inputSummary),
            output_summary: truncate(input.outputSummary),
            decision: input.decision,
            metadata: input.metadata ?? {},
            time_created: now,
            time_updated: now,
          })
          .run()
      })
      Bus.publish(Event.Created, entry)
    } catch (e) {
      log.error("failed to write audit log", { error: e })
    }
  }

  // ── Query ──────────────────────────────────────────────────────────
  export async function list(input?: {
    sessionID?: string
    userID?: string
    action?: string
    start?: number
    end?: number
    limit?: number
  }) {
    const conditions = []
    if (input?.sessionID) conditions.push(eq(AuditLogTable.session_id, input.sessionID))
    if (input?.userID) conditions.push(eq(AuditLogTable.user_id, input.userID))
    if (input?.action) conditions.push(eq(AuditLogTable.action, input.action))
    if (input?.start) conditions.push(gte(AuditLogTable.time_created, input.start))
    if (input?.end) conditions.push(lte(AuditLogTable.time_created, input.end))

    const where = conditions.length > 0 ? and(...conditions) : undefined
    const rows = Database.use((db) =>
      db
        .select()
        .from(AuditLogTable)
        .where(where)
        .orderBy(desc(AuditLogTable.time_created))
        .limit(input?.limit ?? 100)
        .all(),
    )
    return rows.map(fromRow)
  }

  function fromRow(row: typeof AuditLogTable.$inferSelect): Entry {
    return {
      id: row.id,
      sessionID: row.session_id ?? undefined,
      userID: row.user_id ?? undefined,
      action: row.action,
      resourceType: row.resource_type,
      resourceID: row.resource_id ?? undefined,
      tool: row.tool ?? undefined,
      inputSummary: row.input_summary ?? undefined,
      outputSummary: row.output_summary ?? undefined,
      decision: row.decision ?? undefined,
      metadata: row.metadata ?? undefined,
      time: { created: row.time_created },
    }
  }

  // ── Bus subscriber: auto-log key events ────────────────────────────
  export function subscribe() {
    log.info("subscribing to bus events for audit logging")

    // Session created
    Bus.subscribe(Session.Event.Created, async (event) => {
      await record({
        sessionID: event.properties.info.id,
        action: "session.created",
        resourceType: "session",
        resourceID: event.properties.info.id,
        metadata: {
          title: event.properties.info.title,
          directory: event.properties.info.directory,
          parentID: event.properties.info.parentID,
        },
      })
    })

    // Permission asked
    Bus.subscribe(PermissionNext.Event.Asked, async (event) => {
      await record({
        sessionID: event.properties.sessionID,
        action: "permission.asked",
        resourceType: "permission",
        resourceID: event.properties.id,
        tool: event.properties.permission,
        decision: "pending",
        metadata: {
          patterns: event.properties.patterns,
          metadata: event.properties.metadata,
        },
      })
    })

    // Permission replied
    Bus.subscribe(PermissionNext.Event.Replied, async (event) => {
      await record({
        sessionID: event.properties.sessionID,
        action: "permission.replied",
        resourceType: "permission",
        resourceID: event.properties.requestID,
        decision: event.properties.reply,
      })
    })

    // Session error
    Bus.subscribe(Session.Event.Error, async (event) => {
      await record({
        sessionID: event.properties.sessionID,
        action: "session.error",
        resourceType: "session",
        resourceID: event.properties.sessionID,
        metadata: {
          error: event.properties.error,
        },
      })
    })

    log.info("audit bus subscriptions active")
  }

  // ── Retention: clean up old audit logs ─────────────────────────────
  const DEFAULT_RETENTION_DAYS = 90

  export function startRetention(retentionDays = DEFAULT_RETENTION_DAYS) {
    Scheduler.register({
      id: "audit.retention",
      interval: 24 * 60 * 60 * 1000, // daily
      scope: "global",
      async run() {
        const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000
        try {
          Database.use((db) => {
            db.delete(AuditLogTable).where(lte(AuditLogTable.time_created, cutoff)).run()
          })
          log.info("audit retention sweep complete", { cutoff, retentionDays })
        } catch (e) {
          log.error("audit retention sweep failed", { error: e })
        }
      },
    })
  }
}
