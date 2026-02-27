import { Log } from "../util/log"
import { Session } from "../session"
import { Database, lt } from "../storage/db"
import { SessionTable } from "../session/session.sql"
import { AuditLogTable } from "../audit/audit.sql"

const log = Log.create({ service: "retention" })

/**
 * Retention policy configuration.
 *
 * Can be set via:
 * - OPENCODE_RETENTION_SESSIONS_DAYS (default: 90)
 * - OPENCODE_RETENTION_AUDIT_DAYS (default: 365)
 * - OPENCODE_RETENTION_CHECK_INTERVAL_HOURS (default: 24)
 * - Managed config (/etc/opencode/config.json) under `retention`
 */
export namespace Retention {
  export interface Config {
    /** Days to keep sessions (0 = forever) */
    sessionDays: number
    /** Days to keep audit logs (0 = forever) */
    auditDays: number
    /** Hours between retention checks */
    checkIntervalHours: number
  }

  function getConfig(): Config {
    return {
      sessionDays: parseInt(process.env["OPENCODE_RETENTION_SESSIONS_DAYS"] ?? "90", 10) || 90,
      auditDays: parseInt(process.env["OPENCODE_RETENTION_AUDIT_DAYS"] ?? "365", 10) || 365,
      checkIntervalHours: parseInt(process.env["OPENCODE_RETENTION_CHECK_INTERVAL_HOURS"] ?? "24", 10) || 24,
    }
  }

  /**
   * Run a single retention sweep: purge old sessions and audit logs.
   * Returns counts of deleted items.
   */
  export async function sweep(): Promise<{ sessions: number; auditLogs: number }> {
    const config = getConfig()
    let sessions = 0
    let auditLogs = 0

    // Purge old sessions
    if (config.sessionDays > 0) {
      const cutoff = Date.now() - config.sessionDays * 24 * 60 * 60 * 1000
      try {
        const oldSessions = Database.use((db) =>
          db
            .select({ id: SessionTable.id })
            .from(SessionTable)
            .where(lt(SessionTable.time_created, cutoff))
            .all(),
        )

        for (const session of oldSessions) {
          try {
            await Session.remove(session.id)
            sessions++
          } catch (e) {
            log.error("failed to remove session", { sessionID: session.id, error: e })
          }
        }

        if (sessions > 0) {
          log.info("purged old sessions", { count: sessions, cutoffDays: config.sessionDays })
        }
      } catch (e) {
        log.error("session retention sweep failed", { error: e })
      }
    }

    // Purge old audit logs
    if (config.auditDays > 0) {
      const cutoff = Date.now() - config.auditDays * 24 * 60 * 60 * 1000
      try {
        Database.use((db) => {
          db.delete(AuditLogTable).where(lt(AuditLogTable.time_created, cutoff)).run()
        })
        log.info("purged old audit logs", { cutoffDays: config.auditDays })
      } catch (e) {
        log.error("audit retention sweep failed", { error: e })
      }
    }

    return { sessions, auditLogs: 0 }
  }

  let timer: ReturnType<typeof setInterval> | undefined

  /**
   * Start the periodic retention scheduler.
   * Runs an initial sweep, then repeats at the configured interval.
   */
  export function start(): void {
    if (timer) return

    const config = getConfig()
    const intervalMs = config.checkIntervalHours * 60 * 60 * 1000

    log.info("retention scheduler started", {
      sessionDays: config.sessionDays,
      auditDays: config.auditDays,
      intervalHours: config.checkIntervalHours,
    })

    // Initial sweep after a short delay (let the system finish bootstrapping)
    setTimeout(() => {
      sweep().catch((e) => log.error("initial retention sweep failed", { error: e }))
    }, 30_000)

    // Periodic sweeps
    timer = setInterval(() => {
      sweep().catch((e) => log.error("periodic retention sweep failed", { error: e }))
    }, intervalMs)
  }

  /**
   * Stop the retention scheduler.
   */
  export function stop(): void {
    if (timer) {
      clearInterval(timer)
      timer = undefined
      log.info("retention scheduler stopped")
    }
  }
}
