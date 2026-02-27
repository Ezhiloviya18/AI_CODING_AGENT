import { sqliteTable, text, integer, index } from "drizzle-orm/sqlite-core"
import { SessionTable } from "../session/session.sql"
import { Timestamps } from "@/storage/schema.sql"

export const AuditLogTable = sqliteTable(
  "audit_log",
  {
    id: text().primaryKey(),
    session_id: text().references(() => SessionTable.id, { onDelete: "set null" }),
    user_id: text(),
    action: text().notNull(),
    resource_type: text().notNull(),
    resource_id: text(),
    tool: text(),
    input_summary: text(),
    output_summary: text(),
    decision: text(),
    metadata: text({ mode: "json" }).$type<Record<string, any>>(),
    ...Timestamps,
  },
  (table) => [
    index("audit_log_session_idx").on(table.session_id),
    index("audit_log_user_idx").on(table.user_id),
    index("audit_log_action_idx").on(table.action),
    index("audit_log_time_idx").on(table.time_created),
  ],
)
