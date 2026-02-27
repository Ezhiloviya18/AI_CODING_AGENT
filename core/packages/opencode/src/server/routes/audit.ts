import { Hono } from "hono"
import { describeRoute, validator, resolver } from "hono-openapi"
import z from "zod"
import { Audit } from "../../audit"
import { lazy } from "../../util/lazy"

export const AuditRoutes = lazy(() =>
  new Hono()
    .get(
      "/",
      describeRoute({
        summary: "List audit log entries",
        description: "Retrieve audit log entries with optional filters.",
        operationId: "audit.list",
        responses: {
          200: {
            description: "List of audit log entries",
            content: {
              "application/json": {
                schema: resolver(Audit.Entry.array()),
              },
            },
          },
        },
      }),
      validator(
        "query",
        z.object({
          sessionID: z.string().optional(),
          userID: z.string().optional(),
          action: z.string().optional(),
          start: z.coerce.number().optional(),
          end: z.coerce.number().optional(),
          limit: z.coerce.number().optional(),
        }),
      ),
      async (c) => {
        const query = c.req.valid("query")
        const entries = await Audit.list(query)
        return c.json(entries)
      },
    )
    .get(
      "/session/:sessionID",
      describeRoute({
        summary: "List audit logs for a session",
        description: "Retrieve audit log entries for a specific session.",
        operationId: "audit.bySession",
        responses: {
          200: {
            description: "Audit log entries for the session",
            content: {
              "application/json": {
                schema: resolver(Audit.Entry.array()),
              },
            },
          },
        },
      }),
      validator("param", z.object({ sessionID: z.string() })),
      async (c) => {
        const { sessionID } = c.req.valid("param")
        const entries = await Audit.list({ sessionID })
        return c.json(entries)
      },
    ),
)
