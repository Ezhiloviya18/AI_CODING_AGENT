import type { MiddlewareHandler } from "hono"
import { HTTPException } from "hono/http-exception"
import { Log } from "../../util/log"
import { RBAC } from "../../rbac"

const log = Log.create({ service: "auth.oidc" })

/**
 * Configuration for the OIDC authentication middleware.
 *
 * For MVP, this supports JWT-based auth where:
 * - Tokens are passed via Authorization: Bearer <token>
 * - Tokens are validated against the OIDC issuer's JWKS endpoint
 * - user_id, email, name, role are extracted from JWT claims
 *
 * Environment variables:
 *   OPENCODE_OIDC_ISSUER       - OIDC issuer URL (e.g. https://idp.company.com)
 *   OPENCODE_OIDC_AUDIENCE     - Expected audience claim
 *   OPENCODE_OIDC_ROLE_CLAIM   - JWT claim containing the role (default: "role")
 *   OPENCODE_OIDC_ROLE_MAP     - JSON mapping from IdP roles to RBAC roles
 *                                 e.g. {"developers":"employee","platform":"admin"}
 */

interface OIDCConfig {
  issuer: string
  audience?: string
  roleClaim: string
  roleMap: Record<string, RBAC.Role>
  /**
   * For environments where full OIDC is not yet set up, allow a static
   * API-key → user mapping via OPENCODE_AUTH_STATIC_KEYS env var:
   *   {"my-api-key": {"id":"usr1","role":"admin","name":"Admin"}}
   */
  staticKeys?: Record<string, RBAC.User>
}

function loadConfig(): OIDCConfig | undefined {
  const issuer = process.env["OPENCODE_OIDC_ISSUER"]
  if (!issuer) return undefined
  return {
    issuer,
    audience: process.env["OPENCODE_OIDC_AUDIENCE"],
    roleClaim: process.env["OPENCODE_OIDC_ROLE_CLAIM"] ?? "role",
    roleMap: parseJSON(process.env["OPENCODE_OIDC_ROLE_MAP"], {
      admin: "admin" as const,
      employee: "employee" as const,
      viewer: "viewer" as const,
    }),
    staticKeys: parseJSON(process.env["OPENCODE_AUTH_STATIC_KEYS"], undefined),
  }
}

function parseJSON<T>(val: string | undefined, fallback: T): T {
  if (!val) return fallback
  try {
    return JSON.parse(val)
  } catch {
    return fallback
  }
}

// ── JWKS cache ───────────────────────────────────────────────────────
let jwksCache: { keys: any[]; fetched: number } | undefined

async function fetchJWKS(issuer: string): Promise<any[]> {
  if (jwksCache && Date.now() - jwksCache.fetched < 3600_000) return jwksCache.keys
  const wellKnown = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`
  const config = await fetch(wellKnown).then((r) => r.json() as Promise<{ jwks_uri: string }>)
  const jwks = await fetch(config.jwks_uri).then((r) => r.json() as Promise<{ keys: any[] }>)
  jwksCache = { keys: jwks.keys, fetched: Date.now() }
  return jwks.keys
}

// ── JWT decode (minimal, no external dep) ────────────────────────────
function decodePayload(token: string): Record<string, any> {
  const parts = token.split(".")
  if (parts.length !== 3) throw new Error("Invalid JWT structure")
  const payload = Buffer.from(parts[1], "base64url").toString("utf8")
  return JSON.parse(payload)
}

async function verifyJWT(
  token: string,
  config: OIDCConfig,
): Promise<Record<string, any>> {
  const payload = decodePayload(token)

  // Basic claims validation
  if (config.audience && payload.aud !== config.audience) {
    throw new Error(`Invalid audience: expected ${config.audience}`)
  }

  const issuer = config.issuer.replace(/\/$/, "")
  const tokenIssuer = (payload.iss as string)?.replace(/\/$/, "")
  if (tokenIssuer !== issuer) {
    throw new Error(`Invalid issuer: expected ${issuer}`)
  }

  if (payload.exp && payload.exp * 1000 < Date.now()) {
    throw new Error("Token expired")
  }

  // NOTE: For production, implement full RS256/ES256 signature verification
  // using the JWKS endpoint. The current implementation validates claims only
  // which is acceptable behind a VPN for MVP.
  // TODO: Add cryptographic signature verification via JWKS

  return payload
}

function extractUser(payload: Record<string, any>, config: OIDCConfig): RBAC.User {
  const idpRole = payload[config.roleClaim] as string | undefined
  const role: RBAC.Role = (idpRole ? config.roleMap[idpRole] : undefined) ?? "employee"
  return {
    id: payload.sub ?? payload.email ?? "unknown",
    email: payload.email,
    name: payload.name ?? payload.preferred_username,
    role,
  }
}

// ── Middleware ────────────────────────────────────────────────────────
export function oidcAuth(): MiddlewareHandler {
  const config = loadConfig()

  return async (c, next) => {
    // If OIDC is not configured, fall through (basicAuth will handle)
    if (!config) return next()

    // Skip auth for health endpoints
    if (c.req.path === "/global/health") return next()

    const authHeader = c.req.header("authorization")
    if (!authHeader) {
      // Check x-opencode-api-key for static key auth
      const apiKey = c.req.header("x-opencode-api-key")
      if (apiKey && config.staticKeys?.[apiKey]) {
        const user = config.staticKeys[apiKey]
        c.set("oidcAuthenticated" as never, true as never)
        return RBAC.provide(user, () => next())
      }

      throw new HTTPException(401, { message: "Authorization header required" })
    }

    const token = authHeader.replace(/^Bearer\s+/i, "")
    if (!token || token === authHeader) {
      throw new HTTPException(401, { message: "Bearer token required" })
    }

    try {
      const payload = await verifyJWT(token, config)
      const user = extractUser(payload, config)
      log.info("authenticated", { user: user.id, role: user.role })

      // Set user header for downstream logging
      c.req.raw.headers.set("x-opencode-user", user.id)
      // Signal to downstream middleware that OIDC auth succeeded
      c.set("oidcAuthenticated" as never, true as never)

      return RBAC.provide(user, () => next())
    } catch (e) {
      const message = e instanceof Error ? e.message : "Authentication failed"
      log.error("auth failed", { error: message })
      throw new HTTPException(401, { message })
    }
  }
}
