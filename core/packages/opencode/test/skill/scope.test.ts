import { describe, expect, test } from "bun:test"
import z from "zod"

// Test the Skill scope schema and enforcement logic directly.
// The actual skill.ts module depends on Instance context, so we test the
// schema validation and scope-to-role mapping used by the enforcement code.

const Scope = z.enum(["read", "write", "admin"]).default("write")
type Scope = z.infer<typeof Scope>

const ROLES = ["viewer", "employee", "admin"] as const
type Role = (typeof ROLES)[number]

const SCOPE_ROLE_LEVEL: Record<Scope, number> = {
  read: 0,
  write: 1,
  admin: 2,
}

const ROLE_LEVEL: Record<Role, number> = {
  viewer: 0,
  employee: 1,
  admin: 2,
}

function canExecuteSkill(userRole: Role, skillScope: Scope): boolean {
  return ROLE_LEVEL[userRole] >= SCOPE_ROLE_LEVEL[skillScope]
}

describe("Slice D: Skill scope enforcement", () => {
  describe("Scope schema", () => {
    test("parses read scope", () => {
      expect(Scope.parse("read")).toBe("read")
    })

    test("parses write scope", () => {
      expect(Scope.parse("write")).toBe("write")
    })

    test("parses admin scope", () => {
      expect(Scope.parse("admin")).toBe("admin")
    })

    test("defaults to write when undefined", () => {
      expect(Scope.parse(undefined)).toBe("write")
    })

    test("rejects invalid scope", () => {
      expect(() => Scope.parse("superadmin")).toThrow()
    })
  })

  describe("Scope enforcement logic", () => {
    // Viewer tests
    test("viewer can execute read-scope skills", () => {
      expect(canExecuteSkill("viewer", "read")).toBe(true)
    })

    test("viewer cannot execute write-scope skills", () => {
      expect(canExecuteSkill("viewer", "write")).toBe(false)
    })

    test("viewer cannot execute admin-scope skills", () => {
      expect(canExecuteSkill("viewer", "admin")).toBe(false)
    })

    // Employee tests
    test("employee can execute read-scope skills", () => {
      expect(canExecuteSkill("employee", "read")).toBe(true)
    })

    test("employee can execute write-scope skills", () => {
      expect(canExecuteSkill("employee", "write")).toBe(true)
    })

    test("employee cannot execute admin-scope skills", () => {
      expect(canExecuteSkill("employee", "admin")).toBe(false)
    })

    // Admin tests
    test("admin can execute read-scope skills", () => {
      expect(canExecuteSkill("admin", "read")).toBe(true)
    })

    test("admin can execute write-scope skills", () => {
      expect(canExecuteSkill("admin", "write")).toBe(true)
    })

    test("admin can execute admin-scope skills", () => {
      expect(canExecuteSkill("admin", "admin")).toBe(true)
    })
  })

  describe("Scope level ordering", () => {
    test("read < write < admin", () => {
      expect(SCOPE_ROLE_LEVEL.read).toBeLessThan(SCOPE_ROLE_LEVEL.write)
      expect(SCOPE_ROLE_LEVEL.write).toBeLessThan(SCOPE_ROLE_LEVEL.admin)
    })
  })
})
