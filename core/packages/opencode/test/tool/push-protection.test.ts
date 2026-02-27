import { describe, expect, test } from "bun:test"

// Test git push protection logic extracted from bash.ts.
// The actual bash tool depends on runtime context, so we test the
// command analysis logic standalone.

interface PushAnalysis {
  blocked: boolean
  reason?: string
}

const PROTECTED_BRANCHES = ["main", "master", "release/"]

function analyzeGitPush(command: string, userRole: string): PushAnalysis {
  // Only analyze git push commands
  const gitPushMatch = command.match(/\bgit\s+push\b/i)
  if (!gitPushMatch) return { blocked: false }

  // Admin bypasses all restrictions
  if (userRole === "admin") return { blocked: false }

  // Check for force push flags
  const forceFlags = ["--force", "-f", "--force-with-lease"]
  const hasForce = forceFlags.some((flag) => command.includes(flag))
  if (hasForce) {
    return { blocked: true, reason: "Force pushes are not allowed for non-admin users" }
  }

  // Check for protected branch names
  for (const branch of PROTECTED_BRANCHES) {
    if (branch.endsWith("/")) {
      // Prefix match (e.g. release/*)
      if (command.includes(branch)) {
        return { blocked: true, reason: `Pushes to ${branch}* branches are restricted` }
      }
    } else {
      // Exact branch name match in command
      const branchRegex = new RegExp(`\\b${branch}\\b`)
      if (branchRegex.test(command)) {
        return { blocked: true, reason: `Pushes to ${branch} are restricted` }
      }
    }
  }

  return { blocked: false }
}

describe("Slice B: Git push protection", () => {
  describe("Non-git commands", () => {
    test("ls is not blocked", () => {
      expect(analyzeGitPush("ls -la", "employee").blocked).toBe(false)
    })

    test("git status is not blocked", () => {
      expect(analyzeGitPush("git status", "employee").blocked).toBe(false)
    })

    test("git commit is not blocked", () => {
      expect(analyzeGitPush("git commit -m 'test'", "employee").blocked).toBe(false)
    })

    test("git pull is not blocked", () => {
      expect(analyzeGitPush("git pull origin main", "employee").blocked).toBe(false)
    })
  })

  describe("Protected branch pushes", () => {
    test("blocks push to main", () => {
      const result = analyzeGitPush("git push origin main", "employee")
      expect(result.blocked).toBe(true)
      expect(result.reason).toContain("main")
    })

    test("blocks push to master", () => {
      const result = analyzeGitPush("git push origin master", "employee")
      expect(result.blocked).toBe(true)
      expect(result.reason).toContain("master")
    })

    test("blocks push to release/* branches", () => {
      const result = analyzeGitPush("git push origin release/v1.0", "employee")
      expect(result.blocked).toBe(true)
      expect(result.reason).toContain("release/")
    })
  })

  describe("Force push protection", () => {
    test("blocks --force push", () => {
      const result = analyzeGitPush("git push --force origin feature", "employee")
      expect(result.blocked).toBe(true)
      expect(result.reason).toContain("Force push")
    })

    test("blocks -f push", () => {
      const result = analyzeGitPush("git push -f origin feature", "employee")
      expect(result.blocked).toBe(true)
      expect(result.reason).toContain("Force push")
    })

    test("blocks --force-with-lease push", () => {
      const result = analyzeGitPush("git push --force-with-lease origin feature", "employee")
      expect(result.blocked).toBe(true)
      expect(result.reason).toContain("Force push")
    })
  })

  describe("Admin bypass", () => {
    test("admin can push to main", () => {
      expect(analyzeGitPush("git push origin main", "admin").blocked).toBe(false)
    })

    test("admin can force push", () => {
      expect(analyzeGitPush("git push --force origin feature", "admin").blocked).toBe(false)
    })

    test("admin can push to release/*", () => {
      expect(analyzeGitPush("git push origin release/v2.0", "admin").blocked).toBe(false)
    })
  })

  describe("Allowed pushes for non-admin", () => {
    test("employee can push to feature branch", () => {
      expect(analyzeGitPush("git push origin feature/my-branch", "employee").blocked).toBe(false)
    })

    test("employee can push to develop", () => {
      expect(analyzeGitPush("git push origin develop", "employee").blocked).toBe(false)
    })

    test("viewer can push to feature branch", () => {
      expect(analyzeGitPush("git push origin fix/bug-123", "viewer").blocked).toBe(false)
    })
  })
})
