) Deployment choice (what’s “best” for you right now)
Given: self-hosted only, security-sensitive code, TUI first, unknown infra maturity.

Recommendation
MVP: single internal server (VM or bare metal) behind company VPN + reverse proxy
This is the fastest path to deliver value and learn requirements.
Scale/production (later): Kubernetes if your company already runs it; otherwise stay on VMs with good ops practices.
Why not k8s immediately?
K8s adds operational overhead (cluster, ingress, secrets, policies, observability) that slows you down unless your org already has a paved path.

“Secure handling” baseline for MVP (do these even on a single server)
Run inside private network/VPN, no public exposure.
TLS everywhere (even internal).
Store secrets in a secrets manager (Vault/KMS) or at least locked-down env vars.
Encrypt at rest for DB + disk.
Tight egress controls: the backend should not talk to internet except maybe model downloads (and even that can be mirrored internally).
Audit logging for all runs + tool executions.
2) Concrete implementation plan using anomalyco/opencode as the base
You said opencode “has everything” and is already deployed. So your job becomes: extend it with:

Subagent parallelism
Self-hosted slim backend + RBAC + audit logs
Skills/policies
TUI changes (align with the PI agent UI you mentioned)
Work in “vertical slices”
Instead of building each bullet in isolation, do these slices:

Slice A (Week 1): “Run API + audit log + TUI connects”
Backend endpoint: create run, stream events, cancel run
Persist minimal run record (who ran it, repo, model, timestamps)
Audit log entry per run + per tool call
TUI can connect to backend and display streaming response
Slice B (Week 2): RBAC + policy enforcement hook
SSO login (OIDC is typical)
Roles: employee, admin (start simple)
Policy hook: before tool call → allow/deny + log decision
First restrictions:
disallow external network tools
limit file write tools to “workspace only”
enforce “no direct push to main” (PR-only)
Slice C (Week 3–4): Subagents sequential → then parallel
Implement sequential subagents first (planner → workers)
Then add parallel fan-out for safe read-only skills (search/index)
Add budgets: max subagents, max tokens, max tool calls, timeouts
Slice D (Week 5+): expand skills + hardening
Add skill registry with scopes and permissions
Add retention policies, redaction, secret detection
Prepare for web/VS Code later by keeping UI thin and API-driven.

these are the tasks to be done. Go through my repo and verify how you will do these tasks



https://chatgpt.com/share/69a44597-0e90-8012-8347-a112d6eb04f9


https://chatgpt.com/gg/v/69a445c6576081a0ac37d4f88740b1f8?token=5lC-Cdd9M_BCtveOhivj8w
