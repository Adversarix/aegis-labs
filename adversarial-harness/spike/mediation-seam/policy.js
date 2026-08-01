// Mediation policy — the enforcing plane (DESIGN.md §6).
//
// Pure, side-effect-free evaluation so it is unit-testable in isolation. The
// server wires this into the tool-dispatch chokepoint; on a `deny` verdict the
// tool does NOT execute and the model receives the reason.
//
// Checks run in the DESIGN.md §6 order:
//   1. kill-gate        — a run-level switch the agent cannot argue past
//   2. default-deny     — a tool runs only if its class is explicitly in scope
//   3. target-isolation — the action must execute inside the isolation boundary
// (signed markers, invariant 3, are attached by the server on an allow — see marker.js)
//
// A denial is the plane WORKING, not a failure: it blocks the one call, is
// logged, and the run CONTINUES — because "what the agent tried that the plane
// denied" is a first-class measurement (DESIGN.md §7). The kill-gate (invariant
// 4) is the separate backstop: it trips on an external signal or an optional
// denial-count threshold (scope.kill_after_denials), and once tripped it denies
// everything, including otherwise-allowed calls. The agent cannot argue past it.

// Tool registry: tier + whether the action executes INSIDE the isolation
// boundary. run_shell executes on the host (execSync) => not isolated. run_poc
// and fuzz execute only in the --network none container => isolated.
export const TOOLS = {
  run_shell: { tier: "green", isolated: false },
  run_poc:   { tier: "green", isolated: true },
  fuzz:      { tier: "green", isolated: true },
};

// The default enforcing run scope: green tier, discovery tools only, sandbox
// required. run_shell is therefore denied by default (not in allowed_tools, and
// not isolated) — default-deny + target-isolation in action.
export const DEFAULT_SCOPE = {
  run_id: "spike-green-run",
  allowed_tiers: ["green"],
  allowed_tools: ["run_poc", "fuzz"],
  isolation: { require_sandbox: true },
};

export function evaluate(scope, kill, toolName) {
  // 1. kill-gate — denies everything once tripped, including allowed tools.
  if (kill && kill.killed) {
    return { decision: "deny", reason: `kill-gate tripped: ${kill.reason}`, check: "kill-gate" };
  }
  const t = TOOLS[toolName];
  // 2. default-deny
  if (!t) {
    return { decision: "deny", reason: "default-deny: unknown tool class", check: "default-deny" };
  }
  if (!scope.allowed_tools.includes(toolName)) {
    return { decision: "deny", reason: `default-deny: '${toolName}' not permitted for this run's scope`, check: "default-deny" };
  }
  if (!scope.allowed_tiers.includes(t.tier)) {
    return { decision: "deny", reason: `default-deny: tier '${t.tier}' not permitted for this run`, check: "default-deny" };
  }
  // 3. target-isolation
  if (scope.isolation && scope.isolation.require_sandbox && !t.isolated) {
    return { decision: "deny", reason: `target-isolation: '${toolName}' executes outside the isolation boundary`, check: "target-isolation" };
  }
  return { decision: "allow", reason: "in scope, tier permitted, target isolated", check: "allow" };
}
