// Mediator factory — the localizer's binding to the real §6 gate (antares-localizer.md §6).
//
// Reuses mediation-seam/policy.js evaluate() and marker.js signMarker() unchanged, so the
// localizer crosses the SAME chokepoint as the develop/operator seams. Every localize step
// is a mediated tool call that lands in MEDIATION_LOG with a signed marker on allow; a denial
// blocks the one call, is logged, and the loop CONTINUES (DESIGN.md §6/§7).
import { appendFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { evaluate, TOOLS } from "../mediation-seam/policy.js";
import { signMarker } from "../mediation-seam/marker.js";

// The localizer run scope: green tier, static source-navigation tools ONLY, sandbox
// required. run_shell / dynamic tools are default-denied — the loop can read and search
// source, nothing else (antares-localizer.md §6).
export const LOCALIZER_SCOPE = {
  run_id: "localizer-green-run",
  allowed_tiers: ["green"],
  allowed_tools: ["code_read", "code_search"],
  isolation: { require_sandbox: true },
};

// The CONFIRM scope: a DIFFERENT scope from the read-only localize loop. Confirm executes a
// differential PoC against a candidate via run_poc — a dynamic tool that runs ONLY inside the
// --network none sandbox (policy.js: run_poc isolated:true). Static navigation tools are not
// needed here; run_poc is (discovery-stage.md §2.3 dynamic path). Keeping localize (read-only)
// and confirm (execute-in-sandbox) as separate scopes is the point: the loop can never execute,
// and confirm can only execute in isolation.
export const CONFIRM_SCOPE = {
  run_id: "localizer-confirm-run",
  allowed_tiers: ["green"],
  allowed_tools: ["run_poc"],
  isolation: { require_sandbox: true },
};

// makeMediator wires a scope + kill switch + append-only log into a mediate(tool,args)
// closure, mirroring operator/seam.js. `sink` defaults to appending JSONL to `log`; tests
// pass an in-memory sink to assert on the trace without a file.
export function makeMediator({
  scope = LOCALIZER_SCOPE,
  mode = "enforcing",
  kill = { killed: false, reason: "" },
  log = null,
  markerKey = randomBytes(32).toString("hex"),
  actor = "localizer",
  now = () => new Date().toISOString(),
  sink = null,
} = {}) {
  let seq = 0;
  const emit = sink || ((rec) => { if (log) appendFileSync(log, JSON.stringify(rec) + "\n"); });
  function mediate(tool, args = {}) {
    seq += 1;
    const ts = now();
    const verdict = mode === "log-only"
      ? { decision: "allow", reason: "log-only", check: "log-only" }
      : evaluate(scope, kill, tool);
    const marker = verdict.decision === "allow"
      ? signMarker(markerKey, { run_id: scope.run_id, seq, tool, ts })
      : null;
    emit({ ts, seq, actor, tool, tier: TOOLS[tool]?.tier ?? "unknown", args,
      decision: verdict.decision, check: verdict.check, reason: verdict.reason,
      marker: marker?.hmac ?? null, seam: mode });
    return { ...verdict, marker };
  }
  return { mediate, get seq() { return seq; } };
}

// Route a raw navigation command to its mediated tool class. Search/enumeration verbs are
// code_search; a file read (cat/head/tail/less) is code_read. Anything the classifier does
// not recognize as read-only maps to `run_shell` so the gate DENIES it (default-deny) —
// the classifier never widens what the gate would permit.
export function classifyCommand(command) {
  const c = String(command).trim();
  const verb = (c.match(/^[a-z_]+/) || [""])[0];
  if (["grep", "rg", "find", "tree", "ls", "wc", "head", "tail"].includes(verb)) {
    return ["cat", "head", "tail"].includes(verb) ? "code_read" : "code_search";
  }
  if (["cat", "less", "more"].includes(verb)) return "code_read";
  if (verb === "cd" || verb === "pwd") return "code_search"; // navigation, read-only
  return "run_shell"; // unknown/side-effecting -> gate denies (default-deny)
}
