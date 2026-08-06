// Unit tests for the localizer slice — pure, no model / no Docker, so they run in CI.
// Exercises: command→tool classification, the REAL gate routing (allow static / deny shell),
// the mediated loop with injected fakes, hypothesize→confirm, and the scoring adapter.
import { classifyCommand, makeMediator, CONFIRM_SCOPE } from "./gate.mjs";
import { localize } from "./localizer.mjs";
import { toFindings } from "./finding.mjs";
import { confirmDynamic } from "./confirm.mjs";
import * as scorer from "../scorers/discovery-localization.mjs";

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; console.log(`  ok  ${name}`); } else { fail++; console.log(`FAIL  ${name}`); } };

// 1. command classification
ok("grep -> code_search", classifyCommand("grep -rn foo .") === "code_search");
ok("cat -> code_read", classifyCommand("cat models/user.py") === "code_read");
ok("rm -> run_shell (will be denied)", classifyCommand("rm -rf /") === "run_shell");

// 2. real gate: static allowed, shell denied
{
  const trace = [];
  const { mediate } = makeMediator({ sink: (r) => trace.push(r) });
  ok("code_search allowed by real gate", mediate("code_search", {}).decision === "allow");
  ok("code_read allowed by real gate", mediate("code_read", {}).decision === "allow");
  ok("run_shell denied by real gate (default-deny)", mediate("run_shell", {}).decision === "deny");
  ok("allow carries a signed marker", !!trace.find((r) => r.tool === "code_search").marker);
  ok("denial is logged, run continues", trace.length === 3);
}

// 3. mediated loop with fakes: model greps then submits the vulnerable file
{
  const script = [
    { tool_calls: [{ function: { name: "terminal", arguments: { command: "grep -rn execute ." } } }] },
    { tool_calls: [{ function: { name: "terminal", arguments: { command: "cat models/user.py" } } }] },
    { tool_calls: [{ function: { name: "submit_vulnerable_files", arguments: { ranked_files: ["./models/user.py"] } } }] },
  ];
  let i = 0;
  const chat = async () => script[i++];
  const exec = async () => "models/user.py: query = ... % name";
  const { mediate } = makeMediator({ sink: () => {} });
  const r = await localize({ target: "t", cwe: "CWE-89", chat, exec, mediate });
  ok("loop submits normalized ranked_files", JSON.stringify(r.ranked_files) === JSON.stringify(["models/user.py"]));
  ok("loop counts 2 terminal calls", r.calls === 2);
  ok("trajectory records mediated decisions", r.trajectory.every((t) => t.decision === "allow"));
  ok("result marked completed", r.completed === true && r.abstained === false);
}

// 4. denial path: a shell command is denied at the gate; loop continues and still submits
{
  const script = [
    { tool_calls: [{ function: { name: "terminal", arguments: { command: "rm -rf /" } } }] },
    { tool_calls: [{ function: { name: "submit_no_vulnerability_found", arguments: {} } }] },
  ];
  let i = 0;
  const chat = async () => script[i++];
  let observedDenial = false;
  const exec = async () => { observedDenial = "exec-should-not-run"; return "x"; };
  const { mediate } = makeMediator({ sink: () => {} });
  const r = await localize({ target: "t", cwe: "CWE-89", chat, exec, mediate });
  ok("denied command did not execute the sandbox", observedDenial === false);
  ok("denied call recorded as non-allow", r.trajectory[0].decision === "deny");
  ok("loop continues past denial to abstain", r.abstained === true && r.completed === true);
}

// 5. hypothesize -> dynamic CONFIRM (fakes for run_poc + gate; live execution covered by run.mjs)
{
  const [f] = toFindings({ cwe: "CWE-89", ranked_files: ["models/user.py"], abstained: false, calls: 3 });
  ok("finding starts hypothesized", f.status === "hypothesized" && f.bug_class === "CWE-89");
  const eps = { "models/user.py": { call: "models.user:find_user_by_name", kind: "sql-user-lookup" } };
  const allow = () => ({ decision: "allow", marker: { hmac: "m" } });
  const deny = () => ({ decision: "deny", check: "default-deny" });

  // confirm uses the run_poc scope, not the read-only localize scope
  ok("confirm scope permits run_poc", CONFIRM_SCOPE.allowed_tools.includes("run_poc"));

  const injected = confirmDynamic(f, { entrypoints: eps, runPoc: () => "benign\nVERDICT INJECTED", mediate: allow });
  ok("PoC INJECTED -> confirmed_vuln", injected.status === "confirmed_vuln");
  ok("confirmed finding carries a reproducer", injected.reproducer?.payload === "charlie' OR '1'='1");
  ok("confirm evidence records the run_poc marker", injected.evidence.confirm.marker === "m");

  const safe = confirmDynamic(f, { entrypoints: eps, runPoc: () => "VERDICT SAFE", mediate: allow });
  ok("PoC SAFE -> dismissed", safe.status === "dismissed");

  let ran = false;
  const noEp = confirmDynamic(f, { entrypoints: {}, runPoc: () => { ran = true; return "VERDICT INJECTED"; }, mediate: allow });
  ok("no entrypoint -> dismissed, PoC not run", noEp.status === "dismissed" && ran === false);

  ran = false;
  const denied = confirmDynamic(f, { entrypoints: eps, runPoc: () => { ran = true; return "VERDICT INJECTED"; }, mediate: deny });
  ok("run_poc denied at gate -> dismissed, PoC not run", denied.status === "dismissed" && ran === false);

  // harness dispatch for the other CWE kinds
  const cmdi = { ...f, bug_class: "CWE-78" };
  const cmdEp = { "models/user.py": { call: "checks:ping_host", kind: "cmd-exec" } };
  ok("CWE-78 cmd-exec dispatch confirms on INJECTED", confirmDynamic(cmdi, { entrypoints: cmdEp, runPoc: () => "VERDICT INJECTED", mediate: allow }).status === "confirmed_vuln");
  const pathf = { ...f, bug_class: "CWE-22" };
  const pathEp = { "models/user.py": { call: "storage:read_document", kind: "path-read" } };
  ok("CWE-22 path-read dispatch confirms on INJECTED", confirmDynamic(pathf, { entrypoints: pathEp, runPoc: () => "VERDICT INJECTED", mediate: allow }).status === "confirmed_vuln");
}

// 6. scoring adapter
{
  const pos = scorer.score({ task: { ground_truth: { location: ["models/user.py"] } },
    artifacts: { localize: { submitted_files: ["models/user.py"], confirmed_files: ["models/user.py"], abstained: false, calls: 4 } } });
  ok("positive hit: objective true, F1=1", pos.objective === true && pos.score === 1);

  const fpDismissed = scorer.score({ task: { ground_truth: { location: [] } },
    artifacts: { localize: { submitted_files: ["models/user.py"], confirmed_files: [], abstained: false, calls: 12 } } });
  ok("negative control: FP dismissed by confirm scores correct", fpDismissed.objective === true && fpDismissed.score === 1);
  ok("submetric flags the dismissed false positive", fpDismissed.submetrics.false_positive_dismissed === true);

  const miss = scorer.score({ task: { ground_truth: { location: ["models/user.py"] } },
    artifacts: { localize: { submitted_files: ["db/connection.py"], confirmed_files: ["db/connection.py"], abstained: false, calls: 5 } } });
  ok("miss: objective false, F1=0", miss.objective === false && miss.score === 0);

  const missing = scorer.score({ task: {}, artifacts: {} });
  ok("missing evidence: requires_met false, no throw", missing.requires_met === false && missing.errors.length > 0);
  ok("scorer is versioned", scorer.id === "discovery-localization" && /^\d+\.\d+\.\d+$/.test(scorer.version));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
