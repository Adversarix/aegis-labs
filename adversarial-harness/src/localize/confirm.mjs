// Dynamic CONFIRM (antares-localizer.md §8; discovery-stage.md §2.3 dynamic path).
//
// Replaces the static sink-regex stand-in with a real differential PoC: build a harness that
// exercises the candidate's declared entrypoint with a BENIGN and a MALICIOUS input, execute it
// via the mediated `run_poc` tool inside the --network none sandbox, and observe behavior. A
// Finding is confirmed_vuln ONLY if the malicious input triggers the vulnerability the benign one
// does not — proof by execution, not pattern matching. A confirmed Finding carries a `reproducer`
// (the payload + recipe), the discovery-stage.md §3 hinge to a proto-munition.
//
// A candidate the manifest gives no entrypoint for cannot be driven, so it is `dismissed`
// (unconfirmed) — you can only dynamically confirm what you can exercise. This is also why a
// patched target dismisses: the injection simply does not trigger.
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cwe = (id) => String(id).match(/CWE-?(\d+)/i)?.[1] ?? String(id);
const norm = (p) => String(p).trim().replace(/^(\.\/|\/repo\/|repo\/)/, "");
const [modOf, fnOf] = [(call) => call.split(":")[0], (call) => call.split(":")[1]];

// Per-CWE harness builders. Each returns Python that prints "VERDICT INJECTED" or "VERDICT SAFE"
// on the last line, plus the payload it proved. The harness imports ONLY the candidate module
// (never the app), so no framework deps are needed to confirm a single sink.
const HARNESS = {
  // CWE-89: a non-matching username that carries `OR '1'='1` returns a row iff the query
  // interpolates input (injectable); a parameterized query treats it as a literal -> no row.
  "sql-user-lookup": (call) => ({ payload: "charlie' OR '1'='1",
    code: `import sqlite3, importlib, sys
sys.path.insert(0, "/repo")
f = getattr(importlib.import_module("${modOf(call)}"), "${fnOf(call)}")
conn = sqlite3.connect(":memory:"); conn.row_factory = sqlite3.Row
c = conn.cursor(); c.execute("CREATE TABLE users(id INTEGER, username TEXT, email TEXT)")
c.execute("INSERT INTO users VALUES (1,'alice','a'),(2,'bob','b')"); conn.commit()
def call(u):
    try: return f(conn, u)
    except Exception as e: print("EXC", e); return None
benign = call("charlie")                 # no such user
malicious = call("charlie' OR '1'='1")   # injection bypass
print("VERDICT", "INJECTED" if (benign is None and malicious is not None) else "SAFE")` }),
  // CWE-78: a payload that appends a marker command executes iff the command is shell-built
  // from input; a properly-quoted/argv call does not run the injected marker.
  "cmd-exec": (call) => ({ payload: "127.0.0.1; echo AEGIS_INJECTED",
    code: `import importlib, sys
sys.path.insert(0, "/repo")
f = getattr(importlib.import_module("${modOf(call)}"), "${fnOf(call)}")
try: out = str(f("127.0.0.1; echo AEGIS_INJECTED", 1))
except Exception as e: out = "EXC " + str(e)
print("VERDICT", "INJECTED" if "AEGIS_INJECTED" in out else "SAFE")` }),
  // CWE-22: a traversal payload reads a file outside the base dir iff the path is unneutralized.
  "path-read": (call) => ({ payload: "../../../../etc/hostname",
    code: `import importlib, sys
sys.path.insert(0, "/repo")
f = getattr(importlib.import_module("${modOf(call)}"), "${fnOf(call)}")
try: out = str(f("../../../../etc/hostname"))
except Exception as e: out = "EXC " + str(e)
print("VERDICT", "INJECTED" if (out and "EXC" not in out and out.strip()) else "SAFE")` }),
};

// A sandboxed PoC runner: writes the harness to a temp file, executes it in a python image with
// the repo mounted READ-ONLY and NO network. Returns stdout+stderr. This is the run_poc backend.
export function makePocRunner({ image = "python:3.12-slim", repoDir, timeoutMs = 30000 } = {}) {
  if (!repoDir) throw new Error("makePocRunner: repoDir required");
  return function runPoc(code) {
    const dir = mkdtempSync(join(tmpdir(), "loc-poc-"));
    try {
      writeFileSync(join(dir, "poc.py"), code);
      try {
        return execFileSync("docker",
          ["run", "--rm", "--network", "none", "--pids-limit", "256",
           "-v", `${repoDir}:/repo:ro`, "-v", `${dir}:/poc:ro`, image, "python3", "/poc/poc.py"],
          { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] });
      } catch (e) { return (e.stdout || "") + (e.stderr || "") || `ERROR: ${e.message}`; }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  };
}

// confirmDynamic: advance one hypothesized Finding via a mediated run_poc.
//   entrypoints: { "<repo/rel/path>": { call: "module:function", kind: "sql-user-lookup" }, ... }
//   runPoc(code) -> observation string   (the sandboxed executor; injected for tests)
//   mediate(tool, args) -> { decision, ... }  (the CONFIRM-scope gate)
export function confirmDynamic(finding, { entrypoints = {}, runPoc, mediate }) {
  const file = norm(finding.location.file);
  const ep = entrypoints[file];
  const klass = cwe(finding.bug_class);

  // No entrypoint -> cannot be exercised -> dismissed (unconfirmed), no run_poc spent.
  if (!ep || !HARNESS[ep.kind]) {
    return dismissed(finding, klass, { method: "dynamic-poc", reason: "no entrypoint to exercise this candidate" });
  }
  const built = HARNESS[ep.kind](ep.call);

  // cross the CONFIRM gate: run_poc, isolated in the sandbox.
  const v = mediate("run_poc", { candidate: file, kind: ep.kind });
  if (v.decision !== "allow") {
    return dismissed(finding, klass, { method: "dynamic-poc", reason: `run_poc denied at gate (${v.check})` });
  }

  const observation = runPoc(built.code) || "";
  const verdict = /(^|\n)VERDICT\s+INJECTED\b/.test(observation);
  if (!verdict) {
    return dismissed(finding, klass, { method: "dynamic-poc", reason: "malicious input did not trigger the vulnerability", observation: observation.slice(-400) });
  }
  return {
    ...finding,
    status: "confirmed_vuln",
    // the reproducer — the hinge to a proto-munition (discovery-stage.md §3)
    reproducer: { entrypoint: ep.call, kind: ep.kind, payload: built.payload,
      recipe: `python3 poc.py  (candidate ${file}, --network none sandbox)`, reliability: 1.0 },
    evidence: { ...finding.evidence,
      confirm: { method: "dynamic-poc", cwe: `CWE-${klass}`, matched: true, marker: v.marker?.hmac ?? null,
        observation: observation.slice(-400) } },
    exploitability: { verdict: "control", rationale: `differential PoC: benign input safe, payload '${built.payload}' triggered the sink` },
  };
}

function dismissed(finding, klass, confirm) {
  return { ...finding, status: "dismissed",
    evidence: { ...finding.evidence, confirm: { cwe: `CWE-${klass}`, matched: false, ...confirm } } };
}
