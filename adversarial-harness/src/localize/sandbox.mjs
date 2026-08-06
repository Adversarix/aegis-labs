// Read-only source sandbox for the localizer's static navigation (antares-localizer.md §6).
//
// Each mediated code_read/code_search call executes inside an ephemeral `--network none`
// container with the source tree mounted READ-ONLY. No target is ever built or run here —
// this is static navigation (ls/grep/rg/cat/...), so there is no blast radius; the sandbox
// exists to contain a stray `find -exec` or a malformed command, not a live target.
//
// cwd persists across calls within one task (the model may `cd sub && ls`): the tracked cwd
// is prepended and the resulting pwd captured back, mimicking a persistent shell.
import { execFileSync } from "node:child_process";

export function makeDockerExec({ image = "antares-sandbox", repoDir, timeoutMs = 30000 } = {}) {
  if (!repoDir) throw new Error("makeDockerExec: repoDir required");
  const cwd = ["/repo"];
  return function exec(command, maxChars = 2000) {
    const inner = `cd ${shq(cwd[0])} 2>/dev/null; ${command}; printf '\\n__PWD__:%s' "$(pwd)"`;
    let out;
    try {
      out = execFileSync("docker",
        ["run", "--rm", "--network", "none", "--pids-limit", "256",
         "-v", `${repoDir}:/repo:ro`, "-w", "/repo", image, "bash", "-c", inner],
        { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      out = (e.stdout || "") + (e.stderr || "") || `ERROR: ${e.message}`;
    }
    const m = out.match(/\n__PWD__:(\/\S*)\s*$/);
    if (m) { cwd[0] = m[1]; out = out.slice(0, m.index); }
    const mc = Number.isFinite(+maxChars) ? +maxChars : 2000;
    return out.trim() ? out.slice(0, mc) : "(no output)";
  };
}

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
