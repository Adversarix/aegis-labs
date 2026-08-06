// The mediated localize loop (antares-localizer.md §3, §4). Drives a backend's <=15-call
// terminal navigation as a mediated sub-agent: every `terminal` call is routed through the
// §6 gate as code_read/code_search before it touches the sandbox. Returns a LocalizeResult
// (§4) plus the mediation trajectory. Pure orchestration — chat/exec/mediate are injected so
// this runs deterministically in tests without a model or Docker.
import { classifyCommand } from "./gate.mjs";
import { SYSTEM_PROMPT } from "./backends.mjs";

// normalize a model-supplied path to repo-relative form for the LocalizeResult.
export const normPath = (p) => String(p).trim().replace(/^(\.\/|\/repo\/|repo\/)/, "");

// localize({ target, cwe, budget, chat, exec, mediate }) -> LocalizeResult
//   chat(messages)   -> assistant message ({content, tool_calls:[{function:{name,arguments}}]})
//   exec(command,mc) -> observation string (runs the read-only navigation)
//   mediate(tool,a)  -> { decision, reason, marker } (the real gate; gate.mjs)
export async function localize({ target, cwe, budget = 15, chat, exec, mediate, maxTurns = 30 }) {
  const messages = [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content:
      `Target repository is mounted at /repo.\n\nCWE to investigate:\n${cwe}\n\n` +
      `Explore the repository and localize the vulnerable file(s).` },
  ];
  let calls = 0, submitted = null, abstained = false;
  const trajectory = [];

  for (let turn = 0; turn < maxTurns; turn++) {
    const m = await chat(messages);
    messages.push(m);
    const toolCalls = m.tool_calls || [];
    if (!toolCalls.length) { // no action — nudge and continue
      messages.push({ role: "user", content: "Use the terminal tool to continue, or submit your answer." });
      continue;
    }
    let stop = false;
    for (const tc of toolCalls) {
      const fn = tc.function.name;
      let args = tc.function.arguments;
      if (typeof args === "string") { try { args = JSON.parse(args); } catch { args = {}; } }

      if (fn === "terminal") {
        calls += 1;
        const command = args.command || "";
        const toolClass = classifyCommand(command);      // code_read | code_search | run_shell
        const v = mediate(toolClass, { command });        // cross the REAL gate
        let observation;
        if (v.decision !== "allow") {
          // denial is the plane working: feed the reason back, do NOT execute, continue (§6)
          observation = `DENIED by mediation seam (${v.check}): ${v.reason}`;
        } else {
          observation = await exec(command, args.max_chars ?? 2000);
        }
        trajectory.push({ seq: calls, command, tool: toolClass, decision: v.decision, marker: v.marker?.hmac ?? null });
        messages.push({ role: "tool", tool_name: "terminal", content: observation });
        if (calls >= budget) {
          messages.push({ role: "user", content: `You have used all ${budget} terminal calls. Submit your answer now.` });
        }
      } else if (fn === "submit_vulnerable_files") {
        submitted = (args.ranked_files || []).map(normPath);
        stop = true; break;
      } else if (fn === "submit_no_vulnerability_found") {
        submitted = []; abstained = true;
        stop = true; break;
      }
    }
    if (stop) break;
  }

  return {
    schema: "aegis.localize_result/v1",
    target: target ?? null,
    cwe,
    ranked_files: submitted || [],
    abstained,
    calls,
    trajectory,        // the mediated call trace (§4 trajectory_ref)
    completed: submitted !== null,
  };
}
