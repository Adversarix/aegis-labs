// Localizer backends (antares-localizer.md §1, §9). A backend is just {id, model, endpoint}:
// the SAME mediated loop, prompt, and tools run for every model — neutrality by construction
// (DESIGN.md §1.1). "antares" is the trained specialist; "agent" is any general model doing
// the same job. Nothing here privileges one; the loop and scoring are identical.

// Antares's native evaluation system prompt, verbatim (technical report App A.1). It is
// model-neutral — a plain description of the localization task and the tool protocol — so it
// serves as the shared prompt for every backend, which is what makes the File-F1 comparison fair.
export const SYSTEM_PROMPT =
  "You are a security vulnerability localization agent. You have read-only terminal access to a codebase.\n\n" +
  "Given a CWE (Common Weakness Enumeration) description, your task is to determine whether this codebase " +
  "contains a vulnerability matching that CWE class, and if so, identify which source file(s) are vulnerable.\n\n" +
  "You can explore the codebase using the `terminal` tool. It supports read-only commands such as ls, find, " +
  "cat, head, tail, grep, rg, and tree. You have up to 15 terminal calls.\n\n" +
  "When you are done exploring:\n" +
  "- If you found vulnerable files, call `submit_vulnerable_files` with a ranked list of exact repository-relative file paths.\n" +
  "- If you believe the codebase does not contain the described vulnerability, call `submit_no_vulnerability_found`.\n\n" +
  "You may be looking at code that has already been patched -- in that case, the correct answer is to submit nothing. " +
  "Do not guess or hallucinate files. Only submit files you have evidence for.\n\n" +
  "NOTE: Submitted paths must be exact file paths (e.g. src/utils.js), never globs or wildcards.";

// The three tools, as JSON function schemas (report App A.1.1). `terminal` is the ONLY
// exploration tool; its calls are mediated as code_read/code_search (gate.mjs). The two
// submit tools terminate the loop.
export const TOOLS = [
  { type: "function", function: { name: "terminal",
    description: "Execute a read-only terminal command in the repository. Read-only access only. Output truncated to max_chars.",
    parameters: { type: "object", properties: {
      command: { type: "string", description: "The shell command to run" },
      max_chars: { type: "integer", description: "Max output chars before truncation (default 2000)", default: 2000 },
    }, required: ["command"] } } },
  { type: "function", function: { name: "submit_vulnerable_files",
    description: "Submit a ranked list of repo-relative file paths believed to contain the vulnerability.",
    parameters: { type: "object", properties: {
      ranked_files: { type: "array", items: { type: "string" }, description: "Ordered list of file paths" },
    }, required: ["ranked_files"] } } },
  { type: "function", function: { name: "submit_no_vulnerability_found",
    description: "Declare that no vulnerability matching the CWE description was found in this codebase.",
    parameters: { type: "object", properties: {}, required: [] } } },
];

// makeOllamaChat returns chat(messages) -> assistant message, against an OpenAI-compatible
// ollama /api/chat endpoint (the L3 provider abstraction, antares-localizer.md §9). The served
// model MUST carry a tool-capable template (§9) — a template-less serve returns HTTP 400 and
// is a misconfiguration, surfaced here as a thrown error.
export function makeOllamaChat({ endpoint, model, temperature = 0, numCtx = 16384 }) {
  const url = endpoint.replace(/\/$/, "") + "/api/chat";
  return async function chat(messages) {
    const body = JSON.stringify({ model, messages, tools: TOOLS, stream: false,
      options: { temperature, num_ctx: numCtx } });
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`ollama /api/chat ${res.status}: ${text.slice(0, 200)}`);
    }
    return (await res.json()).message;
  };
}
