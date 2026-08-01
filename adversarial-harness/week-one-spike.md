# Week-One Spike — Runbook

**Status:** Draft v0.1 · **Date:** 2026-08-01 · Parent: [`DESIGN.md`](./DESIGN.md) §8

A five-day, throwaway-friendly spike that resolves the design's riskiest unknowns by
**building, not designing**. It answers three questions and produces a `FINDINGS` doc in
the lab's usual style.

**The three questions:**

1. **Format risk + neutrality (highest).** Does a tool call round-trip through the forked
   CLI **across backends** — at least one **local** (Ollama, no GPU) *and* one **hosted**
   API? Neutrality is a day-one property, not a later feature (`DESIGN.md` §1.1, §4 L3).
2. **Fork decision.** Goose or OpenCode — decided by trying the round-trip on each, not on
   paper (`DESIGN.md` §9).
3. **First capability signal.** Does adding one security-native tool move the needle on one
   contained task? (The design's central claim, in miniature.)

**Explicit non-goals** (keep it small and safe): no mediation *enforcement* (log-only), no
munitions store, no microVM / detonation, no third-party targets, no disclosure, no
fine-tuning. Everything runs against one **deliberately-vulnerable, benign, in-box** target
in a container. Green tier only.

---

## Prerequisites

- **A local backend** — **Ollama** on your workstation (runs on Apple Silicon / CPU / any
  GPU; no CUDA needed). This is the day-one path; no GPU box required to start.
- **A hosted backend** — any provider API key you already have (to prove neutrality —
  same run, different backend).
- **Docker** (container sandbox), **git**, a C toolchain with clang/libFuzzer + ASan.
- **Optional, later:** a **CUDA GPU box** for vLLM/SGLang — needed only for the
  *research-grade* capability signal (fp16, logprobs, throughput). vLLM needs an NVIDIA GPU
  and does **not** run on a Mac; defer it until Day 4–5 or week two. Not required for the
  format/fork/mediation questions, which are backend-independent.

> Commands below are concrete starting points — **confirm model ids and each backend's
> tool-call flags/parser** against the versions you install; they move between releases.

---

## Day 1 — Round-trip across a local AND a hosted backend

Goal: a **structured tool call** round-trips through the provider abstraction on *both* a
local and a hosted backend — proving neutrality on day one.

```bash
# LOCAL — Ollama on your workstation (no GPU box). Pull a model with tool-calling support.
ollama pull <qwen3 | llama3.x | a tool-calling model>
ollama serve   # exposes an OpenAI-compatible endpoint at http://localhost:11434/v1
```

```bash
# raw sanity (local): does the model emit a tool_call for a trivial tool?
curl -s http://localhost:11434/v1/chat/completions -H 'content-type: application/json' -d '{
  "model": "<pulled-model>",
  "messages": [{"role":"user","content":"What is the SHA-256 of /etc/hostname? Use the tool."}],
  "tools": [{"type":"function","function":{
    "name":"run_shell","description":"Run a shell command and return stdout",
    "parameters":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}}}],
  "tool_choice":"auto"
}' | tee /tmp/spike_roundtrip_local.json
```

```bash
# HOSTED — the SAME request against a hosted OpenAI-compatible endpoint (swap base_url +
# key + model). Prove the identical tool schema round-trips with only a config change.
# → tee /tmp/spike_roundtrip_hosted.json
```

> Later, when a GPU box is available, repeat once more against **vLLM**
> (`vllm serve <model> --enable-auto-tool-choice --tool-call-parser <parser>`) — its
> parser is backend-specific, so the vLLM round-trip is its own quick re-check, not
> assumed from the Ollama result.

**ACCEPTANCE 1:** **both** responses (local and hosted) contain a well-formed
`tool_calls[0].function` with parseable JSON arguments. If one backend replies in prose or
emits malformed arguments, that IS the format risk, surfaced on day one — and if the two
backends differ, that is exactly the normalization the provider abstraction must own. Fix
path: adjust the backend's tool-call flags/template or the abstraction's normalization, or
drop to a smaller known-good model; do not proceed until the round-trip holds on both.

---

## Day 2 — Fork bake-off (Goose vs OpenCode)

Goal: at least one CLI dispatches a tool call end-to-end against a Day-1 backend (use the
local Ollama endpoint — no GPU needed). Run **both**, pick the cleaner.

```bash
# Goose — configure a custom OpenAI-compatible provider → a Day-1 backend; add one trivial MCP tool
git clone https://github.com/block/goose && cd goose
# point provider base_url at the local endpoint (http://localhost:11434/v1) (see goose docs)
# register a trivial "echo"/"read_file" extension, then run a prompt that must call it
```

```bash
# OpenCode — same shape: custom provider → a Day-1 backend, one trivial tool
git clone https://github.com/sst/opencode && cd opencode
# configure provider base_url at the local endpoint (http://localhost:11434/v1), run the same prompt
```

**ACCEPTANCE 2:** in at least one CLI, a user prompt causes the model to call the tool, the
CLI dispatches it, and the result returns to the model. **DECISION (logged §Decision log):**
pick the fork that round-trips with least glue. If *neither* parses the backend's tool
format, write a thin adapter (translate the backend's emitted format ↔ the CLI's expected
schema) and note it — an adapter requirement is itself a finding.

---

## Day 3 — Mediation seam (log-only)

Goal: the containment seam exists before any offensive tool does — as a no-op.

- In the chosen fork, insert a pass-through **between the agent loop and tool execution**
  that logs every dispatch — `{actor, tool, args, decision: "allow"}` — then allows it.
- No policy, no denial yet. Just prove every tool call is *interceptable* at one chokepoint.

**ACCEPTANCE 3:** every tool call appears in the mediation log immediately before it runs;
there is no code path from model → tool that bypasses the seam. This is the single most
important structural result of the week — if tool dispatch can't be centrally intercepted in
this fork, that changes the fork decision.

---

## Day 4 — One security tool + one target (the capability loop)

Goal: the discovery build-first slice, minimal (`discovery-stage.md` §8).

```bash
# a tiny deliberately-vulnerable target + libFuzzer harness + ASan
cat > vuln.c <<'EOF'
#include <string.h>
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){
  char buf[16]; if(n) memcpy(buf, d, n);   // overflow when n > 16
  return 0;
}
EOF
clang -g -O1 -fsanitize=address,fuzzer vuln.c -o vuln_fuzz
```

- Add **one dynamic discovery tool** behind the seam — `run_poc` (run an input against the
  target, report crash signal + ASan report) and/or `fuzz` (short libFuzzer campaign).
- Run everything in a **container** (no network, resource-capped) — the green sandbox.
- Task the agent: *"Find an input that crashes this target."*

**ACCEPTANCE 4:** the agent, through the tool loop, produces a crashing input and the ASan
report is surfaced back to it (a confirmed crash — `discovery-stage.md` L0). The crash need
not be minimized or promoted; this is plumbing + one real signal, not the full stage.

---

## Day 5 — Capability read + write-up

Goal: one quantified raw-vs-tool data point, and the findings doc.

- **Ablation:** run the Day-4 task twice — (a) with `run_poc`/`fuzz`, (b) with those tools
  removed (model reasons about the source only). Record: found crash? tool-calls / wall-clock
  to find? This is the design's central "does a security-native tool make the agent stronger"
  claim, in miniature.
- **Write `FINDINGS-week-one-spike.md`** in the lab's style (cf. `exploitgym-eval`'s
  `FINDINGS-gemini-smoke.md`): the resolved fork, the working **per-backend** tool-call
  config (local + hosted — the reusable artifact), the mediation-seam approach, and the
  ablation result.

**ACCEPTANCE 5:** a documented delta on one task + the reproducible per-backend tool-call
config + the fork decision. That is the spike's whole job.

---

## What the spike delivers

| Output | Resolves |
|---|---|
| Working per-backend tool-call config (local + hosted) | format risk + neutrality (`DESIGN.md` §1.1/§4/§9) |
| Fork decision, with rationale | fork lock-in (`DESIGN.md` §9) |
| Mediation-seam skeleton (log-only) | proves central interception is feasible in the fork |
| One raw-vs-tool capability data point | validates the core design claim in miniature |
| `FINDINGS-week-one-spike.md` | the record |

If Day 1 or Day 3 fails, that is the point of a spike — you learn the fork/inference stack
is wrong in week one, not month three.

---

## Decision log (fill during the run)

- **Local backend + model:** …
- **Hosted backend + model:** …
- **Per-backend tool-call config (flags/parser/template, each):** …
- **Round-trip held on both (local + hosted)?** …
- **Fork chosen + why:** …
- **Adapter needed?** …
- **Mediation interception clean?** …
- **Ablation result (found w/ tools vs without):** …

---

## Guardrails (do not drift)

- One benign in-box target only. No third-party code, no network, no microVM, no arming,
  no munitions store. Those come after the spike, per the stage specs.
- The seam is **log-only** this week; enforcement is the next milestone, not this one.
- Container is acceptable *because* the target is green/benign — the microVM requirement
  attaches to dynamic analysis of untrusted third-party code and to detonation, neither of
  which is in scope here (`discovery-stage.md` §5, `detonate-stage.md` §5).
