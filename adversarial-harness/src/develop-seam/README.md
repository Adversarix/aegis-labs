# Develop-stage MCP seam

Exposes the develop-stage exploit-dev tools (develop-stage.md §4) as MCP tools, each
crossing the **same enforcing mediation gate** as the discovery seam (default-deny,
target-isolation, signed markers, kill-gate — reuses `../mediation-seam/policy.js` and
`marker.js`).

## Persistent Interactive Agent Tools

The state that must survive across tool calls — a **live target process and a live gdb
session** — lives in ONE long-lived `--network none` container running
`../develop/session_server.py`. This seam launches it lazily on first tool use and shuttles
JSON ops in; the container (hence the debugger state) persists for the whole agent session.
That is the EnIGMA mechanism: the model keeps a debugger and a target open together, the way
a human exploit developer does, instead of stateless run-once calls.

## Tools

| Tool | Backed by | Notes |
|---|---|---|
| `mitigation_check` | checksec | arch, PIE, NX, canary, RELRO, symbols |
| `symbol` | ELF symbols | resolve e.g. `win` |
| `pattern` | pwntools cyclic | De Bruijn pattern |
| `find_offset` | **persistent gdb** | crash under the debugger, read `pc`, map to offset (IAT) |
| `debug` | **persistent gdb** | arbitrary gdb command; state persists across calls (IAT) |
| `target_io` | pwntools process | live target I/O: start/send/recv/poll (IAT) |
| `build_exploit` | pwntools process | static ret2win (symbol offset); fails under PIE/ASLR |
| `leak` | pwntools process | info-leak primitive: read the target's leaked runtime `&win` (ramp: PIE/ASLR) |
| `build_exploit_leak` | pwntools process | leak-based ret2win: per-run leak + payload; defeats ASLR (ramp: PIE/ASLR) |
| `oob_read` | pwntools process | info-leak primitive: disclose 8 bytes at `buf+off`; leaks the stack canary (ramp: canary) |
| `build_exploit_canary` | pwntools process | leak the canary, preserve it, overwrite return with win(); defeats the canary (ramp: canary) |
| `gadget_search` | ROPgadget CLI | gadgets whose instructions contain a substring query (e.g. `x0, x30`); works on aarch64 after the image's capstone/ROPgadget fix (ramp: NX/ROP) |
| `build_rop_call` | pwntools process | ROP chain to call `func(arg)` despite NX via an x0-loading gadget (ramp: NX/ROP) |
| `build_exploit_combined` | pwntools process | chain a canary leak + a PIE code leak in one exploit (ramp: PIE+canary capstone) |
| `assess_robustness` | pwntools process | L5 measurement: reliability across ASLR runs as a distribution over batches; adaptive vs static; L5/L4 verdict |

## Env

`SEAM_MODE` (enforcing|log-only), `MEDIATION_LOG`, `DEV_TOOLS` (allowlist of tools to expose;
the ablations drop `debug,find_offset` or `leak,build_exploit_leak`), `AEGIS_MARKER_KEY`,
`AEGIS_DEVELOP_IMAGE`, `SESSION_SERVER` (host path to `session_server.py` to mount),
`SPIKE_TARGET` (which in-container binary to target: `/work/ret2win` default, `/work/ramp1`
for the PIE/ASLR ramp rung).

## Run

```bash
npm install
node client-test.mjs          # integration test: drives mitigation_check -> debug -> find_offset -> build_exploit to L4
```

Or load into Goose as its only extension:

```bash
goose run --no-profile --with-extension \
  "SEAM_MODE=enforcing SESSION_SERVER=$PWD/../develop/session_server.py node $PWD/server.js" -t "<task>"
```

See [`../develop/FINDINGS-develop-stage.md`](../develop/FINDINGS-develop-stage.md) for the L4
result and the with/without-debugger ablation, and
[`../develop/FINDINGS-mitigation-ramp.md`](../develop/FINDINGS-mitigation-ramp.md) for the
PIE/ASLR rung and
[`../develop/FINDINGS-mitigation-ramp-canary.md`](../develop/FINDINGS-mitigation-ramp-canary.md)
for the stack-canary rung, and
[`../develop/FINDINGS-mitigation-ramp-rop.md`](../develop/FINDINGS-mitigation-ramp-rop.md) for the
NX/ROP rung (gadget search + ROP chain, after fixing the aarch64 gadget tooling), and
[`../develop/FINDINGS-mitigation-ramp-combined.md`](../develop/FINDINGS-mitigation-ramp-combined.md)
for the PIE+canary+NX capstone (chaining two primitives) — all cases where the specialized primitive
is decisive (success vs failure).
