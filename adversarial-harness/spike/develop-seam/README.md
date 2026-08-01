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
| `gadget_search` | pwntools ROP | ret/pop/syscall gadgets |
| `build_exploit` | pwntools process | build + verify a ret2win N×; reports objective-marker reliability |

## Env

`SEAM_MODE` (enforcing|log-only), `MEDIATION_LOG`, `DEV_TOOLS` (allowlist of tools to expose;
the ablation drops `debug,find_offset`), `AEGIS_MARKER_KEY`, `SPIKE_DEVELOP_IMAGE`,
`SESSION_SERVER` (host path to `session_server.py` to mount).

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
result and the with/without-debugger ablation.
