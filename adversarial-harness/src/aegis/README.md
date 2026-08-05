# aegis — contained adversarial research CLI

A thin CLI over Goose. It packages the long
`goose run --no-profile --with-extension "…node …/server.js"` incantation behind subcommands,
owns config / scope / keys / the munitions store, and adds the human custody path that is
deliberately not an agent tool. It does **not** fork Goose: it shells out to stock Goose with the
right extension wired in (`DESIGN.md` §4 L1 realized as a wrapper, not a fork).

## Install

No dependencies (Node builtins only). Link the binary, or run it directly:

```bash
node adversarial-harness/src/aegis/bin/aegis.js <command>
# or: (cd adversarial-harness/src/aegis && npm link)  ->  aegis <command>
```

## Commands

```
aegis init                          initialize config, keys, and the store
aegis doctor                        preflight readiness checks (goose, docker, ollama, images, seams)
aegis config get [key]              show config (secrets redacted)
aegis config set <key> <value>      set a config value
aegis discover [opts]               run the discovery seam (fuzz + promote_finding)
aegis develop --target <t> [opts]   run the develop seam against a target
aegis store <list|show|verify|dispose> [args]   custody store (human path)
```

Run options (discover/develop): `-t/--task`, `-i/--instructions`, `-s/--interactive`,
`--max-turns`, `--binary <path>`, `--model`, `--provider`, `--dry-run`. Develop targets:
`ret2win, ramp1, ramp2, ramp3, ramp4`.

`--binary <path>` (develop) points the run at an arbitrary target instead of a baked one: the
seam mounts it read-only at `/work/task_target` (via `AEGIS_TASK_BINARY`) and it overrides
`--target`. The file may live anywhere on the host. It is preflighted as a **64-bit aarch64 ELF**
(the develop sandbox is Linux/arm64) and rejected fast with a clear reason otherwise — a macOS
Mach-O, a script, or a 32-bit / x86-64 ELF would not execute (x86_64 targets need an x86_64
sandbox, not yet provisioned).

## What it wires for you

- **Model / backend** by config (`provider`, `model`, `ollama_host`) — neutrality without env
  juggling.
- **The seam** as a Goose `--with-extension`, in **enforcing** mode, with a per-run signed-marker
  key and the shared munitions store (`AEGIS_STORE` / `AEGIS_STORE_KEY`).
- **Isolated Goose state** under the aegis home (`XDG_*`), so runs do not pollute your Goose config.
- **The custody store**: `store list/show/verify` and, importantly, `store dispose` — the
  human-authorized op the harness cannot self-authorize. `dispose` requires `--role` and `--actor`,
  which the store library demands (`munitions-custody-policy.md` §6).

## Examples

```bash
aegis init
aegis doctor
# converse turn by turn against a PIE/ASLR target:
aegis develop --target ramp1 --interactive
# point develop at your own aarch64 ELF (mounted read-only, arch-checked):
aegis develop --binary /path/to/your/target --interactive
# one-shot, print the exact Goose command without running it:
aegis develop --target ramp4 -t "leak the canary and win()'s address, then chain them" --dry-run
# custody: list, verify integrity, and dispose (human-authorized) a munition:
aegis store list
aegis store verify <id>
aegis store dispose <id> --role custodian --actor alice --reason "study closed"
```

## Tests

```bash
node aegis.test.mjs   # 26 tests: config, command construction, --binary arch check, target validation, store path
```

## Not covered here (by design)

`arm` / `export` and the red-tier detonate flow are not CLI commands yet — they attach to the
detonation chamber and disclosure workflow, which do not exist. The store models and refuses them
safely; `aegis` will grow those subcommands when red tier lands.
