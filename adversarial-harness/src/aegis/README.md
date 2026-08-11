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
aegis operator [opts]               run the operator cockpit (Goose drives hunt->custody on a real target)
aegis store <list|show|verify|dispose> [args]   custody store (human path)
aegis detonate --munition <id> --role <r> --actor <a> [opts]   red-tier chamber (human-gated)
```

Run options (discover/develop/operator): `-t/--task`, `-i/--instructions`, `-s/--interactive`,
`--max-turns`, `--binary <path>`, `--model`, `--provider`, `--dry-run`. Develop targets:
`ret2win, ramp1, ramp2, ramp3, ramp4`.

`operator` is the cockpit face: it wires the operator seam (`hunt`, `reproduce`, `triage`,
`promote_finding`, green tier only, everything else default-denied) and lets Goose drive the
research loop against a real third-party target baked into `OPERATOR_IMAGE`. With no `-t`/`-i`
it defaults to the shipped agent instructions (`operator/agent-instructions.md`); disclosure is
deliberately NOT a tool (the harness finds; a human discloses). There is no `--target`/`--binary`
— the target ships in the image.

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
- **The red-tier chamber**: `detonate` runs the detonation orchestrator (`detonate-stage.md`,
  `DESIGN.md` §6.1) in-process, so the six chamber invariants are enforced in code on every fire. It
  is human-gated exactly like `dispose` — arming a munition needs `--role`/`--actor` (the armorer),
  never a Goose tool. `--substrate local` is the non-isolating control plane (benign only);
  `--substrate firecracker` is the real microVM substrate. A `--real` munition is refused on any
  non-isolating substrate (`NO_ISOLATION`).

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
# operator cockpit: let Goose drive hunt -> custody on the baked real target:
aegis operator                       # autonomous, uses the shipped agent instructions
aegis operator --interactive         # drive the loop turn by turn
# custody: list, verify integrity, and dispose (human-authorized) a munition:
aegis store list
aegis store verify <id>
aegis store dispose <id> --role custodian --actor alice --reason "study closed"
# red-tier chamber (human-gated). Plan a run without firing:
aegis detonate --munition <id> --role armorer --actor alice --dry-run
# benign fire on the control-plane substrate (no host needed):
aegis detonate --munition <id> --role armorer --actor alice
# a REAL munition on the real microVM substrate over gcloud ssh:
aegis detonate --munition <id> --role armorer --actor alice --real \
  --substrate firecracker --mode gcp-ssh --gcp-instance crucible-fc-host
```

## Tests

```bash
node aegis.test.mjs   # 39 tests: config, command construction, --binary arch check, target validation, operator wiring, store path, detonate flow
```

## Not covered here (by design)

`arm` / `export` are not standalone CLI commands: arming is driven only inside a chamber run
(`detonate` arms and disarms the munition around the fire, bound to the chamber run), and export is
gated behind the disclosure workflow. The store models and refuses these safely when unauthorized.
