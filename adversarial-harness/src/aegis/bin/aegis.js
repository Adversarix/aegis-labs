#!/usr/bin/env node
// aegis — a thin CLI over Goose for contained adversarial research. It wires the
// mediation seam, the security-native tools, scope, keys, and the munitions store
// behind subcommands, so a researcher runs `aegis develop --target ramp1` instead
// of a long `goose run --with-extension "...node .../server.js"` incantation.
//
// It does NOT fork Goose: it shells out to stock Goose with the right extension.
import { parseArgs } from "node:util";
import { spawnSync } from "node:child_process";
import { loadConfig, saveConfig, ensureInitialized, configPath } from "../lib/config.js";
import { buildRun, validTargets } from "../lib/goose.js";
import { runChecks } from "../lib/doctor.js";
import { storeCommand } from "../lib/store.js";

const [, , sub, ...rest] = process.argv;

const HELP = `aegis — contained adversarial research CLI (thin wrapper over Goose)

Usage:
  aegis init                          initialize config, keys, and the store
  aegis doctor                        preflight readiness checks
  aegis config get [key]              show config (or one key)
  aegis config set <key> <value>      set a config value
  aegis discover [opts]               run the discovery seam (fuzz + promote_finding)
  aegis develop --target <t> [opts]   run the develop seam against a target
  aegis operator [opts]               run the operator cockpit (Goose drives hunt->custody on a real target)
  aegis store <list|show|verify|dispose> [args]   custody store (human path)

Run options (discover/develop):
  -t, --task <text>        one-shot instruction
  -i, --instructions <f>   instruction file
  -s, --interactive        interactive session (converse turn by turn)
      --max-turns <n>      cap agent turns
      --binary <path>      mount an arbitrary aarch64 ELF as the target (develop; overrides --target)
      --model <m>          override model for this run
      --provider <p>       override provider (ollama|hosted)
      --dry-run            print the Goose command instead of running it
develop targets: ${validTargets().join(", ")}`;

function applyOverrides(cfg, vals) {
  if (vals.model) cfg.model = vals.model;
  if (vals.provider) cfg.provider = vals.provider;
  return cfg;
}

function doRun(kind, argv) {
  const { values } = parseArgs({ args: argv, options: {
    task: { type: "string", short: "t" }, instructions: { type: "string", short: "i" },
    interactive: { type: "boolean", short: "s" }, "max-turns": { type: "string" },
    target: { type: "string" }, binary: { type: "string" }, model: { type: "string" }, provider: { type: "string" },
    "dry-run": { type: "boolean" },
  }, allowPositionals: true });
  const cfg = applyOverrides(ensureInitialized(), values);
  const run = buildRun(kind, cfg, {
    task: values.task, instructions: values.instructions, interactive: values.interactive,
    maxTurns: values["max-turns"], target: values.target, binary: values.binary,
  });
  if (values["dry-run"]) {
    console.log(`# provider=${cfg.provider} model=${cfg.model} store=${cfg.store_dir}`);
    console.log(run.printable);
    return 0;
  }
  const r = spawnSync(run.bin, run.args, { env: run.env, stdio: "inherit" });
  return r.status ?? 0;
}

function parseStoreArgs(argv) {
  const { values, positionals } = parseArgs({ args: argv, options: {
    role: { type: "string" }, actor: { type: "string" }, reason: { type: "string" },
  }, allowPositionals: true });
  return { id: positionals[0], ...values };
}

async function main() {
  try {
    switch (sub) {
      case undefined: case "help": case "-h": case "--help":
        console.log(HELP); return 0;

      case "init": {
        const cfg = ensureInitialized();
        console.log(`initialized.\n  config: ${configPath()}\n  store:  ${cfg.store_dir}\n  model:  ${cfg.provider}/${cfg.model}`);
        return 0;
      }

      case "doctor": {
        const checks = runChecks(loadConfig());
        for (const c of checks) console.log(`  [${c.ok ? "ok " : "FAIL"}] ${c.name.padEnd(24)} ${c.detail}`);
        const fails = checks.filter((c) => !c.ok).length;
        console.log(`\n${checks.length - fails}/${checks.length} checks passed` + (fails ? ` (${fails} need attention)` : ""));
        return 0;
      }

      case "config": {
        const cfg = loadConfig();
        const [action, key, ...v] = rest;
        if (action === "set") { if (!key || !v.length) throw new Error("usage: aegis config set <key> <value>");
          cfg[key] = v.join(" "); saveConfig(cfg); console.log(`set ${key}`); return 0; }
        // get: redact secrets
        const view = { ...cfg };
        for (const k of ["marker_key", "store_key"]) if (view[k]) view[k] = `${String(view[k]).slice(0, 8)}… (redacted)`;
        console.log(key ? JSON.stringify(view[key] ?? null) : JSON.stringify(view, null, 2));
        return 0;
      }

      case "discover": return doRun("discover", rest);
      case "develop": return doRun("develop", rest);
      case "operator": return doRun("operator", rest);

      case "store": {
        const [ssub, ...sargs] = rest;
        console.log(await storeCommand(ensureInitialized(), ssub, parseStoreArgs(sargs)));
        return 0;
      }

      default:
        console.error(`unknown command '${sub}'\n`); console.error(HELP); return 2;
    }
  } catch (e) {
    console.error(`aegis: ${e.message}`);
    return 1;
  }
}

process.exit(await main());
