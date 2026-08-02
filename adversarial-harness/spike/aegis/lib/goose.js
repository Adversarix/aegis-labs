// Builds the Goose invocation for a discover/develop run: the --with-extension
// string that wires the seam, plus the process env for Goose itself (model,
// backend). Returns argv + env so callers can exec it or print it (--dry-run).
import { join } from "node:path";
import { PATHS } from "./config.js";

const TARGETS = ["ret2win", "ramp1", "ramp2", "ramp3", "ramp4"];

// env assignments prefixed onto the extension command, as Goose expects.
const extPrefix = (env) => Object.entries(env).map(([k, v]) => `${k}=${v}`).join(" ");

function seamExtension(kind, cfg, { target } = {}) {
  const shared = {
    SEAM_MODE: cfg.seam_mode,
    AEGIS_MARKER_KEY: cfg.marker_key,
    AEGIS_STORE: cfg.store_dir,
    AEGIS_STORE_KEY: cfg.store_key,
  };
  if (kind === "discover") {
    const env = { ...shared, SPIKE_IMAGE: cfg.fuzz_image, MEDIATION_LOG: join(cfg.log_dir, "discover.log") };
    return `${extPrefix(env)} node ${PATHS.mediationSeam}`;
  }
  const env = {
    ...shared, SPIKE_DEVELOP_IMAGE: cfg.develop_image, SESSION_SERVER: PATHS.sessionServer,
    SPIKE_TARGET: `/work/${target || "ret2win"}`, MEDIATION_LOG: join(cfg.log_dir, "develop.log"),
  };
  return `${extPrefix(env)} node ${PATHS.developSeam}`;
}

// Process env for Goose: model + backend selection.
function gooseEnv(cfg) {
  const env = { ...process.env,
    GOOSE_PROVIDER: cfg.provider, GOOSE_MODEL: cfg.model,
    XDG_CONFIG_HOME: cfg.goose_state_dir, XDG_DATA_HOME: cfg.goose_state_dir, XDG_CACHE_HOME: cfg.goose_state_dir };
  if (cfg.provider === "ollama") env.OLLAMA_HOST = cfg.ollama_host;
  return env;
}

export function buildRun(kind, cfg, opts = {}) {
  if (kind === "develop" && opts.target && !TARGETS.includes(opts.target)) {
    throw new Error(`unknown target '${opts.target}' (choose one of: ${TARGETS.join(", ")})`);
  }
  const args = ["run", "--no-profile"];
  if (opts.interactive) args.push("--interactive"); else args.push("--no-session");
  if (opts.instructions) args.push("-i", opts.instructions);
  else args.push("-t", opts.task || "You are ready. Await my instructions.");
  if (opts.maxTurns) args.push("--max-turns", String(opts.maxTurns));
  args.push("--with-extension", seamExtension(kind, cfg, opts));
  return { bin: cfg.goose_bin, args, env: gooseEnv(cfg),
    printable: `${cfg.goose_bin} ${args.map((a) => (a.includes(" ") ? JSON.stringify(a) : a)).join(" ")}` };
}

export const validTargets = () => [...TARGETS];
