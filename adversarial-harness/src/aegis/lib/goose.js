// Builds the Goose invocation for a discover/develop run: the --with-extension
// string that wires the seam, plus the process env for Goose itself (model,
// backend). Returns argv + env so callers can exec it or print it (--dry-run).
import { join, resolve } from "node:path";
import { openSync, readSync, closeSync } from "node:fs";
import { PATHS } from "./config.js";

const TARGETS = ["ret2win", "ramp1", "ramp2", "ramp3", "ramp4"];

// env assignments prefixed onto the extension command, as Goose expects.
const extPrefix = (env) => Object.entries(env).map(([k, v]) => `${k}=${v}`).join(" ");

function seamExtension(kind, cfg, { target, binary } = {}) {
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
    MEDIATION_LOG: join(cfg.log_dir, "develop.log"),
  };
  // A host binary (--binary) is mounted read-only at /work/task_target by the seam
  // and takes precedence; otherwise SPIKE_TARGET selects a baked ramp/ret2win target.
  if (binary) env.AEGIS_TASK_BINARY = binary;
  else env.SPIKE_TARGET = `/work/${target || "ret2win"}`;
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

// The develop sandbox runs Linux/aarch64, so a --binary target must be a 64-bit
// aarch64 ELF. Read the ELF header and fail fast with a clear reason otherwise: a
// macOS Mach-O, a script, or a 32-bit / x86-64 ELF would silently fail to execute.
const EM = { 0x3e: "x86-64", 0x28: "ARM (32-bit)", 0x03: "x86", 0xf3: "RISC-V" };
export function assertAarch64Elf(path) {
  let fd;
  try { fd = openSync(path, "r"); } catch { throw new Error(`--binary: cannot open '${path}' (no such file?)`); }
  try {
    const buf = Buffer.alloc(20);
    if (readSync(fd, buf, 0, 20, 0) < 20 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46)
      throw new Error(`--binary: '${path}' is not an ELF — the develop sandbox runs Linux ELF binaries (a macOS Mach-O or a script will not execute)`);
    if (buf[4] !== 2)
      throw new Error(`--binary: '${path}' is a 32-bit ELF; the sandbox needs a 64-bit aarch64 ELF`);
    const machine = buf[5] === 1 ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
    if (machine !== 0xb7) // EM_AARCH64
      throw new Error(`--binary: '${path}' is ${EM[machine] || `machine 0x${machine.toString(16)}`}, but the develop sandbox is aarch64. ` +
        `Provide an aarch64 Linux ELF, or run it on an x86_64 sandbox (not yet provisioned).`);
  } finally { closeSync(fd); }
}

export function buildRun(kind, cfg, opts = {}) {
  const binary = opts.binary ? resolve(opts.binary) : null;
  if (kind === "develop" && !binary && opts.target && !TARGETS.includes(opts.target)) {
    throw new Error(`unknown target '${opts.target}' (choose one of: ${TARGETS.join(", ")})`);
  }
  if (binary) assertAarch64Elf(binary);   // fail fast before launching Goose/docker
  const args = ["run", "--no-profile"];
  if (opts.interactive) args.push("--interactive"); else args.push("--no-session");
  if (opts.instructions) args.push("-i", opts.instructions);
  else args.push("-t", opts.task || "You are ready. Await my instructions.");
  if (opts.maxTurns) args.push("--max-turns", String(opts.maxTurns));
  args.push("--with-extension", seamExtension(kind, cfg, { ...opts, binary }));
  return { bin: cfg.goose_bin, args, env: gooseEnv(cfg),
    printable: `${cfg.goose_bin} ${args.map((a) => (a.includes(" ") ? JSON.stringify(a) : a)).join(" ")}` };
}

export const validTargets = () => [...TARGETS];
