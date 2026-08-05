// aegis config + path resolution. Owns the run keys, store location, model
// selection, and image names, so a researcher does not juggle raw env vars.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";

// Package layout: <src>/aegis/lib/config.js -> the harness src root is two levels up.
const LIB_DIR = dirname(fileURLToPath(import.meta.url));
const AEGIS_DIR = resolve(LIB_DIR, "..");
export const ROOT_DIR = resolve(AEGIS_DIR, "..");

// Absolute paths to the components the CLI drives.
export const PATHS = {
  root: ROOT_DIR,
  mediationSeam: join(ROOT_DIR, "mediation-seam", "server.js"),
  developSeam: join(ROOT_DIR, "develop-seam", "server.js"),
  operatorSeam: join(ROOT_DIR, "operator", "seam.js"),
  operatorInstructions: join(ROOT_DIR, "operator", "agent-instructions.md"),
  sessionServer: join(ROOT_DIR, "develop", "session_server.py"),
  storeLib: join(ROOT_DIR, "munitions-store", "store.js"),
};

const CONFIG_PATH = process.env.AEGIS_CONFIG || join(homedir(), ".config", "aegis", "config.json");

function defaults() {
  const home = process.env.AEGIS_HOME || join(homedir(), ".local", "share", "aegis");
  return {
    goose_bin: "goose",
    provider: "ollama",
    model: "qwen3.6:latest",
    ollama_host: "localhost:11434",
    seam_mode: "enforcing",
    home,
    store_dir: join(home, "store"),
    log_dir: join(home, "logs"),
    goose_state_dir: join(home, "goose"),
    fuzz_image: "aegis-fuzz:latest",
    develop_image: "aegis-develop:latest",
    operator_image: "aegis-operator-stb:latest",
    // Stable keys so the persistent store stays decryptable/verifiable across runs.
    marker_key: null,
    store_key: null,
  };
}

export function loadConfig() {
  const cfg = { ...defaults() };
  if (existsSync(CONFIG_PATH)) Object.assign(cfg, JSON.parse(readFileSync(CONFIG_PATH, "utf8")));
  return cfg;
}

export function saveConfig(cfg) {
  mkdirSync(dirname(CONFIG_PATH), { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
  return CONFIG_PATH;
}

// Ensure stable keys and directories exist; generate keys on first use.
export function ensureInitialized(cfg = loadConfig()) {
  let changed = false;
  if (!cfg.marker_key) { cfg.marker_key = randomBytes(32).toString("hex"); changed = true; }
  if (!cfg.store_key) { cfg.store_key = randomBytes(32).toString("hex"); changed = true; }
  for (const d of [cfg.home, cfg.store_dir, cfg.log_dir, cfg.goose_state_dir]) mkdirSync(d, { recursive: true });
  if (changed) saveConfig(cfg);
  return cfg;
}

export const configPath = () => CONFIG_PATH;
