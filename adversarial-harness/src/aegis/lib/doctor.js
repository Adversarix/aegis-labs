// aegis doctor — preflight readiness checks. Each check returns {name, ok, detail}.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { PATHS } from "./config.js";

function tryCmd(bin, args) {
  try { return execFileSync(bin, args, { encoding: "utf8", timeout: 8000, stdio: ["ignore", "pipe", "ignore"] }).trim(); }
  catch { return null; }
}

export function runChecks(cfg) {
  const checks = [];
  const add = (name, ok, detail = "") => checks.push({ name, ok: !!ok, detail });

  add("node", true, process.version);

  const goose = tryCmd(cfg.goose_bin, ["--version"]);
  add("goose", goose !== null, goose ? goose.split("\n")[0] : `not found: ${cfg.goose_bin}`);

  const docker = tryCmd("docker", ["--version"]);
  add("docker", docker !== null, docker || "not found");

  if (cfg.provider === "ollama") {
    const tags = tryCmd("curl", ["-s", "-m", "3", `http://${cfg.ollama_host}/api/tags`]);
    add("ollama", tags !== null, tags !== null ? `reachable at ${cfg.ollama_host}` : `not reachable at ${cfg.ollama_host}`);
  } else {
    add(`provider:${cfg.provider}`, true, "hosted (verify API key in env)");
  }

  const images = docker ? tryCmd("docker", ["images", "--format", "{{.Repository}}:{{.Tag}}"]) || "" : "";
  add(`image ${cfg.fuzz_image}`, images.includes(cfg.fuzz_image), cfg.fuzz_image);
  add(`image ${cfg.develop_image}`, images.includes(cfg.develop_image), cfg.develop_image);
  add(`image ${cfg.operator_image}`, images.includes(cfg.operator_image), cfg.operator_image);

  add("mediation seam", existsSync(PATHS.mediationSeam), PATHS.mediationSeam);
  add("develop seam", existsSync(PATHS.developSeam), PATHS.developSeam);
  add("operator seam", existsSync(PATHS.operatorSeam), PATHS.operatorSeam);
  add("munitions store", existsSync(cfg.store_dir), cfg.store_dir);
  add("keys initialized", !!(cfg.marker_key && cfg.store_key), cfg.marker_key ? "present" : "run `aegis init`");

  return checks;
}
