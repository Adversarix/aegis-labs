// Tests for the aegis CLI. Drives the CLI as a subprocess (real dispatch + arg
// parsing). No Goose or docker needed: run commands use --dry-run, store commands
// are pure. Run: node aegis.test.mjs
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const DIR = dirname(fileURLToPath(import.meta.url));
const BIN = join(DIR, "bin", "aegis.js");
const HOME = mkdtempSync(join(tmpdir(), "aegis-home-"));
const CONFIG = join(HOME, "config.json");
const env = { ...process.env, AEGIS_CONFIG: CONFIG, AEGIS_HOME: HOME };

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? (pass++, console.log(`  ok  ${name}`)) : (fail++, console.error(`FAIL  ${name}`)); };
function aegis(args) {
  try { return { status: 0, out: execFileSync("node", [BIN, ...args], { env, encoding: "utf8" }) }; }
  catch (e) { return { status: e.status ?? 1, out: (e.stdout || "") + (e.stderr || "") }; }
}

// --- init ---
ok("init succeeds", aegis(["init"]).status === 0);
const cfg = JSON.parse(readFileSync(CONFIG, "utf8"));
ok("init generates a marker key", typeof cfg.marker_key === "string" && cfg.marker_key.length === 64);
ok("init generates a store key", typeof cfg.store_key === "string" && cfg.store_key.length === 64);

// --- config get/set (secrets redacted) ---
ok("config get redacts secrets", /redacted/.test(aegis(["config", "get"]).out));
aegis(["config", "set", "model", "kimi-k3"]);
ok("config set persists", aegis(["config", "get", "model"]).out.includes("kimi-k3"));

// --- discover dry-run ---
const disc = aegis(["discover", "-t", "find a crash", "--dry-run"]).out;
ok("discover wires the mediation seam", disc.includes("mediation-seam/server.js"));
ok("discover sets enforcing mode + store", disc.includes("SEAM_MODE=enforcing") && disc.includes("AEGIS_STORE="));
ok("discover passes the task", disc.includes("find a crash"));

// --- develop dry-run + target validation ---
const dev = aegis(["develop", "--target", "ramp1", "-t", "exploit it", "--dry-run"]).out;
ok("develop wires the develop seam", dev.includes("develop-seam/server.js"));
ok("develop selects the target", dev.includes("SPIKE_TARGET=/work/ramp1"));
ok("develop passes SESSION_SERVER", dev.includes("session_server.py"));
const badTarget = aegis(["develop", "--target", "nope", "--dry-run"]);
ok("develop rejects an unknown target", badTarget.status === 1 && /unknown target/.test(badTarget.out));

// --- interactive flag ---
ok("interactive adds --interactive", aegis(["develop", "--target", "ret2win", "-s", "--dry-run"]).out.includes("--interactive"));

// --- store: seed a munition in the configured store, then drive the CLI ---
const { openStore } = await import(join(DIR, "..", "munitions-store", "store.js"));
const store = openStore(cfg.store_dir, { key: cfg.store_key });
const m = store.create({ artifact: { reproducer_input_hex: "4141", recipe: "r", crash_report: "overflow" } });
ok("store list shows the seeded munition", aegis(["store", "list"]).out.includes(m.id));
ok("store verify reports ok", /"ok": true/.test(aegis(["store", "verify", m.id]).out));
const noAuthz = aegis(["store", "dispose", m.id]);
ok("store dispose without authorization is refused", noAuthz.status === 1 && /requires a human authorization/.test(noAuthz.out));
const disposed = aegis(["store", "dispose", m.id, "--role", "custodian", "--actor", "alice", "--reason", "test"]);
ok("store dispose with --role/--actor succeeds", disposed.status === 0 && /disposed/.test(disposed.out));
ok("store verify still ok after disposal", /"ok": true/.test(aegis(["store", "verify", m.id]).out));

// --- doctor runs and reports ---
ok("doctor runs and prints checks", /checks passed/.test(aegis(["doctor"]).out));

// --- help ---
ok("help lists subcommands", /aegis develop/.test(aegis(["help"]).out));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
