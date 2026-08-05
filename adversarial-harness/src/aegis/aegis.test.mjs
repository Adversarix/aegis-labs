// Tests for the aegis CLI. Drives the CLI as a subprocess (real dispatch + arg
// parsing). No Goose or docker needed: run commands use --dry-run, store commands
// are pure. Run: node aegis.test.mjs
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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

// --- develop --binary: arbitrary target with an aarch64 ELF arch preflight ---
// Craft minimal ELF headers (magic + EI_CLASS + EI_DATA + e_machine) — no real
// binary needed; the check reads only the first 20 bytes.
const elfHeader = (cls, machineLE) => {
  const b = Buffer.alloc(20);
  b[0] = 0x7f; b[1] = 0x45; b[2] = 0x4c; b[3] = 0x46; // \x7fELF
  b[4] = cls;   // EI_CLASS: 2 = 64-bit
  b[5] = 1;     // EI_DATA: little-endian
  b.writeUInt16LE(machineLE, 18); // e_machine
  return b;
};
const aarch64Bin = join(HOME, "target.aarch64");
writeFileSync(aarch64Bin, elfHeader(2, 0xb7)); // EM_AARCH64
const bdev = aegis(["develop", "--binary", aarch64Bin, "-t", "go", "--dry-run"]).out;
ok("develop --binary wires AEGIS_TASK_BINARY", bdev.includes(`AEGIS_TASK_BINARY=${aarch64Bin}`));
ok("develop --binary drops SPIKE_TARGET", !bdev.includes("SPIKE_TARGET="));

const x86Bin = join(HOME, "target.x86_64");
writeFileSync(x86Bin, elfHeader(2, 0x3e)); // EM_X86_64
const badArch = aegis(["develop", "--binary", x86Bin, "--dry-run"]);
ok("develop --binary rejects x86-64 with a clear reason",
  badArch.status === 1 && /x86-64/.test(badArch.out) && /aarch64/.test(badArch.out));

const bin32 = join(HOME, "target.arm32");
writeFileSync(bin32, elfHeader(1, 0x28)); // 32-bit
ok("develop --binary rejects a 32-bit ELF", aegis(["develop", "--binary", bin32, "--dry-run"]).status === 1);

const notElf = join(HOME, "target.sh");
writeFileSync(notElf, "#!/bin/sh\necho hi\n");
const badElf = aegis(["develop", "--binary", notElf, "--dry-run"]);
ok("develop --binary rejects a non-ELF", badElf.status === 1 && /not an ELF/.test(badElf.out));

ok("develop --binary rejects a missing file", aegis(["develop", "--binary", join(HOME, "nope"), "--dry-run"]).status === 1);

// --- operator dry-run: cockpit wiring ---
const op = aegis(["operator", "--dry-run"]).out;
ok("operator wires the operator seam", op.includes("operator/seam.js"));
ok("operator sets OPERATOR_IMAGE + enforcing + store",
  op.includes("OPERATOR_IMAGE=") && op.includes("SEAM_MODE=enforcing") && op.includes("AEGIS_STORE="));
ok("operator defaults to the shipped agent instructions", op.includes("-i") && op.includes("agent-instructions.md"));
ok("operator does not wire develop-only env", !op.includes("SESSION_SERVER=") && !op.includes("SPIKE_TARGET="));
const opTask = aegis(["operator", "-t", "hunt then stop", "--dry-run"]).out;
ok("operator -t overrides the default instructions", opTask.includes("hunt then stop") && !opTask.includes("agent-instructions.md"));

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
ok("help lists the operator cockpit", /aegis operator/.test(aegis(["help"]).out));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
