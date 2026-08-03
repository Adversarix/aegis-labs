// Helper for the teardown-under-kill test: run a detonation that stalls in the
// live-fire window, writing the guest dir to $GUESTFILE so the parent can kill us
// mid-detonation and then assert the guest was torn down by the signal handler.
import { openStore } from "../munitions-store/store.js";
import { LocalHarnessSubstrate } from "./substrate.mjs";
import { detonateRun } from "./detonate.mjs";
import { writeFileSync } from "node:fs";

const STORE_DIR = process.env.STORE_DIR;
const GUESTFILE = process.env.GUESTFILE;
const store = openStore(STORE_DIR, { key: "kill-test-key" });
const m = store.create({ artifact: { reproducer_input_hex: "41", recipe: "r", crash_report: "c" } });

await detonateRun({
  substrate: new LocalHarnessSubstrate(), store, munitionId: m.id,
  armorer: { role: "armorer", actor: "alice" }, markerKey: "k", chamberRunId: "kill-run",
  benign: true, stallMs: 60000,   // long live-fire window; parent kills us during it
  onGuest: (g) => writeFileSync(GUESTFILE, g.dir),
});
