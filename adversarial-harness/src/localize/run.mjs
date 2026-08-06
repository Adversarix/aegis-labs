// Localizer head-to-head runner (antares-localizer.md §9, build-first slice item 4).
// Runs the SAME mediated localize loop for each backend over each target, confirms, scores via
// the discovery-localization adapter, and emits a StageScorecard comparing File-F1 + calls +
// wall-clock across backends over identical ground truth (DESIGN.md §1.1 neutrality, §7).
//
// Usage:
//   node run.mjs --backends antares=hf.co/DevQuasar/fdtn-ai.antares-1b-GGUF:Q8_0,agent=gpt-oss:20b \
//                --endpoint http://100.105.236.92:11434 --image antares-sandbox --out runs/h2h
// Env: OLLAMA_ENDPOINT (fallback for --endpoint).
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { makeMediator, CONFIRM_SCOPE } from "./gate.mjs";
import { makeDockerExec } from "./sandbox.mjs";
import { makeOllamaChat } from "./backends.mjs";
import { localize } from "./localizer.mjs";
import { toFindings } from "./finding.mjs";
import { confirmDynamic, makePocRunner } from "./confirm.mjs";
import * as scorer from "../scorers/discovery-localization.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };
const ENDPOINT = arg("--endpoint", process.env.OLLAMA_ENDPOINT || "http://localhost:11434");
const IMAGE = arg("--image", "antares-sandbox");
const CONFIRM_IMAGE = arg("--confirm-image", "python:3.12-slim");
const OUT = resolve(arg("--out", join(HERE, "runs", "h2h")));
const BACKENDS = arg("--backends", "antares=hf.co/DevQuasar/fdtn-ai.antares-1b-GGUF:Q8_0,agent=gpt-oss:20b")
  .split(",").map((s) => { const [id, ...m] = s.split("="); return { id, model: m.join("=") }; });

const tasks = JSON.parse(readFileSync(join(HERE, "fixtures", "tasks.json"), "utf8"));
mkdirSync(OUT, { recursive: true });

async function runOne(backend, target) {
  const repoDir = resolve(HERE, target.dir);
  const log = join(OUT, `${backend.id}.${target.id}.mediation.log`);
  writeFileSync(log, "");
  const { mediate } = makeMediator({ log, markerKey: `h2h-${backend.id}-${target.id}` });
  const exec = makeDockerExec({ image: IMAGE, repoDir });
  const chat = makeOllamaChat({ endpoint: ENDPOINT, model: backend.model });
  const cwe = tasks.cwe_descriptions[target.cwe] || target.cwe;

  const t0 = Date.now();
  const result = await localize({ target: target.id, cwe, chat, exec, mediate });
  const seconds = Math.round((Date.now() - t0) / 1000);

  // hypothesize -> dynamic CONFIRM: exercise each candidate with a differential PoC via a
  // mediated run_poc in the sandbox (§8; confirm.mjs). A confirmed Finding carries a reproducer.
  const clog = join(OUT, `${backend.id}.${target.id}.confirm.log`);
  writeFileSync(clog, "");
  const { mediate: confirmMediate } = makeMediator({ scope: CONFIRM_SCOPE, log: clog, markerKey: `confirm-${backend.id}-${target.id}` });
  const runPoc = makePocRunner({ image: CONFIRM_IMAGE, repoDir });
  const findings = toFindings(result, { trajectory_ref: log })
    .map((f) => confirmDynamic(f, { entrypoints: target.entrypoints || {}, runPoc, mediate: confirmMediate }));
  const confirmed_files = findings.filter((f) => f.status === "confirmed_vuln").map((f) => f.location.file);
  const reproducers = findings.filter((f) => f.reproducer).map((f) => ({ file: f.location.file, payload: f.reproducer.payload }));
  const denied = result.trajectory.filter((t) => t.decision !== "allow").length;

  // RunEvidence -> score
  const evidence = { task: { id: target.id, ground_truth: target.ground_truth },
    artifacts: { localize: { submitted_files: result.ranked_files, confirmed_files,
      abstained: result.abstained, calls: result.calls } } };
  const sr = scorer.score(evidence);
  return { backend: backend.id, model: backend.model, target: target.id,
    submitted: result.ranked_files, confirmed: confirmed_files, reproducers, denied, calls: result.calls, seconds,
    negative: (target.ground_truth.location || []).length === 0, score: sr };
}

const rows = [];
for (const backend of BACKENDS) {
  for (const target of tasks.targets) {
    process.stdout.write(`localize: ${backend.id} × ${target.id} ... `);
    try {
      const r = await runOne(backend, target);
      rows.push(r);
      const repro = r.reproducers.length ? ` reproducer=${JSON.stringify(r.reproducers[0].payload)}` : "";
      console.log(`submitted=${JSON.stringify(r.submitted)} confirmed=${JSON.stringify(r.confirmed)}${repro} ` +
        `F1=${r.score.score.toFixed(2)} obj=${r.score.objective} calls=${r.calls} denied=${r.denied} ${r.seconds}s`);
    } catch (e) { console.log(`ERROR ${String(e.message).slice(0, 120)}`); rows.push({ backend: backend.id, target: target.id, error: String(e.message) }); }
  }
}

// StageScorecard per backend (scoring-adapter.md StageScorecard shape).
const scorecard = BACKENDS.map(({ id }) => {
  const rs = rows.filter((r) => r.backend === id && r.score);
  const pos = rs.filter((r) => !r.negative), neg = rs.filter((r) => r.negative);
  const mean = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0);
  return { backend: id, model: BACKENDS.find((b) => b.id === id).model,
    mean_file_f1_positive: +mean(pos.map((r) => r.score.score)).toFixed(3),
    localized: pos.filter((r) => r.score.objective).length, positives: pos.length,
    negative_control: neg.every((r) => r.score.objective) ? "PASS" : "FAIL",
    fp_dismissed_by_confirm: neg.some((r) => r.score.submetrics.false_positive_dismissed),
    total_calls: rs.reduce((a, r) => a + r.calls, 0), total_denied: rs.reduce((a, r) => a + r.denied, 0),
    total_wall_s: rs.reduce((a, r) => a + r.seconds, 0), runs: rs.map((r) => ({ target: r.target, score: r.score })) };
});

writeFileSync(join(OUT, "scorecard.json"), JSON.stringify({ schema: "aegis.stage_scorecard/v1", endpoint: ENDPOINT, rows, scorecard }, null, 2));
const md = "# Localizer head-to-head — discovery localization\n\n" +
  "Same mediated loop, sandbox, and File-F1 scorer; model swapped by config (antares-localizer.md §1.1/§7).\n\n" +
  "| Backend | Model | mean File-F1 (pos) | localized | neg-control | FP dismissed by confirm | calls | denied | wall |\n" +
  "|---|---|--:|--:|:--:|:--:|--:|--:|--:|\n" +
  scorecard.map((s) => `| ${s.backend} | ${s.model} | ${s.mean_file_f1_positive.toFixed(2)} | ` +
    `${s.localized}/${s.positives} | ${s.negative_control} | ${s.fp_dismissed_by_confirm ? "yes" : "no"} | ` +
    `${s.total_calls} | ${s.total_denied} | ${s.total_wall_s}s |`).join("\n") + "\n";
writeFileSync(join(OUT, "scorecard.md"), md);
console.log(`\n${md}\nscorecard -> ${join(OUT, "scorecard.md")}`);
