# Cross-model comparison

Run the same develop task through the same contained develop-seam across several models (swapped by
config, not code) and produce a leaderboard: solved?, tool-calls, denials, distinct tools,
wall-clock. This exercises the model-agnostic design (`DESIGN.md` §1.1) and yields the
capability-range results the lab's model-eval threads care about.

Because every action is a mediated tool call, the mediation log per model turns "solved or not" into
"how it failed" — a clean solve, a wrong parameter, or an incoherent plan.

## Run

```bash
GOOSE_BIN=<path-to-goose> node compare.mjs \
  --target ramp1 \
  --models qwen3.6:latest,qwen3.6:35b-a3b,qwen2.5:7b,glm-4.7-flash:latest \
  --max-turns 12 --timeout 300 --out runs/ramp1
```

Options: `--target` (`ramp1` | `ret2win`), `--models` (comma list), `--max-turns`, `--timeout`
(seconds per model), `--out`. Env: `GOOSE_BIN`, `OLLAMA_HOST`. Models run sequentially; the
leaderboard is written incrementally so progress survives.

## Output (per `--out` dir)

- `leaderboard.md` / `leaderboard.json` — the comparison table.
- `<model>.mediation.log` — the containment trace (every tool call + verdict + signed marker).
- `<model>.out` — the agent's captured output.

## Notes

- `solved` is read from the agent's output (a `build_exploit*` that fired: reliability 1.0 / a
  crash marker). Single sample per model by default; run it N times and compare the range for a
  converged result (`DESIGN.md` §9).
- A hosted model (any OpenAI-compatible backend) can be added once Goose is configured for it; the
  neutrality is the same swap. This first pass is all local Ollama.

See [`FINDINGS-cross-model.md`](./FINDINGS-cross-model.md) for the first result.
