#!/usr/bin/env python3
"""Adjudicate Jev's high-confidence false positives against the report prose.

The calibration result (Jev looks overconfident) is confounded by incomplete
CISA gold: the tables tag fewer techniques than the prose describes, so a
"false positive" may be a real-but-untabled technique. This settles it.

For each CISA report we take Jev's high-confidence predictions that are NOT in
the CISA gold table (the false positives) and ask a judge model -- Claude, NOT
Jev, to avoid circularity -- whether the PROSE substantiates each technique per
its ATT&CK definition. We also slip in random low-confidence non-gold
techniques as blind negative controls, so we can measure the judge's own
false-positive rate and trust the verdicts.

Read-out:
  * substantiation rate of Jev's high-conf FPs  -> how much of the apparent
    overconfidence is really just thin labels
  * control substantiation rate (should be low) -> judge specificity sanity check

Usage:
    python adjudicate_jev_fp.py --threshold 0.9 --judge claude-opus-4-8
    python adjudicate_jev_fp.py --threshold 0.9 --controls 3 --max-reports 5   # cheap dry run
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import re
import time

import yaml

ROOT = pathlib.Path(__file__).parent
RAW = ROOT / "results" / "raw" / "jev-typesafe"
OUT = ROOT / "results" / "jev_fp_adjudication.json"

JUDGE_SYS = (
    "You are a MITRE ATT&CK adjudicator. You are given an excerpt from a real "
    "threat-intelligence advisory and a list of candidate ATT&CK techniques. For "
    "EACH candidate, decide whether the TEXT ITSELF substantiates that the "
    "technique was used, judged against the technique's ATT&CK definition -- not "
    "whether it is merely plausible for this kind of actor. Quote the shortest "
    "supporting sentence when supported. Respond ONLY as JSON: "
    '{"<technique_id>": {"supported": true|false, "quote": "<sentence or empty>"}, ...}'
)


def load_gold() -> dict[str, set[str]]:
    return {r["id"]: set(r["gold_techniques"])
            for r in (json.loads(l) for l in (ROOT / "data" / "corpus_cisa.jsonl").read_text().splitlines() if l.strip())}


def load_report_text() -> dict[str, str]:
    return {r["id"]: r["text"]
            for r in (json.loads(l) for l in (ROOT / "data" / "corpus_cisa.jsonl").read_text().splitlines() if l.strip())}


def nouls_for(rid: str) -> dict[str, float]:
    rec = json.loads((RAW / f"{rid}.json").read_text())
    return json.loads(rec.get("raw_text") or "{}").get("nouls", {})


def make_judge(judge_key: str):
    cfg = {m["key"]: m for m in yaml.safe_load((ROOT / "config.yaml").read_text())["models"]}[judge_key]
    if cfg["provider"] == "anthropic":
        from anthropic import Anthropic
        client = Anthropic()

        def ask(user: str) -> str:
            r = client.messages.create(model=cfg["model"], max_tokens=1500, system=JUDGE_SYS,
                                       messages=[{"role": "user", "content": user}])
            if getattr(r, "stop_reason", None) == "refusal":
                return '{"__refusal__": true}'
            return next((b.text for b in r.content if b.type == "text"), "")
        return ask
    import os
    from openai import OpenAI
    client = OpenAI(api_key=os.environ.get(cfg.get("api_key_env", ""), ""),
                    base_url=os.environ.get(cfg.get("base_url_env", ""), "") or cfg.get("base_url_default"))

    def ask(user: str) -> str:
        r = client.chat.completions.create(model=cfg["model"], max_tokens=1500, temperature=0,
                                           response_format={"type": "json_object"},
                                           messages=[{"role": "system", "content": JUDGE_SYS},
                                                     {"role": "user", "content": user}])
        return r.choices[0].message.content or ""
    return ask


def parse_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    return json.loads(m.group(0)) if m else {}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--threshold", type=float, default=0.9, help="Jev noul >= this counts as a high-confidence prediction")
    ap.add_argument("--judge", default="claude-opus-4-8", help="judge model key from config.yaml (must not be Jev)")
    ap.add_argument("--controls", type=int, default=3, help="random low-confidence non-gold techniques per report as negative controls")
    ap.add_argument("--control-max", type=float, default=0.05, help="controls drawn from techniques with noul below this")
    ap.add_argument("--candidates", default="data/candidates_corpus.json")
    ap.add_argument("--max-reports", type=int, help="limit reports (for a cheap dry run)")
    args = ap.parse_args()
    if args.judge == "jev-typesafe":
        raise SystemExit("refusing to use Jev to judge Jev -- pick a different --judge")

    names = json.loads((ROOT / args.candidates).read_text())
    gold, text = load_gold(), load_report_text()
    ask = make_judge(args.judge)
    random.seed(0)

    rids = list(gold)
    if args.max_reports:
        rids = rids[: args.max_reports]

    results = {"threshold": args.threshold, "judge": args.judge, "reports": {}}
    fp_supported = fp_total = ctrl_supported = ctrl_total = 0
    band = {"0.90-0.95": [0, 0], "0.95-1.00": [0, 0]}  # [supported, total]

    for rid in rids:
        n = nouls_for(rid)
        g = gold[rid]
        fps = {tid: p for tid, p in n.items() if p >= args.threshold and tid not in g}
        if not fps:
            continue
        lows = [tid for tid, p in n.items() if p < args.control_max and tid not in g]
        random.shuffle(lows)
        controls = lows[: args.controls]

        candidates = list(fps) + controls
        random.shuffle(candidates)  # blind: judge can't tell FPs from controls
        listing = "\n".join(f"- {tid}: {names.get(tid, {}).get('name', tid)}" for tid in candidates)
        user = (f"Advisory excerpt:\n\"\"\"\n{text[rid][:12000]}\n\"\"\"\n\n"
                f"Candidate ATT&CK techniques:\n{listing}\n\n"
                "For each, is it substantiated by the text? Respond as the specified JSON.")
        try:
            verdicts = parse_json(ask(user))
        except Exception as e:  # noqa: BLE001
            verdicts = {"__error__": str(e)}
        time.sleep(0.3)

        rep = {"n_fp": len(fps), "n_control": len(controls), "verdicts": {}}
        for tid in candidates:
            v = verdicts.get(tid) or {}
            supported = bool(v.get("supported")) if isinstance(v, dict) else False
            is_fp = tid in fps
            rep["verdicts"][tid] = {"is_fp": is_fp, "noul": round(n[tid], 3),
                                    "supported": supported, "quote": (v.get("quote", "") if isinstance(v, dict) else "")[:200]}
            if is_fp:
                fp_total += 1
                fp_supported += supported
                b = "0.95-1.00" if n[tid] >= 0.95 else "0.90-0.95"
                band[b][1] += 1
                band[b][0] += supported
            else:
                ctrl_total += 1
                ctrl_supported += supported
        results["reports"][rid] = rep
        print(f"  {rid}: {len(fps)} FP, {len(controls)} ctrl | "
              f"FP supported so far {fp_supported}/{fp_total}", flush=True)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2))

    print("\n" + "=" * 60)
    print(f"Judge: {args.judge}  | threshold: {args.threshold}")
    print(f"Jev high-confidence FALSE POSITIVES judged: {fp_total}")
    if fp_total:
        print(f"  substantiated by prose (real-but-untabled): {fp_supported} "
              f"({fp_supported / fp_total:.1%})")
        print(f"  genuinely wrong (over-prediction):          {fp_total - fp_supported} "
              f"({1 - fp_supported / fp_total:.1%})")
        for b, (s, t) in band.items():
            if t:
                print(f"    noul {b}: {s}/{t} substantiated ({s / t:.1%})")
    print(f"\nNegative controls (low-noul non-gold) judged: {ctrl_total}")
    if ctrl_total:
        print(f"  judge called supported: {ctrl_supported} ({ctrl_supported / ctrl_total:.1%})  "
              f"<- should be LOW; high means the judge over-accepts")
    print(f"\nwrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
