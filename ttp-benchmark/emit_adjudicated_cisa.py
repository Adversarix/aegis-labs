#!/usr/bin/env python3
"""Emit an adjudicated CISA corpus so absolute precision/recall are fair.

CISA advisory tables under-count: the prose describes more techniques than the
table tags, which penalises every model's precision (real-but-untabled
extractions score as false positives). This builds corrected gold.

Per report the candidate pool = CISA table gold UNION every technique ANY model
predicted. A judge model decides, against the PROSE, which candidates are
substantiated. Adjudicated gold = table gold PLUS substantiated candidates
(table entries are kept as a trusted floor; we only ADD, never remove).

Bias controls:
  * BLIND -- the candidate list never says which model proposed a technique,
    and order is shuffled, so the judge (which is itself a scored model) cannot
    systematically favour its own picks. It rules on prose substantiation only.
  * Negative controls -- random low-signal non-gold techniques are mixed in;
    the judge should reject them. A high control-accept rate invalidates the run.
This mitigates but does not eliminate judge bias; a human should validate a sample.

Usage:
    python emit_adjudicated_cisa.py --judge claude-opus-4-8
    python emit_adjudicated_cisa.py --judge claude-opus-4-8 --max-reports 2   # dry run
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
RAW = ROOT / "results" / "raw"
CISA = ROOT / "data" / "corpus_cisa.jsonl"
JEV = RAW / "jev-typesafe"

_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

JUDGE_SYS = (
    "You are a MITRE ATT&CK adjudicator. You are given an excerpt from a real "
    "threat-intelligence advisory and a list of candidate ATT&CK techniques. For "
    "EACH candidate, decide whether the TEXT ITSELF substantiates that the technique "
    "was used, judged against the technique's ATT&CK definition -- not whether it is "
    "merely plausible for this kind of actor. Quote the shortest supporting sentence "
    "when supported. Respond ONLY as JSON: "
    '{"<technique_id>": {"supported": true|false, "quote": "<sentence or empty>"}, ...}'
)


def norm(s: str) -> str:
    m = _ID_RE.search((s or "").upper())
    return m.group(0) if m else ""


def load_corpus() -> dict:
    return {r["id"]: r for r in (json.loads(l) for l in CISA.read_text().splitlines() if l.strip())}


def model_dirs() -> list[str]:
    return sorted(p.name for p in RAW.iterdir() if p.is_dir())


def preds(model: str, rid: str) -> list[str]:
    f = RAW / model / f"{rid}.json"
    if not f.exists():
        return []
    d = json.loads(f.read_text())
    if d.get("error"):
        return []
    return [norm(t.get("technique_id", "")) for t in (d.get("techniques") or []) if t.get("technique_id")]


def jev_nouls(rid: str) -> dict[str, float]:
    f = JEV / f"{rid}.json"
    if not f.exists():
        return {}
    return json.loads(json.loads(f.read_text()).get("raw_text") or "{}").get("nouls", {})


def make_judge(judge_key: str):
    cfg = {m["key"]: m for m in yaml.safe_load((ROOT / "config.yaml").read_text())["models"]}[judge_key]
    if cfg["provider"] == "anthropic":
        from anthropic import Anthropic
        client = Anthropic()

        def ask(user: str) -> str:
            r = client.messages.create(model=cfg["model"], max_tokens=4000, system=JUDGE_SYS,
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
        r = client.chat.completions.create(model=cfg["model"], max_tokens=4000, temperature=0,
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
    ap.add_argument("--judge", default="claude-opus-4-8")
    ap.add_argument("--candidates", default="data/candidates_corpus.json", help="id->name map for readable prompts")
    ap.add_argument("--controls", type=int, default=3)
    ap.add_argument("--out", default="data/corpus_cisa_adjudicated.jsonl")
    ap.add_argument("--audit", default="results/cisa_adjudication_audit.json")
    ap.add_argument("--max-reports", type=int)
    args = ap.parse_args()

    names = json.loads((ROOT / args.candidates).read_text())
    corpus = load_corpus()
    models = model_dirs()
    ask = make_judge(args.judge)
    random.seed(0)

    rids = list(corpus)
    if args.max_reports:
        rids = rids[: args.max_reports]

    rows, audit = [], {"judge": args.judge, "reports": {}}
    added_tot = ctrl_total = ctrl_accept = 0

    for rid in rids:
        rep = corpus[rid]
        table = {norm(t) for t in rep.get("gold_techniques", []) if norm(t)}
        pool: set[str] = set()
        for m in models:
            pool |= set(preds(m, rid))
        to_judge = sorted(pool - table)  # table kept as floor; judge the rest

        nouls = jev_nouls(rid)
        lows = [t for t, p in nouls.items() if p < 0.05 and t not in table and t not in pool]
        random.shuffle(lows)
        controls = lows[: args.controls]

        cand = to_judge + controls
        random.shuffle(cand)
        supported: set[str] = set()
        verdicts = {}
        if cand:
            listing = "\n".join(f"- {t}: {names.get(t, {}).get('name', t)}" for t in cand)
            user = (f"Advisory excerpt:\n\"\"\"\n{rep['text'][:12000]}\n\"\"\"\n\n"
                    f"Candidate ATT&CK techniques:\n{listing}\n\n"
                    "For each, is it substantiated by the text? Respond as the specified JSON.")
            try:
                verdicts = parse_json(ask(user))
            except Exception as e:  # noqa: BLE001
                verdicts = {"__error__": str(e)}
            time.sleep(0.3)
            for t in cand:
                v = verdicts.get(t) or {}
                ok = bool(v.get("supported")) if isinstance(v, dict) else False
                if t in controls:
                    ctrl_total += 1
                    ctrl_accept += ok
                elif ok:
                    supported.add(t)

        adjudicated = sorted(table | supported)
        added = sorted(supported - table)
        added_tot += len(added)
        rows.append({
            "id": rid, "source": "cisa-adjudicated",
            "url": rep.get("url", ""), "title": rep.get("title", ""),
            "text": rep["text"], "gold_techniques": adjudicated,
            "adjudication": {"table_gold": sorted(table), "added": added,
                             "n_pool": len(pool), "judge": args.judge},
        })
        audit["reports"][rid] = {
            "table": sorted(table), "added": added, "pool_judged": len(to_judge),
            "verdicts": {t: {"supported": bool((verdicts.get(t) or {}).get("supported")),
                             "quote": ((verdicts.get(t) or {}).get("quote", "") or "")[:200]}
                         for t in to_judge},
        }
        print(f"  {rid}: table {len(table)} +{len(added)} added (pool {len(pool)}) "
              f"| controls accepted {ctrl_accept}/{ctrl_total}", flush=True)

    (ROOT / args.out).write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n")
    (ROOT / args.audit).parent.mkdir(parents=True, exist_ok=True)
    (ROOT / args.audit).write_text(json.dumps(audit, indent=2))

    print("\n" + "=" * 60)
    print(f"Adjudicated {len(rows)} CISA reports (judge={args.judge})")
    print(f"Techniques ADDED vs CISA tables: {added_tot}")
    if ctrl_total:
        print(f"Negative controls accepted: {ctrl_accept}/{ctrl_total} ({ctrl_accept / ctrl_total:.1%}) "
              f"<- should be LOW")
    print(f"wrote {args.out} and {args.audit}")


if __name__ == "__main__":
    main()
