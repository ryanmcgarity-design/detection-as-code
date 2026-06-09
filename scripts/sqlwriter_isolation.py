#!/usr/bin/env python3
"""SQL-writer isolation harness.

Question: can a small local model (e.g. gemma4:e4b) do the *mechanical* SQL-writer
role well enough to feed a strong analyst? Cost analysis shows the SQL-writer is only
5-21% of tokens, so moving it to a cheap local model is attractive IF its SQL holds up.
The risk is silent wrong-evidence (valid SQL, wrong rows) that poisons the analyst.

This harness exercises the REAL SQL-writer code path (`triage._get_evidence`: same
system prompt, schema grounding with sample values, SQL extraction, execution, shaping)
on each candidate model, over a fixed set of REAL analyst questions mined from the
durable per-model corpus JSONs. For each question it also has a known-good REFERENCE
query (the SQL a trusted model produced for that exact question), so it can score:

  generated  : model emitted a SQL statement at all
  valid      : that SQL executes without error
  nonempty   : it returns >=1 row (weak relevance proxy)
  match      : its result set EXACTLY equals the reference query's result set
  overlap    : Jaccard of result rows vs reference (partial credit)

`match`/`overlap` are the load-bearing metrics — they catch plausible-but-wrong SQL
that `valid`+`nonempty` miss.

NOTE: this loads models into VRAM, so run it AFTER the main sweep finishes (it would
otherwise contend with the 3090). Local backend only.

Usage:
  uv run python scripts/sqlwriter_isolation.py \
      --models gemma4:e4b-it-q8_0,gemma4:12b-it-q8_0 [--dataset apt3] [--n 25]
"""
import argparse
import glob
import json
import logging
import time
from pathlib import Path

import src.triage as t
from src.detect import DATASETS, build_db, load_events

# Trust order for picking the reference SQL when the same question appears in
# multiple corpora — strongest/most-thorough models first.
REF_PRIORITY = [
    "claude-opus", "gemma4_31b", "gemma4_12b", "deepseek", "gpt-oss",
    "gemma4_26b", "meta_llama", "gemma4_e4b",
]


def _file_rank(name: str) -> int:
    for i, tag in enumerate(REF_PRIORITY):
        if tag in name:
            return i
    return len(REF_PRIORITY)


def mine_questions(limit=None):
    """Mine distinct (question, reference_sql, rule) from corpus JSONs, attaching the
    reference SQL from the highest-trust model that answered that question."""
    by_q: dict[str, dict] = {}
    files = sorted(glob.glob("data/runs/*__apt3.json"), key=lambda f: _file_rank(Path(f).name))
    for fp in files:
        try:
            recs = json.load(open(fp))
        except Exception:
            continue
        for r in (recs if isinstance(recs, list) else [recs]):
            trail = r.get("evidence_trail", []) or []
            sqls = (r.get("triage", {}) or {}).get("queries_run", []) or []
            for idx, ev in enumerate(trail):
                q = (ev.get("question") or "").strip()
                if not q:
                    continue
                key = q.lower()
                ref_sql = sqls[idx] if idx < len(sqls) else None
                if key not in by_q:  # first writer wins = highest trust (sorted)
                    by_q[key] = {"question": q, "ref_sql": ref_sql,
                                 "rule": r.get("rule"), "ref_src": Path(fp).name}
                elif by_q[key]["ref_sql"] is None and ref_sql:
                    by_q[key]["ref_sql"] = ref_sql
                    by_q[key]["ref_src"] = Path(fp).name
    out = list(by_q.values())
    return out[:limit] if limit else out


def _result_set(conn, sql):
    """Execute sql; return (ok, frozenset_of_rows, err)."""
    if not sql:
        return False, None, "no sql"
    try:
        cur = conn.execute(sql)
        rows = frozenset(tuple(r) for r in cur.fetchall())
        return True, rows, None
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"


def run_model(model, questions, conn, schema_writer):
    t.LLM_MODEL = model
    t.LLM_BACKEND = "local_ollama"
    rows = []
    for i, item in enumerate(questions, 1):
        q = item["question"]
        queries_run: list[str] = []
        t0 = time.time()
        call_err = None
        try:
            t._get_evidence(q, conn, schema_writer, queries_run, client=None)
        except Exception as e:
            call_err = f"{type(e).__name__}: {e}"
        dt = time.time() - t0
        sql = queries_run[-1] if queries_run else None

        ok, cand_rows, exec_err = _result_set(conn, sql)
        ref_ok, ref_rows, _ = _result_set(conn, item.get("ref_sql"))

        match = overlap = recall = over_fetch = contains_ref = None
        if ok and ref_ok:
            match = (cand_rows == ref_rows)
            union = cand_rows | ref_rows
            overlap = (len(cand_rows & ref_rows) / len(union)) if union else 1.0
            # reference-recall = fraction of reference rows present in the candidate.
            # THE load-bearing metric: the SQL-writer's job is to get the needle INTO
            # the set (§5/§8) — a correct-but-broader query should score 1.0 here.
            recall = (len(cand_rows & ref_rows) / len(ref_rows)) if ref_rows else 1.0
            contains_ref = ref_rows.issubset(cand_rows)  # full superset = ideal
            # over-fetch = how much extra it pulls vs the reference (guards against
            # "win recall by returning the whole table"). >1 = broader, ~1 = tight.
            if ref_rows:
                over_fetch = round(len(cand_rows) / len(ref_rows), 2)
            else:
                over_fetch = 1.0 if not cand_rows else float(len(cand_rows))

        rows.append({
            "i": i, "rule": item.get("rule"), "question": q,
            "sql": sql, "ref_sql": item.get("ref_sql"), "ref_src": item.get("ref_src"),
            "generated": sql is not None, "valid": ok,
            "nrows": (len(cand_rows) if ok else None),
            "ref_comparable": ref_ok,
            "match": match, "overlap": (round(overlap, 2) if overlap is not None else None),
            "ref_recall": (round(recall, 2) if recall is not None else None),
            "contains_ref": contains_ref, "over_fetch": over_fetch,
            "exec_err": exec_err if not ok else None,
            "call_err": call_err, "secs": round(dt, 1),
        })
        print(f"  [{i}/{len(questions)}] gen={sql is not None} valid={ok} "
              f"rows={len(cand_rows) if ok else '-'} recall={recall if recall is None else round(recall,2)} "
              f"contains_ref={contains_ref} overfetch={over_fetch} {dt:.1f}s")
    return rows


def _median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else None


def score(model, rows):
    n = len(rows)
    g = sum(r["generated"] for r in rows)
    v = sum(1 for r in rows if r["valid"])
    ne = sum(1 for r in rows if r["valid"] and (r["nrows"] or 0) > 0)
    comp = [r for r in rows if r["match"] is not None]
    m = sum(1 for r in comp if r["match"])
    ov = (sum(r["overlap"] for r in comp) / len(comp)) if comp else None
    rec = (sum(r["ref_recall"] for r in comp) / len(comp)) if comp else None
    contains = sum(1 for r in comp if r["contains_ref"])
    overf = _median([r["over_fetch"] for r in comp if r["over_fetch"] is not None])
    return {
        "model": model, "n": n,
        "generated_rate": round(g / n, 3) if n else 0,
        "valid_rate": round(v / n, 3) if n else 0,
        "nonempty_rate": round(ne / n, 3) if n else 0,
        "n_comparable": len(comp),
        # load-bearing: did the candidate include the reference rows (the needle)?
        "avg_ref_recall": round(rec, 3) if rec is not None else None,
        "contains_ref_rate": round(contains / len(comp), 3) if comp else None,
        "median_over_fetch": overf,
        # secondary (strict)
        "exact_match_rate": round(m / len(comp), 3) if comp else None,
        "avg_overlap": round(ov, 3) if ov is not None else None,
        "avg_secs": round(sum(r["secs"] for r in rows) / n, 1) if n else 0,
    }


def stratify_by_rule(rows):
    """Per-rule (proxy for question-type) breakdown — find WHERE small models break."""
    by_rule = {}
    for r in rows:
        by_rule.setdefault(r.get("rule") or "?", []).append(r)
    out = []
    for rule, rs in sorted(by_rule.items()):
        comp = [x for x in rs if x["match"] is not None]
        rec = (sum(x["ref_recall"] for x in comp) / len(comp)) if comp else None
        out.append({
            "rule": rule, "n": len(rs),
            "valid_rate": round(sum(1 for x in rs if x["valid"]) / len(rs), 2),
            "avg_ref_recall": round(rec, 2) if rec is not None else None,
        })
    return out


def _param_size(model):
    """Best-effort param count from the local ollama for size-ordering the curve."""
    import urllib.request
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/show",
            data=json.dumps({"name": model}).encode(), method="POST")
        with urllib.request.urlopen(req, timeout=8) as r:
            ps = json.load(r).get("details", {}).get("parameter_size", "?")
        return ps
    except Exception:
        return "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", required=True, help="comma-separated ollama model tags")
    ap.add_argument("--dataset", default="apt3")
    ap.add_argument("--n", type=int, default=None, help="limit number of questions")
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING)  # silence per-call INFO

    questions = mine_questions(args.n)
    withref = sum(1 for q in questions if q["ref_sql"])
    print(f"Mined {len(questions)} distinct questions ({withref} with a reference query)")

    events = load_events(DATASETS[args.dataset])
    conn = build_db(events)
    schema_writer = t._get_schema_for_writer(conn)

    out = {"dataset": args.dataset, "questions": questions, "results": {}, "scores": []}
    for model in [m.strip() for m in args.models.split(",") if m.strip()]:
        print(f"\n=== {model} ===")
        rows = run_model(model, questions, conn, schema_writer)
        out["results"][model] = rows
        s = score(model, rows)
        s["param_size"] = _param_size(model)
        s["by_rule"] = stratify_by_rule(rows)
        out["scores"].append(s)
        print(f"  -> valid={s['valid_rate']:.0%} ref_recall={s['avg_ref_recall']} "
              f"contains_ref={s['contains_ref_rate']} over_fetch={s['median_over_fetch']} "
              f"(match={s['exact_match_rate']}) avg={s['avg_secs']}s")

    # order the curve by parameter count (small -> large)
    def _pnum(s):
        try:
            return float(str(s.get("param_size", "?")).rstrip("Bb"))
        except ValueError:
            return 1e9
    out["scores"].sort(key=_pnum)

    outp = Path("data/runs/sqlwriter_isolation.json")
    outp.write_text(json.dumps(out, indent=2))
    print(f"\nWrote {outp}")

    def fmt(x, pct=False):
        if x is None:
            return "-"
        return f"{x:.0%}" if pct else str(x)

    print("\n=== DEGRADATION CURVE (small -> large) ===")
    print(f"{'model':<34}{'size':>7}{'valid':>7}{'recall':>8}{'has_ref':>8}"
          f"{'ovrftch':>8}{'match':>7}{'sec':>6}")
    for s in out["scores"]:
        print(f"{s['model']:<34}{str(s['param_size']):>7}{s['valid_rate']:>7.0%}"
              f"{fmt(s['avg_ref_recall']):>8}{fmt(s['contains_ref_rate'], True):>8}"
              f"{fmt(s['median_over_fetch']):>8}{fmt(s['exact_match_rate'], True):>7}"
              f"{s['avg_secs']:>6}")
    print("recall = fraction of reference rows the candidate returned (the needle-in-set "
          "metric); has_ref = full superset; ovrftch = rows vs reference (lower=tighter).")

    print("\n=== per-rule ref_recall (where models break) ===")
    rules = sorted({br['rule'] for s in out['scores'] for br in s['by_rule']})
    print(f"{'model':<34}" + "".join(f"{r[:10]:>11}" for r in rules))
    for s in out["scores"]:
        rr = {br['rule']: br['avg_ref_recall'] for br in s['by_rule']}
        print(f"{s['model']:<34}" + "".join(f"{fmt(rr.get(r)):>11}" for r in rules))


if __name__ == "__main__":
    main()
