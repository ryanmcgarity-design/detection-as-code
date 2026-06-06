"""
Metrics layer: scores the detection layer against ground truth labels.

Detection-layer metrics (computed here):
  - Precision:       TP / (TP + FP)
  - Recall:          TP / (TP + FN)
  - False-positive rate: FP / (FP + TN)  — how much benign noise we generate

Triage-layer metrics are added in step 7.

Honesty notes:
  - Ground truth comes from known attack patterns in the dataset, not from the
    LLM. See src/ground_truth.py for labeling logic.
  - Events that are neither clearly malicious nor clearly benign are excluded
    from scoring rather than guessed at.
  - MTTD is NOT reported — this is static replay data; no time-to-detect exists.
"""

import json
import logging
from pathlib import Path

from src.ground_truth import is_malicious_process_creation, label_event

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"
DATASET = DATA_DIR / "empire_apt3_2019-05-14223117.json"
MATCHES_FILE = DATA_DIR / "matches.json"
RESULTS_FILE = Path(__file__).parent.parent / "docs" / "results.md"


def load_events(path: Path) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def build_ground_truth(events: list[dict]) -> tuple[set[str], set[str]]:
    """Return (malicious_timestamps, benign_timestamps) for process creation events."""
    malicious, benign = set(), set()
    for e in events:
        label = label_event(e)
        ts = e.get("@timestamp", "")
        ed = e.get("event_data", {})
        # Use timestamp + image as a unique key (timestamp alone can collide)
        key = f"{ts}|{ed.get('Image', '')}"
        if label == "malicious":
            malicious.add(key)
        elif label == "benign":
            benign.add(key)
    return malicious, benign


def score_detection(matches: list[dict], malicious: set[str], benign: set[str]) -> dict:
    """Compute precision, recall, FP rate for the detection layer."""
    matched_keys = {f"{m['timestamp']}|{m['image']}" for m in matches}

    tp = len(matched_keys & malicious)
    fp = len(matched_keys & benign)
    fn = len(malicious - matched_keys)
    tn = len(benign - matched_keys)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "fp_rate": round(fp_rate, 4),
        "f1": round(f1, 4),
        "total_malicious_labeled": len(malicious),
        "total_benign_labeled": len(benign),
        "total_matches": len(matches),
    }


def _norm_verdict(v) -> str:
    """Normalize a disposition/verdict to its bare string ('malicious_true_positive')."""
    return str(v or "").lower().rsplit(".", 1)[-1]


def _decision(disposition: str) -> str:
    """Collapse a disposition to the one bit triage must answer: did bad occur?
      malicious_true_positive -> 'bad'
      benign_true_positive / false_positive -> 'no_bad'
      uncertain / anything else -> 'undecided' (a non-decision, scored wrong)."""
    d = _norm_verdict(disposition)
    if d == "malicious_true_positive":
        return "bad"
    if d in ("benign_true_positive", "false_positive"):
        return "no_bad"
    return "undecided"


def score_triage(records: list[dict]) -> dict:
    """Score LLM triage dispositions against ground truth.

    Ground truth per alert (src/ground_truth.py, never the LLM): a command that
    matches the APT3 playbook -> bad occurred; otherwise -> no bad. The LLM's
    disposition is collapsed to that same bit ('did bad occur?'):
    malicious_true_positive='bad'; benign_true_positive/false_positive='no_bad';
    uncertain/fallback='undecided' (a non-decision, counted wrong).
    """
    n = len(records)
    correct = uncertain = fallback = 0
    real_bad = bad_hits = 0        # recall: of the real 'bad', how many did the LLM call 'bad'
    llm_bad = bad_correct = 0      # precision: of the LLM's 'bad' calls, how many were right
    conf_correct: list[float] = []
    conf_wrong: list[float] = []
    rows = []
    for r in records:
        gt_malicious = is_malicious_process_creation(r.get("image", ""), r.get("command_line", ""))
        gt = "bad" if gt_malicious else "no_bad"
        t = r.get("triage") or {}
        disp = _norm_verdict(t.get("disposition"))
        llm = _decision(disp)
        conf = float(t.get("confidence") or 0.0)
        is_fallback = bool(r.get("fallback_used"))
        is_correct = llm == gt

        if is_correct:
            correct += 1
        if is_fallback:
            fallback += 1
        if llm == "undecided":
            uncertain += 1
        if gt == "bad":
            real_bad += 1
            if llm == "bad":
                bad_hits += 1
        if llm == "bad":
            llm_bad += 1
            if gt == "bad":
                bad_correct += 1
        (conf_correct if is_correct else conf_wrong).append(conf)
        rows.append({"cmd": (r.get("command_line", "") or "")[:48], "gt": gt,
                     "llm": disp or llm, "conf": conf, "fallback": is_fallback, "correct": is_correct})

    avg = lambda xs: round(sum(xs) / len(xs), 3) if xs else None
    return {
        "n": n,
        "verdict_accuracy": round(correct / n, 4) if n else 0.0,
        "tp_recall": round(bad_hits / real_bad, 4) if real_bad else None,
        "tp_precision": round(bad_correct / llm_bad, 4) if llm_bad else None,
        "uncertain_rate": round(uncertain / n, 4) if n else 0.0,
        "fallback_rate": round(fallback / n, 4) if n else 0.0,
        "avg_conf_correct": avg(conf_correct),
        "avg_conf_wrong": avg(conf_wrong),
        "rows": rows,
    }


def print_triage_scorecard(m: dict, label: str = "") -> None:
    acc = m["verdict_accuracy"]
    print(f"\n=== Triage quality {('['+label+'] ') if label else ''}(n={m['n']}) ===")
    print(f"  verdict_accuracy : {acc:.1%}")
    print(f"  TP recall        : {m['tp_recall']}   TP precision: {m['tp_precision']}")
    print(f"  uncertain_rate   : {m['uncertain_rate']:.1%}   fallback_rate: {m['fallback_rate']:.1%}")
    print(f"  conf(correct)    : {m['avg_conf_correct']}   conf(wrong): {m['avg_conf_wrong']}")
    print("  per-alert:")
    for r in m["rows"]:
        flag = "✓" if r["correct"] else "✗"
        fb = " [fallback]" if r["fallback"] else ""
        print(f"    {flag} gt={r['gt']:21s} llm={r['llm']:21s} conf={r['conf']}{fb}  {r['cmd']}")


def compare_models(case_files: list[Path]) -> dict:
    """Cross-model agreement over the per-model case corpus (data/runs/*.json).

    For each alert, collect every model's verdict + the ground-truth label, then
    bucket: agree+correct (trustworthy), agree+WRONG (systematic blind spot — the
    dangerous case), or disagree (hard case → human review). Agreement needs no
    ground truth; the buckets that involve 'correct' use it.
    """
    runs: dict[str, dict] = {}      # alert_key -> {model: {verdict, gt, correct}}
    models: list[str] = []
    for f in sorted(case_files):
        cases = json.loads(f.read_text())
        if not cases:
            continue
        model = cases[0].get("model", f.stem)
        if model not in models:
            models.append(model)
        for c in cases:
            key = f"{c.get('timestamp', '')}|{c.get('command_line', '')}"
            llm = _decision((c.get("triage") or {}).get("disposition"))
            gt = c.get("ground_truth_verdict", "")
            runs.setdefault(key, {})[model] = {"verdict": llm, "gt": gt, "correct": llm == gt}

    agree_correct = agree_wrong = disagree = 0
    rows = []
    for key, permodel in runs.items():
        gt = next(iter(permodel.values()))["gt"]
        verdicts = {m: d["verdict"] for m, d in permodel.items()}
        all_agree = len(set(verdicts.values())) == 1
        all_correct = all(d["correct"] for d in permodel.values())
        if all_agree and all_correct:
            cat = "agree+correct"; agree_correct += 1
        elif all_agree:
            cat = "agree+WRONG"; agree_wrong += 1
        else:
            cat = "disagree"; disagree += 1
        rows.append({"cmd": key.split("|", 1)[-1][:48], "gt": gt, "verdicts": verdicts, "category": cat})

    per_model_accuracy = {}
    for m in models:
        items = [d[m] for d in runs.values() if m in d]
        per_model_accuracy[m] = round(sum(x["correct"] for x in items) / len(items), 4) if items else None

    return {"models": models, "n_alerts": len(runs),
            "agree_correct": agree_correct, "agree_wrong": agree_wrong, "disagree": disagree,
            "per_model_accuracy": per_model_accuracy, "rows": rows}


def print_model_comparison(c: dict) -> None:
    print(f"\n=== Cross-model comparison ({len(c['models'])} models, {c['n_alerts']} alerts) ===")
    for m, acc in c["per_model_accuracy"].items():
        print(f"  accuracy[{m}] = {acc if acc is None else f'{acc:.1%}'}")
    print(f"  agree+correct: {c['agree_correct']}   agree+WRONG (blind spot): {c['agree_wrong']}   disagree: {c['disagree']}")
    print("  per-alert:")
    for r in c["rows"]:
        print(f"    [{r['category']:13s}] gt={r['gt']:21s} {r['verdicts']}  {r['cmd']}")


def render_results(detection_metrics: dict) -> str:
    dm = detection_metrics
    return f"""# Detection Results

> Generated by `src/metrics.py` against the OTRF APT3 empire dataset.
> Ground truth: {dm['total_malicious_labeled']} labeled malicious events,
> {dm['total_benign_labeled']} labeled benign events (process creation only).
> Events not clearly malicious or benign are excluded from scoring.

## Detection Layer

| Metric | Value |
|--------|-------|
| True Positives | {dm['tp']} |
| False Positives | {dm['fp']} |
| False Negatives | {dm['fn']} |
| True Negatives | {dm['tn']} |
| **Precision** | **{dm['precision']:.1%}** |
| **Recall** | **{dm['recall']:.1%}** |
| **False-Positive Rate** | **{dm['fp_rate']:.1%}** |
| F1 | {dm['f1']:.3f} |

## Limitations and Honest Caveats

- **Ground truth circularity.** Our rules and ground truth labels are both
  derived from the same observed attack patterns. This produces artificially
  high scores and does NOT demonstrate generalization to unseen attacks. In
  production, ground truth would come from an independent red-team log or
  authoritative SIEM labels.
- **MTTD not reported.** This is static replay data; mean-time-to-detect has no
  meaning without a live event stream.
- **FN scope.** Techniques in the dataset our rules do not cover (e.g. `net use`
  credential spray, `dsregcmd`, lateral movement via `wmic`) are excluded from
  ground truth rather than counted as FNs, because they are ambiguous without
  additional context. The true FN rate against a complete attack taxonomy is
  higher than reported here.
- **FP scope limited.** Only known-benign Windows background processes are in
  the benign set. FP rate against production telemetry with broader process
  diversity would be higher, particularly for the `net.exe` and `cmd.exe` rules.
"""


def main() -> dict:
    if not DATASET.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET} — run data/fetch.sh first")
    if not MATCHES_FILE.exists():
        raise FileNotFoundError(f"Matches not found: {MATCHES_FILE} — run src/detect.py first")

    events = load_events(DATASET)
    matches = json.loads(MATCHES_FILE.read_text())

    malicious, benign = build_ground_truth(events)
    log.info("Ground truth: %d malicious, %d benign process creation events",
             len(malicious), len(benign))

    detection_metrics = score_detection(matches, malicious, benign)
    log.info("Detection: precision=%.1f%% recall=%.1f%% fp_rate=%.1f%%",
             detection_metrics["precision"] * 100,
             detection_metrics["recall"] * 100,
             detection_metrics["fp_rate"] * 100)

    RESULTS_FILE.parent.mkdir(exist_ok=True)
    RESULTS_FILE.write_text(render_results(detection_metrics))
    log.info("Results written to %s", RESULTS_FILE)

    return detection_metrics


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser()
    parser.add_argument("--triage", help="Score a triage results JSON (e.g. data/triage_apt3.json)")
    parser.add_argument("--label", default="", help="Label for the triage scorecard (e.g. model name)")
    parser.add_argument("--compare", action="store_true",
                        help="Cross-model comparison over the per-model corpus in data/runs/")
    args = parser.parse_args()

    if args.compare:
        files = sorted((DATA_DIR / "runs").glob("*.json"))
        if not files:
            print("No per-model case files in data/runs/ — run triage on a few models first.")
        else:
            print_model_comparison(compare_models(files))
    elif args.triage:
        records = json.loads(Path(args.triage).read_text())
        print_triage_scorecard(score_triage(records), label=args.label)
    else:
        main()
