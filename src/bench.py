"""
Model benchmark runner.

Runs triage against a sample of matches for each model in models.yaml,
records verdict/confidence/fallback/latency, and writes a comparison table.

Usage:
    python src/bench.py                          # all models, apt3 dataset, 5 matches
    python src/bench.py --dataset apt29_day1     # different dataset
    python src/bench.py --sample 10              # more matches per model
    python src/bench.py --model deckard-q6       # single model only

Output:
    data/bench_results.json    — full per-match results
    data/bench_summary.json    — aggregated per-model stats
"""

import argparse
import json
import logging
import os
import random
import time
from pathlib import Path

import yaml

from src.detect import DATASETS, build_db, load_events, output_path
from src.triage import _get_schema_hint, _make_client, triage_match

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"
MODELS_FILE = Path(__file__).parent.parent / "models.yaml"


def load_model_configs(filter_name: str = None) -> list[dict]:
    with open(MODELS_FILE) as f:
        cfg = yaml.safe_load(f)
    models = cfg.get("models", [])
    if filter_name:
        models = [m for m in models if m["name"] == filter_name]
    return models


def run_bench(dataset_key: str = "apt3", sample_size: int = 5, filter_model: str = None):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    matches_file = output_path(dataset_key)
    if not matches_file.exists():
        raise FileNotFoundError(f"{matches_file} not found — run src/detect.py first")

    all_matches = json.loads(matches_file.read_text())
    matches = random.sample(all_matches, min(sample_size, len(all_matches)))
    log.info("Benchmarking %d matches from %s", len(matches), matches_file.name)

    events = load_events(DATASETS[dataset_key])
    conn = build_db(events)
    schema_hint = _get_schema_hint(conn)

    model_configs = load_model_configs(filter_model)
    if not model_configs:
        raise ValueError(f"No models found in {MODELS_FILE}" +
                         (f" matching '{filter_model}'" if filter_model else ""))

    all_results: list[dict] = []
    summary: list[dict] = []

    for model_cfg in model_configs:
        model_name = model_cfg["name"]
        backend = model_cfg.get("backend", "local_ollama")
        mode = model_cfg.get("mode", "auto")

        log.info("=== Model: %s | backend: %s | mode: %s ===", model_name, backend, mode)

        if backend == "1min_ai":
            log.warning("Skipping %s — 1min.ai backend not yet implemented", model_name)
            continue

        # Temporarily override module-level vars for this model
        import src.triage as triage_mod
        original_model = triage_mod.LLM_MODEL
        original_backend = triage_mod.LLM_BACKEND
        try:
            triage_mod.LLM_MODEL = model_name
            triage_mod.LLM_BACKEND = backend

            if backend == "remote_ollama":
                remote_url = os.environ.get("LLM_REMOTE_URL", "")
                if not remote_url:
                    log.warning("Skipping %s — LLM_REMOTE_URL not set", model_name)
                    continue

            client = _make_client()

            model_results = []
            for i, match in enumerate(matches):
                log.info("  [%d/%d] %s", i + 1, len(matches), match["rule"])
                t0 = time.monotonic()
                record = triage_match(match, conn, client, schema_hint, mode=mode)
                elapsed = round(time.monotonic() - t0, 2)

                result = {
                    "model": model_name,
                    "backend": backend,
                    "mode": mode,
                    "rule": match["rule"],
                    "verdict": record.triage.verdict if record.triage else None,
                    "priority": record.triage.priority if record.triage else None,
                    "confidence": record.triage.confidence if record.triage else None,
                    "fallback_used": record.fallback_used,
                    "fallback_reason": record.fallback_reason,
                    "queries_run": len(record.triage.queries_run) if record.triage else 0,
                    "latency_s": elapsed,
                }
                model_results.append(result)
                log.info("    verdict=%s fallback=%s latency=%.1fs",
                         result["verdict"], result["fallback_used"], elapsed)

            all_results.extend(model_results)

            # Per-model aggregate stats
            n = len(model_results)
            n_fallback = sum(1 for r in model_results if r["fallback_used"])
            avg_confidence = (
                sum(r["confidence"] for r in model_results if r["confidence"] is not None) /
                max(1, sum(1 for r in model_results if r["confidence"] is not None))
            )
            avg_latency = sum(r["latency_s"] for r in model_results) / max(1, n)
            avg_queries = sum(r["queries_run"] for r in model_results) / max(1, n)

            summary.append({
                "model": model_name,
                "backend": backend,
                "mode": mode,
                "matches_run": n,
                "fallback_rate": round(n_fallback / max(1, n), 3),
                "avg_confidence": round(avg_confidence, 3),
                "avg_latency_s": round(avg_latency, 1),
                "avg_queries_per_match": round(avg_queries, 1),
                "verdicts": {
                    v: sum(1 for r in model_results if r["verdict"] == v)
                    for v in ("true_positive", "likely_false_positive", "uncertain")
                },
            })

        finally:
            triage_mod.LLM_MODEL = original_model
            triage_mod.LLM_BACKEND = original_backend

    # Write outputs
    results_out = DATA_DIR / "bench_results.json"
    summary_out = DATA_DIR / "bench_summary.json"
    results_out.write_text(json.dumps(all_results, indent=2))
    summary_out.write_text(json.dumps(summary, indent=2))

    log.info("Results: %s", results_out)
    log.info("Summary: %s", summary_out)

    # Print summary table
    print("\n=== BENCHMARK SUMMARY ===")
    print(f"{'Model':<35} {'Mode':<8} {'Fallback%':<12} {'AvgConf':<10} {'AvgLatency':<12} {'AvgQueries'}")
    print("-" * 90)
    for s in summary:
        print(
            f"{s['model']:<35} {s['mode']:<8} "
            f"{s['fallback_rate']*100:>6.0f}%      "
            f"{s['avg_confidence']:>6.3f}     "
            f"{s['avg_latency_s']:>7.1f}s      "
            f"{s['avg_queries_per_match']:.1f}"
        )

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=list(DATASETS), default="apt3")
    parser.add_argument("--sample", type=int, default=5, help="Matches per model (default 5)")
    parser.add_argument("--model", default=None, help="Run only this model name")
    args = parser.parse_args()
    run_bench(args.dataset, args.sample, args.model)
