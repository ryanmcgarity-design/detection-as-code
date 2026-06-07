"""
Detection layer: loads a dataset into SQLite, compiles Sigma rules via pySigma,
runs each rule as a SQL query, and writes normalized matches to an output file.

Usage:
    python src/detect.py                        # APT3 training set -> data/matches.json
    python src/detect.py --dataset apt29_day1   # APT29 day 1 -> data/matches_apt29_day1.json
    python src/detect.py --dataset apt29_day2   # APT29 day 2 -> data/matches_apt29_day2.json

APT3 is the training/development dataset. APT29 is the held-out validation set
used for independent recall measurement and LLM triage evaluation.
"""

import argparse
import glob
import json
import logging
import sqlite3
import sys
from pathlib import Path

from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"
RULES_DIR = Path(__file__).parent.parent / "rules"
TABLE = "logs"

DATASETS = {
    "apt3": DATA_DIR / "empire_apt3_2019-05-14223117.json",
    "apt29_day1": DATA_DIR / "apt29_evals_day1_manual_2020-05-01225525.json",
    "apt29_day2": DATA_DIR / "apt29_evals_day2_manual_2020-05-02035409.json",
}

def output_path(dataset_key: str) -> Path:
    if dataset_key == "apt3":
        return DATA_DIR / "matches.json"
    return DATA_DIR / f"matches_{dataset_key}.json"


def load_events(path: Path) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    log.info("Loaded %d events from %s", len(events), path.name)
    return events


def flatten_event(event: dict) -> dict:
    """Flatten event_data fields to top level for SQL querying.

    SQLite columns are case-insensitive, so top-level fields that collide with
    event_data fields (e.g. ProcessID vs ProcessId) are prefixed with '_raw_'
    to avoid duplicate column names. event_data fields win because Sigma field
    names map to them.
    """
    ed_keys_lower = {k.lower() for k in event.get("event_data", {})}

    flat: dict = {}
    for k, v in event.items():
        if k in ("event_data",) or isinstance(v, dict):
            continue
        if k.lower() in ed_keys_lower:
            flat[f"_raw_{k}"] = v
        else:
            flat[k] = v

    flat.update(event.get("event_data", {}))

    # Normalize to Sigma pipeline expected field names.
    # APT3 (winlogbeat): channel in log_name, event id in event_id (lowercase).
    # APT29 (nxlog/flat): Channel and EventID already top-level with correct names.
    if not flat.get("Channel"):
        flat["Channel"] = event.get("log_name", "")
    if flat.get("EventID") is None:
        flat["EventID"] = event.get("event_id")
    flat["TimeCreated"] = event.get("@timestamp", "")
    flat["Computer"] = (flat.get("Computer") or flat.get("Hostname")
                        or event.get("computer_name", ""))
    return flat


def build_db(events: list[dict]) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row

    flat_events = [flatten_event(e) for e in events]

    # Deduplicate column names case-insensitively; first occurrence wins
    seen_lower: set[str] = set()
    all_keys: list[str] = []
    for fe in flat_events:
        for k in fe.keys():
            if k.lower() not in seen_lower:
                seen_lower.add(k.lower())
                all_keys.append(k)

    cols = ", ".join(f'"{k}" TEXT' for k in all_keys)
    conn.execute(f"CREATE TABLE {TABLE} ({cols})")

    for fe in flat_events:
        keys = sorted(fe.keys())
        placeholders = ", ".join("?" for _ in keys)
        col_names = ", ".join(f'"{k}"' for k in keys)
        conn.execute(
            f"INSERT INTO {TABLE} ({col_names}) VALUES ({placeholders})",
            [str(fe[k]) if fe[k] is not None else None for k in keys],
        )

    conn.commit()
    log.info("Built in-memory SQLite DB with %d rows, %d columns", len(flat_events), len(all_keys))
    return conn


def compile_rules() -> list[tuple[str, str, SigmaCollection]]:
    """Returns list of (rule_path, title, compiled_query) tuples."""
    pipeline = sysmon_pipeline() + windows_logsource_pipeline()
    backend = sqliteBackend(processing_pipeline=pipeline)

    compiled = []
    for rule_path in sorted(glob.glob(str(RULES_DIR / "*.yml"))):
        with open(rule_path) as f:
            rule_text = f.read()
        try:
            collection = SigmaCollection.from_yaml(rule_text)
            queries = backend.convert(collection)
            if queries:
                query = queries[0].replace("<TABLE_NAME>", TABLE)
                title = collection.rules[0].title if collection.rules else rule_path
                compiled.append((rule_path, title, query))
        except Exception as e:
            log.warning("Failed to compile %s: %s", rule_path, e)

    log.info("Compiled %d/%d rules", len(compiled), len(glob.glob(str(RULES_DIR / "*.yml"))))
    return compiled


def run_detections(conn: sqlite3.Connection, rules: list[tuple]) -> list[dict]:
    matches = []
    for rule_path, title, query in rules:
        try:
            rows = conn.execute(query).fetchall()
            for row in rows:
                match = {
                    "rule": Path(rule_path).stem,
                    "title": title,
                    "timestamp": row["TimeCreated"] if "TimeCreated" in row.keys() else "",
                    "computer": row["Computer"] if "Computer" in row.keys() else "",
                    "image": row["Image"] if "Image" in row.keys() else "",
                    "command_line": row["CommandLine"] if "CommandLine" in row.keys() else "",
                    "event_id": row["EventID"] if "EventID" in row.keys() else "",
                    "channel": row["Channel"] if "Channel" in row.keys() else "",
                }
                matches.append(match)
        except Exception as e:
            log.warning("Error running rule %s: %s", rule_path, e)

    log.info("Found %d total matches across all rules", len(matches))
    return matches


def main(dataset_key: str = "apt3") -> list[dict]:
    dataset_path = DATASETS.get(dataset_key)
    if dataset_path is None:
        log.error("Unknown dataset '%s'. Valid: %s", dataset_key, list(DATASETS))
        sys.exit(1)
    if not dataset_path.exists():
        log.error("Dataset not found: %s — run data/fetch.sh first", dataset_path)
        sys.exit(1)

    events = load_events(dataset_path)
    conn = build_db(events)
    rules = compile_rules()
    matches = run_detections(conn, rules)

    out = output_path(dataset_key)
    out.write_text(json.dumps(matches, indent=2))
    log.info("Matches written to %s", out)
    return matches


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset",
        choices=list(DATASETS),
        default="apt3",
        help="Dataset to run detections against (default: apt3)",
    )
    args = parser.parse_args()
    main(args.dataset)
