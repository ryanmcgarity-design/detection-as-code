#!/usr/bin/env python3
"""Quantify the two 'don't miss the needle' levers on the real APT3 data (CPU only).

1) CLOCK SKEW: per-event, multiple timestamp fields disagree (envelope vs Sysmon vs
   ingest). Measure the within-row delta distribution so a time-only window can be
   padded by the *measured* skew instead of a guess.
2) ENTROPY/CARDINALITY: for the recon window, profile how homogeneous vs heterogeneous
   key columns are -> tells you whether a LIMIT'd dump is safe (homogeneous: aggregate
   is the answer) or dangerous (heterogeneous + truncated: needle can hide).
"""
import logging
from datetime import datetime
from statistics import median

logging.basicConfig(level=logging.ERROR)
from src.detect import DATASETS, build_db, load_events  # noqa: E402


def parse_ts(s):
    if not s or not isinstance(s, str):
        return None
    t = s.strip().replace("Z", "").replace("T", " ")
    t = t.split("+")[0].strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(t, fmt)
        except ValueError:
            continue
    return None


def skew(conn, a, b, limit=20000):
    cur = conn.execute(
        f'SELECT "{a}", "{b}" FROM logs WHERE "{a}" IS NOT NULL AND "{b}" IS NOT NULL LIMIT {limit}'
    )
    deltas = []
    for va, vb in cur.fetchall():
        ta, tb = parse_ts(va), parse_ts(vb)
        if ta and tb:
            deltas.append(abs((ta - tb).total_seconds()))
    if not deltas:
        return None
    deltas.sort()
    return {
        "n": len(deltas),
        "median_s": round(median(deltas), 3),
        "p95_s": round(deltas[int(0.95 * (len(deltas) - 1))], 3),
        "max_s": round(deltas[-1], 3),
        "nonzero_%": round(100 * sum(1 for d in deltas if d > 0.0005) / len(deltas)),
    }


def cardinality(conn, where, col):
    total = conn.execute(f"SELECT COUNT(*) FROM logs WHERE {where}").fetchone()[0]
    distinct = conn.execute(
        f'SELECT COUNT(DISTINCT "{col}") FROM logs WHERE {where} AND "{col}" IS NOT NULL'
    ).fetchone()[0]
    return total, distinct


def main():
    conn = build_db(load_events(DATASETS["apt3"]))

    print("=== 1) CLOCK SKEW (within-row, |Δ| seconds) ===")
    for a, b in [("UtcTime", "TimeCreated"),
                 ("@timestamp", "TimeCreated"),
                 ("@timestamp", "UtcTime"),
                 ("ProcessCreationTime", "TimeCreated")]:
        s = skew(conn, a, b)
        print(f"  {a:>20s} vs {b:<14s}: {s}")

    print("\n=== 2) ENTROPY / CARDINALITY (recon window on HR001) ===")
    # the net.exe recon burst: one host, ~30-min window around the alert
    win = ("Computer LIKE '%HR001%' AND TimeCreated BETWEEN "
           "'2019-05-14T22:30:00' AND '2019-05-14T23:00:00'")
    for label, where, col in [
        ("all process-create CommandLine", win + " AND EventID=1", "CommandLine"),
        ("network dest IPs (EID3)", win + " AND EventID=3", "DestinationIp"),
        ("network dest ports (EID3)", win + " AND EventID=3", "DestinationPort"),
        ("images launched", win + " AND EventID=1", "Image"),
    ]:
        total, distinct = cardinality(conn, where, col)
        shape = "—"
        if total:
            ratio = distinct / total
            shape = ("HOMOGENEOUS → aggregate is the answer" if ratio < 0.25
                     else "HETEROGENEOUS → LIMIT unsafe if truncated; anomaly-rank")
        trunc = "TRUNCATED@20" if total > 20 else "fits in 20"
        print(f"  {label:<34s} total={total:<5d} distinct={distinct:<4d} "
              f"({trunc}) -> {shape}")

    # command-variety as a recon signature: distinct discovery verbs from one user
    print("\n=== bonus: command entropy as a verdict feature ===")
    row = conn.execute(
        f"SELECT COUNT(*) , COUNT(DISTINCT CommandLine) FROM logs WHERE {win} AND EventID=1"
    ).fetchone()
    print(f"  HR001 22:30-23:00: {row[0]} process events, {row[1]} DISTINCT command lines")
    print("  (high distinct-command count in a tight window = recon burst signature)")


if __name__ == "__main__":
    main()
