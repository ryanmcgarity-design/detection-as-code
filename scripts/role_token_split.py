#!/usr/bin/env python3
"""Parse 1min.ai cost logs and split tokens/credits by role.

Each model API call logs a credit line:
  INFO 1min.ai <model>: <cr> credits (in=<n> out=<n> tok) | run total=...
followed by a descriptor line that reveals the role:
  'analyst turn #N'   -> analyst (the reasoning role)
  'evidence sql='     -> sql-writer (the mechanical role)
  anything else       -> other (closing/disposition/reviewer)

Usage: role_token_split.py <logfile> [logfile ...]
"""
import re
import sys

# Handles both meter formats:
#   old: (in=1261 out=195 tok)
#   new: (in=1137/614 out=56/121 tok/cr)   -> token count is the first number
CRED = re.compile(r"1min\.ai\s+(\S+):\s+(\d+)\s+credits\s+\(in=(\d+)(?:/\d+)?\s+out=(\d+)(?:/\d+)?")


def classify(next_line: str) -> str:
    s = next_line.lower()
    if "analyst turn" in s:
        return "analyst"
    if "evidence sql" in s:
        return "sql_writer"
    return "other"


def parse(path: str):
    with open(path) as f:
        lines = f.readlines()
    # role -> [calls, in, out, credits]
    agg: dict[str, list[int]] = {}
    for i, line in enumerate(lines):
        m = CRED.search(line)
        if not m:
            continue
        model, cr, tin, tout = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
        # find the next descriptor (non-credit) line to classify this call
        role = "other"
        for j in range(i + 1, min(i + 4, len(lines))):
            if CRED.search(lines[j]):
                break
            if "analyst turn" in lines[j].lower() or "evidence sql" in lines[j].lower():
                role = classify(lines[j])
                break
        a = agg.setdefault(role, [0, 0, 0, 0])
        a[0] += 1
        a[1] += tin
        a[2] += tout
        a[3] += cr
    return agg


def report(path: str):
    agg = parse(path)
    if not agg:
        print(f"\n{path}: (no credit lines found)")
        return
    tot = [sum(agg[r][k] for r in agg) for k in range(4)]
    print(f"\n=== {path.split('/')[-1]} ===")
    print(f"{'role':<11}{'calls':>6}{'in_tok':>10}{'out_tok':>10}{'credits':>10}{'cr%':>7}")
    for role in ("analyst", "sql_writer", "other"):
        if role not in agg:
            continue
        c, ti, to, cr = agg[role]
        pct = 100 * cr / tot[3] if tot[3] else 0
        print(f"{role:<11}{c:>6}{ti:>10}{to:>10}{cr:>10}{pct:>6.0f}%")
    print(f"{'TOTAL':<11}{tot[0]:>6}{tot[1]:>10}{tot[2]:>10}{tot[3]:>10}")
    if "analyst" in agg and "sql_writer" in agg:
        a_in_avg = agg["analyst"][1] / agg["analyst"][0]
        s_in_avg = agg["sql_writer"][1] / agg["sql_writer"][0]
        print(f"  avg input tokens/call: analyst={a_in_avg:.0f}  sql_writer={s_in_avg:.0f}")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        report(p)
