"""Derive credits-per-input-token and credits-per-output-token per model from the
1min.ai per-call logs.

Two log formats exist:
  new: "1min.ai <model>: <cr> credits (in=<it>/<ic> out=<ot>/<oc> tok/cr) ..."
       -> exact split credits, rates = sum(ic)/sum(it), sum(oc)/sum(ot)
  old: "1min.ai <model>: <cr> credits (in=<it> out=<ot> tok) ..."
       -> only total credit; recover (in_rate, out_rate) by least-squares fit
          of cr ~ a*it + b*ot across the run's calls.
"""
import glob
import re

NEW = re.compile(r"1min\.ai (\S+): (\d+) credits \(in=(\d+)/(\d+) out=(\d+)/(\d+) tok/cr\)")
OLD = re.compile(r"1min\.ai (\S+): (\d+) credits \(in=(\d+) out=(\d+) tok\)")

# model -> list of dicts {cr, it, ot, ic, oc(optional)}
data: dict[str, list[dict]] = {}
# Per-call lines are tee'd into both the individual log AND the wrapper driver log,
# so the same call appears in multiple files. Each line carries "run total ... over N
# calls" with N strictly increasing per run, so an exact-identical matched line is a
# true duplicate — dedupe on it.
seen: set[str] = set()

for path in glob.glob("data/runs/_1min_*.log"):
    with open(path) as f:
        for line in f:
            key = line.strip()
            if "1min.ai" in line and "credits" in line:
                if key in seen:
                    continue
                seen.add(key)
            m = NEW.search(line)
            if m:
                model, cr, it, ic, ot, oc = m.groups()
                data.setdefault(model, []).append(
                    {"cr": int(cr), "it": int(it), "ot": int(ot), "ic": int(ic), "oc": int(oc)})
                continue
            m = OLD.search(line)
            if m:
                model, cr, it, ot = m.groups()
                data.setdefault(model, []).append(
                    {"cr": int(cr), "it": int(it), "ot": int(ot)})


def lstsq_2(rows):
    """Fit cr ~ a*it + b*ot (no intercept). Returns (a, b)."""
    sxx = sum(r["it"] * r["it"] for r in rows)
    syy = sum(r["ot"] * r["ot"] for r in rows)
    sxy = sum(r["it"] * r["ot"] for r in rows)
    sxc = sum(r["it"] * r["cr"] for r in rows)
    syc = sum(r["ot"] * r["cr"] for r in rows)
    det = sxx * syy - sxy * sxy
    if det == 0:
        return None, None
    a = (syy * sxc - sxy * syc) / det
    b = (sxx * syc - sxy * sxc) / det
    return a, b


print(f"{'model':<38}{'calls':>6}{'creds':>9}{'in_tok':>9}{'out_tok':>9}"
      f"{'cr/in':>8}{'cr/out':>9}{'method':>9}")
print("-" * 95)
rows_out = []
for model, rows in sorted(data.items()):
    calls = len(rows)
    tot_cr = sum(r["cr"] for r in rows)
    tot_it = sum(r["it"] for r in rows)
    tot_ot = sum(r["ot"] for r in rows)
    if all("ic" in r for r in rows) and tot_it and tot_ot:
        in_rate = sum(r["ic"] for r in rows) / tot_it
        out_rate = sum(r["oc"] for r in rows) / tot_ot
        method = "exact"
    else:
        in_rate, out_rate = lstsq_2(rows)
        method = "fit"
    rows_out.append((model, calls, tot_cr, tot_it, tot_ot, in_rate, out_rate, method))
    print(f"{model:<38}{calls:>6}{tot_cr:>9}{tot_it:>9}{tot_ot:>9}"
          f"{in_rate:>8.3f}{out_rate:>9.3f}{method:>9}")

print("\nNotes: cr/in = credits per INPUT token, cr/out = credits per OUTPUT token.")
print("'fit' = recovered by least-squares from per-call totals; 'exact' = from split credits.")
