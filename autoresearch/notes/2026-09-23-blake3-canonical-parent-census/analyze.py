"""Summarize retained parent census receipts; no timing or security inference."""
import json
import re
from pathlib import Path
root = Path(__file__).resolve().parent
text = (root / "blake3-canonical-parent-row-census.log").read_text()
rows = []
for line in text.splitlines():
    if not line.startswith("BLAKE3_PARENT_ROW_CENSUS air="):
        continue
    fields = dict(re.findall(r"(\w+)=([^ ]+)", line))
    row = {k: (v if k == "type" else int(v)) for k, v in fields.items()}
    row["trace_words"] = row["padded"] * sum(row[k] for k in ("main_columns", "preprocessed_columns", "interaction_columns"))
    row["padding_rows"] = row["padded"] - row["live"]
    rows.append(row)
assert len(rows) == 20 and {r["air"] for r in rows} == set(range(20)), "incomplete roster receipt"
total = sum(r["trace_words"] for r in rows)
for row in rows:
    row["trace_word_share"] = row["trace_words"] / total
rows.sort(key=lambda r: r["trace_words"], reverse=True)
(root / "summary.json").write_text(json.dumps({"scope": "20 parent AIRs; excludes shared lookup tables, LDE expansion, Merkle trees and scratch", "trace_words": total, "rows": rows}, indent=2) + "\n")
for row in rows:
    print(f'{row["air"]:2} {row["trace_word_share"]:6.1%} {row["type"]} live={row["live"]} padded={row["padded"]}')
