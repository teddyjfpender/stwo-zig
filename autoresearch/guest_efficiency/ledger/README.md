# Ledger

One JSON object per line in `attempts.jsonl`, appended for every attempt (kept or not):

```json
{"date": "YYYY-MM-DD", "branch": "...", "commit": "...", "elf_sha256": "...",
 "result": "path/to/result.json", "set": "all",
 "scored": {"instructions_per_gas": 0.0, "committed_bits_per_gas": 0},
 "holdout": {"instructions_per_gas": 0.0}, "guards_ok": true,
 "part": "1|2|3", "description": "one line", "kept": true}
```

`baseline-v1.json` is the measured starting point produced by `bench.py run --set all`
on the unmodified guest.
