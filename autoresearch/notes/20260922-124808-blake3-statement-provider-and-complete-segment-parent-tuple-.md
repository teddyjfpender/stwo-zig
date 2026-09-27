---
title: BLAKE3 statement provider and complete segment-parent tuple matching
author: Teddy Pender
created_utc: 2026-09-22T12:48:08Z
---

# BLAKE3 statement provider and scoped tuple qualification

The BLAKE3 row-10 provider now schedules 2,100 rows (four 525-word lanes), with
525 active source words in segment mode and 1,575 in binary mode. Legacy and
BLAKE3 profiles instantiate one direct SoA writer; both preprocessing and writer
binding identities are format-separated. The existing typed routing AIR and its
relation plan are unchanged: their equations depend on supplied verifier-owned
coordinates rather than hardcoded statement size.

New writer-binding digest:
`b8f13339cbd4fe70f43a44d7944c9ffc23e4304858475a83054a7d201589a514`.

Qualification command:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all
```

Passed; final outer build reported 9 seconds and 785 MB peak RSS. The focused
gate now has a 47-named-test floor, retaining six existing row-10 checks alongside
the previous codec, input AIR and graph gates. Three new provider tests cover
format-separated seals, all 1,050 segment/parent scoped tuples against the real
BLAKE3 graph input schedule, all 1,575 binary output words, zero padding and
rejection of mutated schedule authority before writing any output column.

The tuple test authenticates the typed provider and consumer interaction plans,
then compares domain, arity, every tuple coordinate and cancelling multiplicity
for each segment/parent word. This is a concrete provider/consumer boundary check,
not full global relation closure. Binary child words still emit multiplicity two:
row 11 consumes one copy and row 18 composition consumes another. VM-claim and
verifier-input relations also remain external obligations.

Next: migrate composition input schedules, which still bound statement words by
the legacy count, and the underlying source/public-claim projections. Then bind
BLAKE3 identity preimages and hash constraints and migrate artifact/key admission.
No production recursive proof, default promotion or performance gain is claimed.
