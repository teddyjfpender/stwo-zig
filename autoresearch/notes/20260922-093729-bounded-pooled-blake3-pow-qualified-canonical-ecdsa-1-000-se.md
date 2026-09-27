---
title: Bounded pooled BLAKE3 PoW qualified: canonical ECDSA 1.000 seconds
author: Teddy Pender
created_utc: 2026-09-22T09:37:29Z
---

# BLAKE3 pooled PoW canonical qualification

2026-09-22. BLAKE3 PCS PoW now reuses the bounded prover pool. Nonce classes are
partitioned by worker count; a shared atomic minimum and full join retain the
lowest valid nonce independently of scheduling. No hash/transcript bytes or
security parameters change. Core owns the cached prefix and nonce predicate.
The maximum-u64 sentinel is verified before return; overflow never wraps.
Backend host admission remains ahead of search. With STWO_ZIG_POW_WORKERS set,
the existing override bypass policy currently selects the serial BLAKE3 fallback.
No new OS threads are created by the pooled search.

ReleaseFast protocol plus canonical ECDSA: 8/8 steps, 8/8 tests. Tests compare
minimum nonce for four states at 1, 2, 3, 8 and 16 workers, zero difficulty,
maximum-u64 candidate predicate and invalid difficulty rejection. Full ECDSA
uses 70 queries/26 PoW bits, precompile enabled, 16 workers, 1,828 guest cycles.

| Measurement | Serial baseline | Pooled candidate |
|---|---:|---:|
| Total proving (s) | 2.523295083 | 1.000019083 |
| PoW stage (s) | 1.640898 | 0.122675 |
| Verification (s) | 0.191454291 | 0.197666917 |

Candidate execution: 0.001701917 s; inner proof: 3,748,258 bytes. These are single
stage-profiled qualification samples, not a statistical performance verdict.
The observed total ratio is 2.52x and PoW ratio 13.38x. The canonical total has
not beaten the historical ~0.882 s result. Next isolate commitment/hash costs;
production defaults and Metal remain unchanged/unqualified.

Command:
```sh
STWO_CSP_PROFILE=1 STWO_CSP_FIXTURE_ROOT="$PWD/vectors/riscv_csp" python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-protocol test-blake3-csp-ecdsa -Doptimize=ReleaseFast --summary all
```
Baseline evidence: ../2026-09-22-csp-blake3-slowdown-profile/README.md.

ReleaseSafe protocol gate also passes 7/7 tests (4/4 build steps), including the pooled search parity test.
