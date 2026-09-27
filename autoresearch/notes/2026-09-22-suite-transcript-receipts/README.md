# Core transcript receipts and canonical CSP qualification

2026-09-22, local dirty worktree, ReleaseFast CPU. Core now owns typed
suite/version/digest receipts. BLAKE3 v2 retains the full u64 draw counter;
BLAKE2s v1 bytes remain compatible. CSP compares receipts from proving and
independent artifact verification. Independent Python vectors cover counters
0, 1, 2^32 and 2^64-1 (oracle.py/oracle.json).

Command (STWO_CSP_FIXTURE_ROOT points to vectors/riscv_csp):

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-protocol test-blake3-csp-ecdsa test-csp-ecdsa-guest-proof -Doptimize=ReleaseFast --summary all
```

11/11 build steps succeeded; 8/8 tests passed (6 protocol, 1 BLAKE3 CSP,
1 legacy CSP). Both CSP gates use 70 queries and 26 PoW bits, with 1,828 cycles.

| Suite | Execution (s) | Proving (s) | Verification (s) | Inner proof bytes |
|---|---:|---:|---:|---:|
| BLAKE3 | 0.002079 | 2.506949 | 0.191967 | 3,748,258 |
| BLAKE2s | 0.000897 | 0.851909 | 0.290428 | 3,748,143 |

These are single qualification samples, not controlled performance comparisons.
PoW work varies; no speedup or subsecond BLAKE3 claim follows. Product report
schemas, production defaults, segmented artifacts, Metal dispatch and the full
CSP matrix remain unqualified. Core/ordinary RISC-V migration remains in scope.

Source snapshots and logs are pinned in SHA256SUMS.
