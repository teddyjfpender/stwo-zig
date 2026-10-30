# Complete v7 execution-root qualification — 29 October 2026

The genuine two-segment SHA + Keccak workload now reduces its six original
proofs directly to **one 161,305-byte recursive proof**. Fresh verification
runs after original proofs, captures, rows and fixture producers are destroyed.
All 11 tests passed. The receiver closes the complete execution, caller, ROM,
lookup and memory relations under independently selected ELF, policy and key.

This is q8/PoW0 diagnostic qualification, **not canonical security or an Ethereum
block benchmark**. See the adjacent JSON for exact binary/log hashes, selected
source hashes, coverage and preserved test output.

| Phase | Diagnostic seconds |
|---|---:|
| metadata | 0.267825 |
| cold_fixed | 7.949698 |
| verifier_witness | 13.690780 |
| join_parity | 1.464843 |
| live_key_and_plan | 3.611236 |
| proof | 24.326705 |
| fresh_verify | 0.529929 |

These phases were measured during one correctness run while compiler jobs were
active. They exclude original-proof production and hostile replays. They must
not be compared as a speed ratio with older, different workloads. Joined
verifier rows retain 1,783,477,464 bytes; this is not RSS or whole-job peak.

The first combined run correctly rejected a fixed/live geometry mismatch.
Independent family compilation partitions each child's G cohort before joining;
the live mixed path had instead joined raw cohorts then partitioned the total.
The live join now uses the same per-child boundary. Exact row, namespace, wire,
context and key comparisons all remain enabled and pass.

## Reproduce

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_complete_root_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 complete actual'
```

Remaining work includes a larger matched workload, bounded reduction beyond
64 total original children, canonical-security qualification, and measured
Ethereum execution-to-root performance. Shared-epoch verification is being
implemented to remove repeated transcript work, and source collection now has
a separate variable-segment driver awaiting runtime qualification.
