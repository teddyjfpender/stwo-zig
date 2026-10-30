# Active caller V3: canonical combined proofs

V3 removes the five SHA arithmetic components when the independently admitted
SHA call count is zero. It also removes their table projections and padded
lookup requests. Every omitted physical claim must be zero; compensating claims
are rejected. The Ethereum byte provider and all active arithmetic remain.
The changed layout is explicitly transcript-bound. Historical V2 proof bytes
are retained separately for the earlier performance comparisons.

The fixtures use 70 queries and 26 PoW bits. They are synthetic RISC-V programs
with native execution, SHA and Keccak precompiles, ROM, shared lookups and global
RAM. They are not Ethereum block proofs or compact recursive publication roots.

| Fixture | Cycles | Native windows | Caller windows | Purpose |
|---|---:|---:|---:|---|
| `one-window` | 20,495 | 1 | 1 | Canonical single combined proof and bounded transport |
| `two-windows` | 20,495 | 2 | 1 | Compact input/interaction storage, producer consumption and explicit compact resource admission |
| `isolated-callers` | 20 | 7 | 3 | SHA, Keccak-only, SHA in separate windows; omitted-SHA global lookup and RAM closure |

The producer gates compare every physical claim to independently produced
original family proofs. Fresh verification runs after producer and oracle
objects have been destroyed. Saved transport reloads run separately and derive
trusted ELF, expected execution/output and security policy independently.
The JSON sidecar is a typed fixture import, never authority to select policy.

`active-families.log` records 13 passing tests for SHA, Keccak, recovery and mixed
callers, checkpoint parity and hostile claims. `keccak-recursive-composition.log`
records nine passing tests, including evaluation of the exact original Keccak
proof through the recursive composition circuit and rejection of omitted-field
mutations. This checks the changed composition leg, not a newly proved parent.

`results.tsv` separates proof time, preparation, original-family oracle work and
verification. Timings are shared-host diagnostics, not benchmark medians.
Charged proving peaks exclude external fixture preparation and are not process
RSS. Transport decoding is measured separately. Receipts pin the saved bytes
and logs; none claim full-block performance.

The resource admission option only discounts physically verified compact
coefficient storage. It retains all statement checks and requires a hard outer
allocation budget. Verifier admission stays unchanged. Original and merged
fixed trees, raw witness construction and active scratch are not silently
excluded from the accounting contract.

Reproduce the isolated caller proof:

```sh
STWO_V7_MULTI_UNION_ITERATIONS=1 \
STWO_V7_MULTI_UNION_CUT=20 \
STWO_V7_MULTI_UNION_ISOLATE_CALLERS=1 \
STWO_V7_MULTI_UNION_CANONICAL=1 \
STWO_V7_MULTI_UNION_COEFFICIENT_INPUTS=1 \
STWO_V7_MULTI_UNION_COEFFICIENT_INTERACTION=1 \
STWO_V7_MULTI_UNION_CONSUME_MEMORY=1 \
STWO_V7_MULTI_UNION_RAM_TILES=1 \
STWO_V7_MULTI_UNION_ARTIFACT_DIR=/tmp/v7-isolated \
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_multi_union_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 multi union genuine'
```

For the two-window fixture use 4096 iterations, cut 10248, omit
`STWO_V7_MULTI_UNION_ISOLATE_CALLERS`, and add
`STWO_V7_MULTI_UNION_COMPACT_ADMISSION=1`. The fixture demonstrates that the old
resident estimate rejects the smaller cap while the correctly compact producer
proves and the ordinary receiver verifies.

Verify a saved multiwindow artifact without proving:

```sh
STWO_V7_MULTI_UNION_RELOAD_DIR=vectors/reports/block-v7-active-caller-v3-20261029/isolated-callers \
STWO_V7_MULTI_UNION_RELOAD_ITERATIONS=1 \
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_multi_union_wire_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 multi union saved'
```

Omit both reload overrides to verify the saved two-window fixture. The separate
`block_v7_complete_union_wire_test_root.zig` defaults to `one-window`.
