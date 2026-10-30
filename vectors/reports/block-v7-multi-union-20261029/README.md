# Canonical multiwindow proof artifacts

These are historical active-layout V2 artifacts. Current default reload tests
use the [V3 artifacts](../block-v7-active-caller-v3-20261029/README.md), which
remove zero-call SHA components and qualify the corresponding lookup closure.
Keep these original bytes for the attributable storage comparisons; the current
V3 verifier deliberately derives a different caller identity.

These fixtures prove complete synthetic RISC-V executions with SHA and Keccak
precompiles, native execution, ROM, lookups and joint memory in one original
STARK. Both use 70 queries and 26 PoW bits. They are not Ethereum block proofs
or compact recursive publication proofs.

| Fixture | Cycles | Native windows | Callers | Trees | STARK bytes | Envelope bytes |
|---|---:|---:|---:|---:|---:|---:|
| `q70-coefficient-inputs` | 20,495 | 2 | 1 | 18 | 6,016,333 | 6,063,212 |
| `q70-two-callers` | 20 | 10 | 2 | 39 | 7,268,983 | 7,351,530 |

Each directory contains `guest.elf`, `public-metadata.json`, `proof.b7mun`,
qualification and fresh-process logs, and a receipt pinning their hashes.
`results.tsv` records diagnostic phase times and separately scoped memory
measurements. The producer used coefficient-backed memory input commitments
and bounded RAM quotient tiles. Its original per-family proof oracle matched
every physical claim; original producers and oracle proofs were destroyed
before independent combined verification. The proof-producing gate passed
11 tests and the separate saved-artifact receiver passed eight.

`B7MUN001` encodes schema/epoch binding, canonical physical claims and the STARK.
`block_v7_multi_union_codec_v1.verifyBytes` validates the independently derived
tree inventory before postcard allocation and then runs the original verifier
and complete global closure. Its default decode/whole-verification allocation
limits are 256 MiB/4 GiB, with explicit receiver and retained-PCS admission
limits. The latter remain conservative resident-storage estimates. Decode peak
was 20.1 MB and 44.2 MB respectively; those are **not** whole proving peaks.

Trusted ELF, expected execution/output and security policy remain external to
the proof. The fixture receiver reconstructs them from the known guest generator
and independently selected iteration count. The JSON sidecar is a typed test
import, not a producer-authorized policy or a production metadata parser.

Reproduce the larger proof plus transport qualification:

```sh
STWO_V7_MULTI_UNION_ITERATIONS=4096 \
STWO_V7_MULTI_UNION_CUT=10248 \
STWO_V7_MULTI_UNION_CANONICAL=1 \
STWO_V7_MULTI_UNION_COEFFICIENT_INPUTS=1 \
STWO_V7_MULTI_UNION_RAM_TILES=1 \
STWO_V7_MULTI_UNION_ARTIFACT_DIR=/tmp/v7-multi-artifact \
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_multi_union_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 multi union genuine'
```

Verify the saved larger fixture without generating any proof:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_multi_union_wire_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 multi union saved'
```

For the ten-window saved fixture, also set
`STWO_V7_MULTI_UNION_RELOAD_DIR=vectors/reports/block-v7-multi-union-20261029/q70-two-callers`
and `STWO_V7_MULTI_UNION_RELOAD_ITERATIONS=1`. These are caller-selected test
policy, not values accepted from the artifact.
