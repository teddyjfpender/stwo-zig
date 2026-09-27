# Full-width BLAKE3 Ethereum segment custody and aggregation

Status: diagnostic two-segment custody/aggregate gate, one-shot witness
regression and canonical base-segment regression all passed.

Base and Ethereum segment preparation share owned public-I/O extraction,
leaf-local clock/role validation and completion admission. The Ethereum witness
owner accepts the runner's actual segment type, including nonfinal unretired
instruction fetches, while preserving the existing one-shot entry point. No
intermediate segment is represented as a completed one-shot execution.

The shared segment-parent orchestrator selects the B3EH proof/capture API for
Ethereum and uses an explicit caller work pool. Before either leaf generates
interactions, pairing admits both independently pinned keys, adjacent Spans and
ordinary-to-continuation memory conversions. Capture-to-Span binding and parent
custody emission reuse the existing shared path. Ethereum callers use
`ForEthereumBackend.prepareWithPool` or `preparePairWithPool`; base signatures
remain available without the extension-only pool argument.

The test runs two real leaf-local segments: signer recovery in the first,
Keccak and completion in the second. It checks full-memory continuity and a
bad second key/aliased owner before proving, then folds both recursive verifier
witnesses with their custody conversions. The aggregate root is encoded, decoded
and independently verified after source witness, worker and prepared-row release.
Leaf and root parameters are diagnostic q8/PoW0; parent worker cap is 24 GiB.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation '-Driscv-test-filter=BLAKE3 Ethereum adjacent segments' -Doptimize=ReleaseSafe --summary all
```

Canonical Ethereum recursion/aggregation, Metal qualification and production
routing/key admission remain unfinished. No speedup or complete migration is
claimed by this integration test.

## Two-segment result

Passed: two real Ethereum segments cover seven retired cycles, with signer
recovery in the first and Keccak in the second. The decoded aggregate root
independently verifies after source witness, worker and prepared-row release.
Both leaves and the root use diagnostic q8/PoW0. Wrong second-key and aliased-owner
checks pass before interaction generation.

- Complete build/test gate: 25 minutes / 37 GiB peak RSS, four workers.
- Retained aggregate preparation: 4,476,857,164 bytes.
- Tracked root worker peak: 20,271,200,200 bytes under the 24 GiB cap.
- Aggregate root artifact: 144,055 bytes.

These measurements describe this integration gate, not an isolated latency
benchmark or a speedup comparison. Canonical recursive Ethereum, Metal and
production routing/default activation remain unqualified.

## One-shot witness regression

Passed after shared source/public-I/O extraction: one signer recovery and one
Keccak call retain two external retirements, include no legacy commitment
components, reject the base-only protocol and close the combined interaction
relations. The focused gate reports 4 minutes / 12 GiB.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments '-Driscv-test-filter=BLAKE3 execution commitment Ethereum external witness census' -Doptimize=ReleaseSafe --summary all
```

## Canonical base regression

The shared base segment path still passes the q70/PoW26 leaf-to-parent gate.
The complete gate reports 4 minutes / 23 GiB, with unchanged 860,503-byte
artifact, 4,214,454,616 retained preparation bytes and 19,514,934,660-byte
tracked worker peak.

```sh
python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-canonical-chain -Doptimize=ReleaseSafe --summary all
```
