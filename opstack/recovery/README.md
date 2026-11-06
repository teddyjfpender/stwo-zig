# Interrupted follow-up and recovery

2026-11-06. The execution environment became unavailable after roughly 2½ hours of execution work, cutting short the requested 5–6 hour session. No GPU was available before that interruption.

The applied and validated implementation is commit `56a750b10224ddbc54115e5dc4940ef72167cf29`, rebased onto GPU head `6d0d1e56a9d3c2f58a2cb035343fd3c643acffc5`. The final 16 upstream commits changed 28 paths with no overlap with the OP changes. That final rebase used GitHub Git objects after the environment stopped; no GPU or build rerun on the final base is claimed. The guest, shared Rust runtime and CPU executor paths were unchanged by those upstream commits. The full committed benchmark evidence remains in [the dated report](../../vectors/reports/rv64-opstack-20261106/README.md).

## What is preserved here

The recovery patches were reconstructed from the session's edits after filesystem access was lost. They are **not applied to the runtime**, are not a byte-for-byte recovery of the local working tree, and need apply/build/validation checks. This keeps the published runtime at its validated checkpoint. Cargo lockfiles are deliberately not reconstructed by hand.

- [sha-service.patch](sha-service.patch): the SHA feature integration, explicit SHA build variants, independent OpenSSL 3 compression oracle and boundary tests. It aliases the existing admitted SHA crate only for our statement hashes; the native reference and other dependencies retain registry SHA. Local execution and oracle validation completed before the interruption, but the exact local ELF/source receipts were not durably recovered.
- [candidate-cost-draft.patch](candidate-cost-draft.patch): **unvalidated draft** of `plan-candidate CONFIG JOBS PREFIX_COUNT RESOURCE_JSON`, using the same source-bound accounting and request-view routing as production. Its first compile failed because of an incorrect collector import; that was corrected to the GKR coordinator. The subsequent build was interrupted before completion was observed. Do not apply this as a qualified producer change.
- [observations.json](observations.json): numerical results actually observed in tool output, with their limitations. These are research observations, not a replacement for the committed benchmark receipts.

## Observed SHA experiment

Same four-block range, 22,094,683 gas; baseline remains our software Kona RV64 guest, not SP1.

| Local candidate | Instructions | Instructions/gas | Service RAM word transitions |
|---|---:|---:|---:|
| Bounded MPT + SHA service | 160,265,366 | 7.2536 | 1,487,298 |
| Same + default bulk memory | 144,106,647 | 6.5222 | 12,204,927 |
| Same + bulk thresholds 64 bytes | 150,080,552 | 6.7926 | 9,624,042 |

These are not GPU speedups. The 128- and 256-byte sweep completions were observed, but their numerical artifacts were not recovered. The 512-byte build was interrupted when its source paths disappeared. Do not invent those results.

The SHA candidate matched native execution and independent machine/oracle checks on all eight fixtures and the default shared range. The SHA+bulk candidate's default four isolated cases and range also matched. Its extra-fixture run was still in progress at the last observation; no complete extra-fixture qualification is claimed.

SHA compression was checked through the public OpenSSL 3 `SHA256_Transform` ABI, independently of the guest's Rust implementation and producer's Zig implementation. Padding-boundary tests compared the composed hash with hashlib. Guest output, all registers, PC, exact instruction count and service counts matched. The complete first SHA block also matched serial and 1/2-worker capture digests. Its three observed RSS peaks are in the JSON.

## Resume in a restored environment

Start from the PR head, read the main [OP README](../README.md), and keep each experiment isolated. The patch source paths are the same as at `7839beb080167711a70dea303e509a92b41d8556`; the later GPU-only rebase did not alter them.

```sh
git apply --check opstack/recovery/sha-service.patch
git apply opstack/recovery/sha-service.patch
# Resolve only the added optional path dependency; inspect both lockfile diffs.
cargo +stable check --manifest-path opstack/kona/Cargo.toml --features host,sha-service -j1
cargo +nightly-2026-08-08 update --manifest-path opstack/kona/lean/Cargo.toml \\
  --offline -p stwo-kona-rv64-lean
python3 opstack/build.py --variant sha --artifacts /tmp/kona-sha --jobs 1
python3 opstack/build.py --variant memory-sha --artifacts /tmp/kona-memory-sha --jobs 1
```

Then format the owned packages, run all host/SHA/Python tests and repeat the pinned fixtures, independent oracle, corruption controls and capture parity. Install OpenSSL 3 for the SHA oracle. Regenerate and commit exact build/ELF/input identities before promoting these observations. Re-run the unfiltered Ethereum chain test; it passed locally before the environment loss.

The interrupted build-helper improvement made all bulk thresholds explicit and recorded, clearing ambient `STWO_ADMITTED_*` variables. Its allowed values were 8..1048576 or `off`; reject values below 8 so the existing memset wrapper cannot underflow when peeling its destination head. That improvement and its guard test are not included in the SHA recovery patch. Reimplement and validate them before sweeping. The local 64/128/256 sweeps set COPY, UCOPY, SET and CMP minima to the same byte value. Default admitted minima were 16/16/16/8. Record every compile-time value with the ELF identity.

The cost draft reports exact source-derived native FIXED/MAIN/INTERACTION cells including padding, and `31 * (MAIN + INTERACTION)` payload bits separately from 32-bit storage. It excludes composition, PCS blowup, openings, recursion, proof bytes and timing. This differs from the guest-efficiency challenge's frozen proxy; do not claim target parity from it. Validate against actual native proof cost telemetry and preserve unchanged producer/receiver acceptance before using it to choose a threshold.

The local profiler wrapper reused `scripts/riscv64_ethereum_profile.py`, requiring profiled reference execution to match fast execution in instructions, registers, PC and output. Block 26207961 accounted for 73,436,348 function instructions plus 6 unknown boundary instructions. The observed hotspots are recorded in JSON. The wrapper itself was not recovered.

Full SP1 replacement remains open: authenticated L1 derivation/KZG, execution–derivation binding, anchored L1/reorg handling, accumulator, committed-input/initial-image qualification for settlement, STARK compression and a direct on-chain STARK verifier. The current fresh receiver reconstructs initial memory from supplied witness bytes; a settlement adapter cannot simply trust an arbitrary prover-supplied initial image. No SNARK wrap is planned. Physical OP native/recursive proving and independent reception need a GPU host.
