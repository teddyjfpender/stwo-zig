# Retained Ethereum windows: exact sources and explicit state

This corpus uses the exact previously executed mainnet block 24,628,607 guest,
not generated replacement instructions. The historical execution retired
139,214,856 RV32 instructions. A captured window is an explicit incoming-state
benchmark; replay alone is not a proof of the window, its skipped prefix, or
Ethereum block validity.

The missing binaries were recovered on 2026-10-29. All ten source hashes in
`ethereum-block-sha-default-v3.build.json` matched the checkout. The documented
nightly-2026-08-08 release build reproduced the ELF **byte for byte**. The
upstream Zisk transport at commit
`0887d43621931faba8cdf8da70402091bbe620ff` was downloaded and hash checked, then
the locked Rust projection regenerated canonical SSZ. The retained twelve
successful recovery hints regenerated the exact augmented input. The expected
43-byte output was reconstructed from the recorded request root, success byte,
chain ID and schema, then checked against its historical hash.

| Artifact | SHA-256 |
| --- | --- |
| Guest ELF | `ef68fdca9e627a4969e64aa97119f52f2d9c9d6b6e8d5cbbeb541fb93dab0688` |
| Augmented runner input | `737368031bfec21aa2bd557a3a71d2cbf253ec730199f7ec4c3bccd628df8e82` |
| Expected whole-guest output | `730396807814bc71f14405b3ecf27237778a5359732001b32c93692c3275a8c5` |

Sources, build logs and manifest are in
`vectors/reports/block-v7-real-window-corpus-20261029/source/`.
The public transport is pinned by
`autoresearch/benchmarks/ethereum_block_mainnet_24628607.json`; its SHA-256 is
`e1c6d4e06a87649da68e461a91465e4123b990f531e68581ee1750599ff12376`.

## Selected real windows

Counts below are observed from the exact replay, not apportioned from the
historical larger segments. Every case contains 32,768 retired instructions.
These are source-execution diagnostics, **not proving times**.

| Case | Instructions skipped | Core rows | Keccak | Recovery | SHA | Window execution | Prefix replay |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Startup (capture only) | 0 | 32,768 | 0 | 0 | 0 | 36.05 ms | 0 |
| Native nonfirst | 1 | 32,768 | 0 | 0 | 0 | 38.12 ms | 33.09 ms |
| Recovery | 24,718,000 | 32,730 | 32 | 6 | 0 | 42.95 ms | 16.26 s |
| Keccak | 42,700,000 | 32,540 | 228 | 0 | 0 | 59.26 ms | 32.44 s |

Each capsule records exact incoming/outgoing PC, all 32 registers, the complete
initialized word inventory, a canonical behavioral digest including all native
rows and precompile input/output records, and source identities. A fresh runner
restores the independently selected incoming state and checks exact behavioral
and complete outgoing-state equality. Prefix replay and captured-window
execution have separate timers. The diagnostic runner uses bounded discarded
prefix segments, not one retained 42-million-instruction witness.

The durable capsules are in `startup/`, `native/`, `recovery/` and `keccak/` beside `source/`.
Snapshots use gzip around `B7WIN001`: eight magic bytes, little-endian u32 PC,
32 little-endian u32 registers, little-endian u64 word count, then strictly
increasing `(u32 address, u32 value)` pairs. Decoding checks exact length, count
cap, alignment, ordering, x0 and the caller-selected state digest before use.
No initialized-word fingerprint is treated as a cryptographic commitment.

## Reproduce

```sh
# Rebuild/download only pinned public sources; fail if any result differs.
python3 scripts/v7_real_window_corpus.py recover /external/new-corpus
python3 scripts/v7_real_window_corpus.py status /external/new-corpus

# Or import already recovered files without rebuilding them.
python3 scripts/v7_real_window_corpus.py import /external/new-corpus \
  --elf /external/guest.elf --input /external/input.bin \
  --expected-output /external/expected-output.bin

# Capture and exactly replay a real window. This command does not prove it.
python3 scripts/v7_real_window_corpus.py capture /external/new-corpus \
  /external/new-capture --case recovery-region
```

The importer checks hashes before publishing a directory, copies the checked
bytes rather than rereading replaceable paths, and refuses existing output
directories. Recovery uses the shared compiler lock and at most two Cargo jobs.
The capture defaults cap ELF at 32 MiB, input at 4 MiB, the selected window at
262,144 instructions, prefix replay at 150 million instructions and snapshots
at eight million words. An optional precompiled capture binary avoids rebuilds.

## Nonterminal proof boundary

`block_v7_real_window_statement_v1.zig` and
`block_v7_real_window_proof_v1.zig` define a separate explicit-window adapter for
the existing SHA-capable canonical original leaf. They do not change terminal
v7 admission. The adapter binds independently selected complete incoming and
outgoing RW state roots, all registers, PC, cycle count, decoded ELF ROM and the
actual unretired boundary fetch. It rejects a first-window public-input
projection and any terminal/public-output substitution.

Two separately committed memory roots are insufficient by themselves: an
untouched cell could otherwise differ between endpoints. The adapter therefore
requires every changed complete-state word in both original boundary-provider
rosters, with a nonzero final access clock. Native relation closure must prove
those access chains; all other complete endpoint words are equal. The original
proof verifier, not a host replay receipt, authenticates the resulting claims.

The genuine proof gate is `block_v7_real_window_proof_test_root.zig`: 419 tests
passed, one skipped. Its small actual Keccak window creates the original proof,
destroys producer traces and prepared key, then decodes the admission and proof
and independently reconstructs the verifier. Wrong endpoint identities and
registers reject. A stronger negative changes an unused memory cell, reseals the
outgoing capsule and both affected boundary-root references, and passes the
original plan validator; complete-state admission still rejects it because no
proved access chain covers that changed cell.

The retained ELF includes immutable PT_LOAD header words before its declared
TEXT range. These words are accepted only with exact membership in the
independently loaded ELF address set and exact ELF values. An arbitrary address
whose default memory read happens to be zero is rejected.

All three real 32,768-instruction windows now produce canonical original proofs
(q70, proof-of-work 26), independently verified after producer traces and keys
are destroyed. Each opt-in gate passes 419 tests with one skipped. The native
case skips exactly one real instruction before taking its incoming state; it
uses the explicit nonfirst projection and does not change first-window semantics.
Its capsule and proof live under `native/`.

| Real window | Preparation | Proving | Serialize/release | Fresh verification | Prepared window → verified | Charged peak | Proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Native, 0 precompiles | 11.528 s | 28.571 s | 0.238 s | 5.767 s | 46.104 s | 9.577 GB | 2,299,118 |
| Recovery, 32 Keccak + 6 recovery | 8.622 s | 20.272 s | 0.239 s | 3.978 s | 33.111 s | 3.825 GB | 6,192,652 |
| Keccak, 228 calls | 15.649 s | 32.539 s | 0.241 s | 6.596 s | 55.025 s | 10.009 GB | 4,297,656 |

These are single shared-host diagnostics, with the native case instrumented;
they are not an idle repeated speed comparison. The tracked cap is 24 GiB.
Prefix/capture adds 0.153 s, 17.902 s and 33.692 s respectively, and remains
separate from prepared-window proving. Prefix replay is input preparation, not
authenticated execution of the skipped prefix. The state inventories and memory
access patterns differ, so fewer precompile calls do not imply a faster proof.

These are the existing canonical partial-leaf architecture, including its
machine-memory Merkle proofs. They are not measurements of the new v7 direct
whole-execution union, and are not independently verifiable Ethereum blocks or
compact recursive roots. Full metadata is about 16–17 MB per window and must be
accounted for alongside proof bytes. `proving-times.csv` records all coarse
phases, input loading, prefix timing, source census and allocation peaks.

Saved `window.proof`, `window.admission`, externally selected endpoint capsules,
and `report.json` support a fresh-process verifier. The report SHA-256 is supplied
by the caller as benchmark admission; it is never accepted from the proof as its
own trust anchor. The verifier reconstructs ELF ROM, complete memory roots and
original key and checks the actual proof. It does not execute the prefix or
window, and does not need the producer witness.

```sh
python3 scripts/v7_real_window_corpus.py prove \
  vectors/reports/block-v7-real-window-corpus-20261029/source \
  /external/new-proof --case recovery-region

python3 scripts/v7_real_window_corpus.py verify \
  vectors/reports/block-v7-real-window-corpus-20261029/source \
  vectors/reports/block-v7-real-window-corpus-20261029/recovery/proof \
  --snapshot-directory vectors/reports/block-v7-real-window-corpus-20261029/recovery \
  --expected-report-sha256 2d264c3b4672eef5bc4da321c6a57239c235da2051547a325128b1f111ea82a8
```

Both commands accept an optional previously compiled `--binary`. Cold reload
uses bounded gzip materialization, snapshot decoding, manifest/proof reads and
a 24 GiB allocation budget. No trusted-host replay receipt substitutes for the
original proof.


## Stage evidence and architectural implications

`stage-times.csv` preserves 108 rows across the three instrumented real cases
and the additional native RSS repeat.
Each original JSON stage tree is retained in `CASE/profile/stages.json`, with
raw logs and its complete timing report. Parent stage times are inclusive; do
not add a parent to its descendants. Two explicitly derived residuals per case
account for admission/key/manifest work outside the witness recorder and proof
bookkeeping outside the proof recorder. No missing time is silently omitted.

| Instrumented stage | Native | Recovery | Keccak |
| --- | ---: | ---: | ---: |
| Memory commitment plan | 0.592 s | 0.980 s | 1.212 s |
| Memory hash witness | 4.824 s | 3.536 s | 7.422 s |
| Native witness | 0.024 s | 0.024 s | 0.033 s |
| Shared lookup census and statement | 0.893 s | 0.345 s | 1.200 s |
| Hash interaction generation | 3.292 s | 0.894 s | 3.990 s |
| Fixed + main + interaction commitments | 9.277 s | 2.955 s | 9.631 s |
| Composition evaluation | 9.825 s | 3.034 s | 12.855 s |
| Sampled-value evaluation | 1.831 s | 0.216 s | 1.889 s |
| Lazy DEEP quotient + FRI commitment | 2.108 s | 11.102 s | 3.299 s |

The recovery and Keccak instrumented repeats produce **byte-identical proofs**
to their uninstrumented originals. Their measured process peak RSS is 3.849 GB
and 10.067 GB. A later same-binary native repeat measured 9.580 GB RSS
(9,579,806,720 bytes), with exact original proof and metadata bytes. Its original
RSS field remains null; the new observation is stored in `native/rss-repeat/`.
This repeat overlapped a small independent correctness gate and remains a
shared-host diagnostic. All tracked
allocation peaks remain below the 24 GiB cap. The hardware is an Apple M5 Max
(Mac17,7), 64 GiB RAM, with four prover workers. Timing runs overlapped other
engineering work; these are diagnostics, not controlled regression thresholds.

This actual workload supports removing repeated machine-memory Merkle witness
and interaction work in the new architecture. It also shows a distinct secp
workload cost: lazy DEEP/FRI takes 11.102 s of the recovery case's 19.942 s
instrumented proving interval, while composition dominates the native and
Keccak cases. Treating every precompile or every instruction as having one
constant proving cost would hide this distinction. The new v7 whole-execution
union and this original partial leaf have different statements and proof
structures; a direct speedup comparison requires a separately admitted v7
nonterminal state-transition route or a complete execution of the same guest.

All three artifacts also pass the standalone reload gate in a fresh process
(343 passed, one skipped each). The cold verifier uses only independently
selected admission/report identity, ELF, endpoint capsules, metadata and proof;
it never executes the window or assumes a cached producer key.


## Logical artifact I/O and measurement boundary

`io-accounting.json` and `artifact-io.csv` enumerate exact application payload
lengths for each successful file API. They distinguish the proof process,
standalone capsule capture, cold Zig verifier, and Python verification wrapper.
They do not estimate physical disk traffic or infer it from the page cache.

| Case | Producer logical reads | Producer artifact writes | Cold Zig verifier logical reads |
| --- | ---: | ---: | ---: |
| Native | 6,485,610 B | 18,957,128 B | 46,894,808 B |
| Recovery | 6,485,610 B | 22,666,641 B | 62,785,865 B |
| Keccak | 6,485,610 B | 20,999,195 B | 68,962,267 B |

The producer reads the ELF and original input once each. It does not read
capsules or checkpoint files: prefix replay, window execution, witnesses and
PCS state stay in memory. Producer checkpoint reads and writes are therefore
**zero by the explicit code path**, not unmeasured values represented as zero.
It writes the proof, admission metadata and report only after the verification
completion timer ends. Those writes are recorded as payload bytes, but their
publication time was not separately measured by the immutable binary.

The cold verifier reads ELF, both raw endpoint capsules, metadata, proof and
the externally selected report. The Python wrapper additionally validates the
source bundle and report, reads compressed capsules, and writes bounded
uncompressed temporary files; its separate ledger avoids hiding that work.
Harness logs, executable/library loading, filesystem metadata and actual device
I/O remain outside payload accounting. Physical disk read/write bytes remain
explicitly null.

Executable hashes and commands are preserved. An exact full prover-source
snapshot was not captured before the original binary builds; the current
mutable checkout must not be retroactively attributed as their precise source.
The retained `source_sha256` values identify the guest workload artifacts, not
a complete prover-source manifest. This reproducibility gap is explicit in the
receipt rather than filled with a later checkout hash.
