# Direct-native recursion: measured architectural work elimination

Follow-up: [nine-segment batches and a real upper proof](native-batch-scaling-m5-20261028.md)
now cover heterogeneous native templates, partial tails and recursive batch
consumption. The qualification limits below describe this earlier two-segment
measurement; global closure remains open in both experiments.

A focused implementation now replaces two individual native-verifier wrappers
and their recursive parent with one proof of both original native verifiers.
On an M5 Max with eight CPU workers, its median recursive phase is **17.0x
faster**. This is an actual proof comparison at q70/PoW26, not a cell projection.
It is **not a completed Ethereum block proof or a measured block speedup**.

Implementation: [`46772b295`](https://github.com/teddyjfpender/stwo-zig/commit/46772b295)
on `codex/ethereum-block-fast-lab`. The experimental implementation stays with
the archived block stack; this does not enable a new production receiver.
[Raw results](block-v6-native-batch-m5-20261028.json) contain every sample,
source/log hashes, stage times and scaling assumptions.

## Matched proof comparison

Both paths execute the same real ELF, prove the same two adjacent one-instruction
segments, admit the same native public policies and freshly verify the encoded
recursive output. Both retain open global obligations. ROM/source/provider pins
in this focused fixture are synthetic; they are not replaced by provider proofs.

```text
Previous: native proof 0 -> wrapper proof 0 --+
                                             +-> recursive parent proof
          native proof 1 -> wrapper proof 1 --+

New:      native proof 0 --+
                          +-> one direct-native batch proof
          native proof 1 --+
```

The new proof contains both native verifier equation sets, isolated wire
namespaces, public-claim supply and constrained index/PC/clock edges. It does
not substitute a host verification receipt for those equations. The batch
transcript binds all physical claims and its verifier-owned public values.
Its protocol/key domains are separate from the old wrapper-only forest.

Three sequential runs, Zig 0.15.2 ReleaseFast, Apple M5 Max, 64 GiB, one explicit
eight-worker pool on **both** paths:

| Metric | Individual wrappers + parent | Direct native batch | Reduction |
| --- | ---: | ---: | ---: |
| Recursive preparation/setup/prove/encode/verify | 32.425 s | 1.910 s | 16.98x |
| Native generation + recursive phase sum | 32.893 s | 2.375 s | 13.85x |
| Recursive BLAKE3 G rows, all produced proofs | 4,878,496 | 128,800 | 37.88x |
| Padded committed AIR cells, all produced proofs | 1,214,347,608 | 36,828,460 | 32.97x |
| Final recursive proof bytes | 977,158 | 761,485 | 1.28x |

The first direct batch's canonical stage split was preparation 0.712 s,
key/setup 0.192 s, proving 0.848 s, encoding/fresh verification 0.144 s.
Native generation was 0.464 s. The JSON retains all three splits. Native phase
medians were 0.468 s and 0.465 s respectively, so this comparison isolates
recursive structure rather than changing the executed workload.

AIR cells exclude shared lookup provider tables, PCS expansion and quotient
scratch. They are not sampled process peak. Final proof sizes exclude original
native and intermediate wrapper artifacts. Phase sums exclude teardown and
negative-test work and are not complete command latency. The baseline excludes
its deliberately invalid edge-graph construction; smaller harness checks remain
inside its timer. The first run compiled; the following runs used the same
cached executable. Build time is outside every recorded phase.

An earlier serial proof comparison passed too (113.894 s to 7.834 s recursion),
but the table uses the explicit pooled configuration. Serial Zig tests do not
automatically create the production worker pool; those times must not be used
as a production baseline.

## Qualification and remaining boundary

Each run passes all ten selected tests (three proof experiments plus imported
module tests). The focused negative checks reject changed residual claims,
wrong PC, duplicate/omitted children, a wrong key, empty batches and a changed
native capture. PC, clock and index mutations also bypass host adjacency checks
and fail evaluation of the emitted arithmetic graph. The first negative probe
used an individually invalid span and failed at the wrong layer; it was corrected
to preserve individual bounds while violating the join.

This is focused proof evidence, not a formal soundness certificate. In particular:

- The receiver derives public values again from independent native admissions;
  the artifact cannot choose its trusted key or public statement.
- Register/RW endpoints and external buses still need the global providers.
  PC/clock continuity alone is not complete machine-state continuity.
- Global closure and recursive consumption of a batch by a higher parent have
  **not** been integrated. The current wrapper forest cannot consume this new
  protocol without a new verifier/admission path.
- The implementation caps batches at eight but only two-child positive proofs
  are qualified here. Capacity selection, larger/heterogeneous segments, partial
  tails, complete provider closure and multi-level roots remain required.

## Why this is not automatically a 17x large-tree improvement

The small job removes its entire upper recursive tier. A large job still has to
verify batch proofs. Use the measured G counts to make that limitation explicit:

```text
s = 64,400 G rows per native verifier in this tiny fixture
p = 4,749,696 G rows per old two-child recursive parent

old(N)       = N*s + (N - 1)*p
batch(N, b)  = N*s + (ceil(N/b) - 1)*p
```

This deliberately optimistic counterfactual assumes unchanged parent cost,
uniform tiny native proofs, no new binding cost and no global providers. A real
parent may grow because its batched child has different geometry. It models
work, not time or a memory-feasible plan.

| Native proofs | Batch size | Batch proofs | Upper binary parents | Modeled G-work reduction |
| --- | ---: | ---: | ---: | ---: |
| 4,096 | 4 | 1,024 | 1,023 | 3.85x |
| 4,096 | 8 | 512 | 511 | 7.33x |
| 4,096 | 16 | 256 | 255 | 13.37x |

Sixteen is a design counterfactual beyond the current implementation cap. This
is why the next architecture needs **several** changes:

1. **Direct batches plus cheaper upper proofs.** Measure 4/8-child and partial
   batches, then prove an upper parent that binds the entire batch statement.
   Select capacities from actual padded cells and memory, not a fixed fan-in.
   Co-design FRI/opening geometry and jointly prove compatible components so
   fewer expensive child proofs reach the upper tree. Existing hash-work models
   suggest additional opportunities; they are not measured protocol upgrades.
2. **Execution-local registers plus packed mutable RAM.** The retained block's
   83.76% register traffic need not enter the global RAM sorter. The existing
   model gives **10.14x less committed memory area**, independently of wrapper
   removal. Preserve exact register custody and boundary/caller checks. This
   remains a memory-work projection awaiting a matched complete-block timing.
3. **One wide witness construction, narrow late relations.** Finish segment
   proofs once, export exact event-column commitments, and open those same
   columns for the later block-global relation. Remove the collection/proving
   replay and allow bounded overlap. This is an enabling protocol redesign,
   not an independent 10x claim; its challenge/root binding must be proved.

These gains cannot simply be multiplied. The next acceptance gate is a complete,
freshly verified multi-batch job including global providers. Only then is a
same-block old/new root comparison meaningful. See
[the full architecture](block-v6-architecture.md) for that closure contract.

## Reproduction

From the lab branch at the implementation commit:

```sh
STWO_NATIVE_BATCH_WORKERS=8 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_native_batch_test_root.zig \
  -OReleaseFast --test-filter block-v6 > native-batch-1.log 2>&1
# Repeat with output paths native-batch-2.log and native-batch-3.log.
python3 design/riscv-proving-stack/performance/native-batch-results.py \
  native-batch-1.log native-batch-2.log native-batch-3.log
```

The summarizer rejects incomplete/failed runs, missing matched paths, worker
configuration mismatches, stage-sum mismatches and changed geometry/proof sizes.
Do not run a concurrent build or proof while collecting timings. The script and
receipt are added in the follow-up documentation commit to the implementation.
