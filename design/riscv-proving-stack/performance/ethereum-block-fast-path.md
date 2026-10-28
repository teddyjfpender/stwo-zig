# Ethereum block fast path: work reduction before acceleration

Status: architecture decision and falsifiable experiments. No full Ethereum
block-to-root proof or end-to-end speedup is established by this document.

## Why the present path is slow

The stopped block 24,628,607 run had 139,214,856 guest cycles and 67 execution
segments. Its first collection/sort/commit/admission pass took 1,650.976 s.
The recorded sorted-memory census was 356,303,914 events, of which 298,427,187
(83.76%) were registers. The pass planned 85 memory instances and admitted 622
base proof files. Nine segment sidecars took roughly 80 s each; their recursive
leaf stages took 17.6–22.4 s. The run stopped before a complete root, so none
of these observations is an end-to-end block proving measurement. Source:
`autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-performance-roadmap-v1.md`.
The retained measurement also says its producer policy does not independently
admit an Ethereum block or external public-state policy. A production benchmark
must pin those inputs outside the prover-generated bundle.

This is a work-amplification problem. A faster hash kernel alone cannot remove
hundreds of millions of generic memory events or hundreds of proof instances.
The q193 test's 55,781 Poseidon calls describe one small recursive wrapper;
they do not describe the block's base-memory workload. In the stopped block,
the measured sidecar stage was several times the measured leaf stage.

### Reproducible geometry experiment

Run `python3 design/riscv-proving-stack/performance/block-work-model.py`. The
model fixes the measured event census and compares three *protocol widths* at
row log 22, counting full padded commitment domains. The old memory AIR has
22 fixed + 36 main + 84 interaction cells/event. The archived word-v4 profile
has 12 + 27 + 68 cells/event. The archived RAM2 profile has 24 + 54 + 92
cells/two-event row. The latter two include the proposed mode1 projection,
which sends only writable RAM to sorted memory and closes register custody in
execution windows. They were not measured on the complete block.

| Geometry | Instances | Committed M31 cells | Raw trace bytes | Cell reduction |
| --- | ---: | ---: | ---: | ---: |
| Recorded all-memory layout | 85 | 50.625 billion | 188.59 GiB | 1.00x |
| Mode1 + word-v4, projected | 14 | 6.283 billion | 23.41 GiB | 8.06x |
| Mode1 + RAM2, projected | 7 | 4.991 billion | 18.59 GiB | 10.14x |

Raw trace bytes sum all committed domains; they are **not concurrent peak RAM**.
PCS expansion, quotient scratch, FRI and proof serialization add work. The
model demonstrates the size of the avoidable base-field workload, not runtime.
It also shows the limit of width tuning: after mode1 and RAM2, roughly five
billion committed cells remain. Further large gains require reducing *work
per mutable RAM event*, avoiding duplicated range requests, and reducing
fixed proof overhead. The existing archive's mode1 and RAM2 source gates do
not substitute for fresh full-security STARK proofs.

A fresh ReleaseFast M5 run of the archived, source-hash-pinned 32,768-event
RAM kernel comparison passed exact bus/counter parity. Median interaction
generation was 32.327 ms for word-v4 versus 22.004 ms for RAM2 (1.469x);
trace and interaction arrays were 14,024,704 versus 11,141,120 bytes (20.6%
less). This benchmark excludes commitment, FRI, recursion, guest execution,
shared inverse-table setup and whole-process peak. The archived prior run
measured 32.327 versus 21.500 ms, showing similar kernel behavior, but neither
run proves an end-to-end gain. See `block-ram2-m5-20261028.json` for the fresh
samples and scope.

The row-cap sensitivity check is informative. For the RAM2 census, row logs
20, 21 and 22 commit the same 4.991 billion cells in 28, 14 and 7 instances.
Row logs 23 and 24 commit 5.704 billion cells in 4 and 2 instances because
of padding: **14.3% more cells for fewer proofs**. At this count, log22 is the
first capacity that minimizes proof count without increasing committed area;
raising the row cap blindly worsens the base-field workload and likely raises
per-instance peak. This is geometry evidence, not a measured time optimum.

## Chosen block-specific protocol

Use a versioned Ethereum-block profile with fixed security parameters and
independent public-state pins. Do not retain a generic all-access memory AIR
on this profile merely for code sharing.

1. **Execution-local registers.** Prove register reads, writes, predecessor
   clocks, x0 semantics and boundary values in typed native/caller AIRs. Close
   every ordered execution window with a shared random relation and exact
   counts. The global sorter sees only writable RAM. The archive contains a
   mode1 source path; qualify and measure that path before redesigning it.
2. **Block-global RAM.** Sort writable RAM accesses once for the whole block.
   Prove strict address/clock order, read-after-write continuity, first-touch
   values, last values, and exact permutation against the execution/caller
   requester tuples. Keep input and ROM in separate authenticated read-only
   families. Lane packing is selected by **total committed cells and owned
   scratch**, not by instance count alone. Narrow the predecessor and range
   witness before raising row caps.
3. **Ethereum-heavy operations.** Route Keccak, SHA-256 and elliptic-curve
   calls to dedicated typed AIRs with exact ordered call/return buses. Host
   precomputation may produce witnesses but never grants arithmetic authority.
   Derive every public state root from proved trie/hash transitions tied to
   the block's independently expected parent and output roots.
4. **One block dependency graph.** Stream execution events and stage bounded
   witnesses while producing the first commitments. Sort RAM and seal ROM/
   precompile inputs concurrently where transcript dependencies permit. After
   all first roots determine shared lookup challenges, prove independent
   interaction/composition/FRI jobs in parallel. Reuse immutable fixed data,
   compiled kernels and capacity templates. Request-specific state, witness
   and transcript bytes are reset and rebound on every proof.
5. **Fewer proofs and fewer recursive verifiers.** Fuse compatible same-root
   projections while keeping distinct bus equations. Aggregate several
   already verified adjacent children per capacity-bounded recursive circuit;
   prove each child verifier equation and ordered state/clock span. Publish
   parents from a ready queue, with bounded memory and independent key/policy
   admission. A digest of child proof files cannot replace verification.
6. **Resident GPU proving.** Keep witness, interaction, quotient, LDE, Merkle
   and FRI buffers on device where capacity permits. Stream one bounded family
   at a time for near-capacity jobs. Batch BLAKE3 and field kernels, then
   schedule independent family proofs and forest nodes across GPUs. Use the
   CPU receiver as an independent proof verifier; preserve 70 queries and 26
   PoW bits for the canonical profile.

The existing archive already implements parts of items 1, 2, 4 and 5 as
source or focused tests. The performance ledger explicitly says the resulting
mode1/RAM2 complete-block proof, assembled forest and GPU throughput remain
unqualified. Reuse those sound pieces; do not count their projected gains as
achieved twice.

## Experiments that decide the architecture

| Experiment | Same-input comparison | Required evidence |
| --- | --- | --- |
| Register custody | Mode0 vs mode1, with the same block and q70/PoW26 | Fresh independent verification, exact register/RW census, changed-window and caller negatives, memory cells, per-family wall time and RSS/device peak. |
| RAM layout | Word-v4 vs RAM2 on the same authenticated RW stream | Full-security proof and verifier, padded cells, peak scratch, throughput, odd-tail and cross-instance negatives. Reject RAM2 if extra width/peak outweighs fewer events. |
| Source pipeline | Existing 1,650.976 s pass vs streamed/staged pass | First-input-to-last-seal wall time, sort bytes/passes, commitment time, input hash, I/O wait, and output-equivalent source seals. Distinguish actual latency cuts from work hidden before a timer. |
| Proof fusion | Current base roster vs fused same-root roster | Exact proof count, verification of every original bus, proof bytes, phase timings, hostile omission/substitution tests. |
| Recursive fan-in | Binary parents vs 2/4/8 child capacity cohorts | Child-verifier equations, span continuity, fixed-row inventory, proof time, key reuse, peak and depth on exact odd leaf counts. |
| Full block | Old profile vs selected fast path | Same ELF/input/expected roots, 70 queries/26 PoW, fresh detached verification, root proof, complete wall-clock and peak. Report stage and critical-path times and reject any result missing global family closure. |

The first-pass measurement alone exceeds a 60-second block target by 27.5x.
That makes its redesign mandatory for a one-minute target; a six-second target
would require 275x improvement or elimination of that serialized pass. These
are arithmetic ratios against one stopped CPU run, not forecasts. A claim of
an order-of-magnitude end-to-end gain must wait for a completed, independently
verified old/new block pair on stated hardware.
