# Build and commit native witnesses once: bounded PCS checkpoint

Task: preserve the original prechallenge fixed/main polynomial commitments
through the global source-seal barrier without retaining every wide tree in
RAM, re-running FFTs, or rebuilding Merkle layers. Raw native witness columns
are already staged once; the current second phase repeats their polynomial
extension and commitment, not the guest execution.

The canonical match is external-memory checkpointing of immutable DAG
intermediates. Exact state reuse replaces recomputation with sequential I/O.
Input dimensions are independently admitted native geometry, domain blowup,
two physical roots and their original template identity. The durable state is
the extended columns and retained Merkle layers. No random challenge, private
cache digest or early local admission may replace the original global seal.

| Candidate | Match and cost | Decision |
|---|---|---|
| Keep all native PCS trees resident | Exact state reuse; O(total block cells) live memory | Reject as the general architecture; breaks bounded segment lifetime |
| Save raw columns and recommit | Existing exact replay; bounded RAM but repeated FFT/Merkle work | Comparison baseline |
| Persist original PCS state | Exact immutable DAG checkpoint; O(snapshot bytes) write/read, one segment live | Implement, measure I/O and memory; retain ordinary final verification |
| Prove locally before global challenges, bridge later | New authenticated event reduction and new proof protocol | Not a shortcut: must prove every projected event and its binding; separate larger lane |

The [Stwo PCS implementation](https://raw.githubusercontent.com/starkware-libs/stwo/dev/crates/stwo/src/prover/pcs/mod.rs)
retains committed trees and supports externally constructed owned/borrowed
trees through `commit_tree`. Our existing `initPrecommitted` and host
`MerkleProverLifted` ownership provide the same state boundary. This supports
the mechanism, not a transferable performance estimate. No code is copied.

Integration: `collectRetained` returns the real original PCS and narrow root
proposal. Write one bounded checkpoint, then destroy the PCS before advancing
to the next segment. At proving time rebuild the raw native owner as today,
load the original extended columns and layers directly, bind the independent
late admission, and use the unchanged native proof/transcript/global receiver.
Storage names and aggregate budgets belong to the driver. CPU state format is
explicitly scoped; CUDA/device handles are not serialized as host pointers.

Identity and safety: expected scope, config/template, column logs, root pair,
lengths, field canonicality, layer topology and resource limits are validated.
The file cannot supply its own expected identity. Cached internal nodes are
**untrusted proving material**, not a proof or accepted receipt. No full-file
hash/FFT/Merkle pass is required merely to reload it: the independently pinned
roots and unchanged cryptographic proof verifier authenticate the resulting
proof. A malformed cache may deny service or produce a rejected proof; it must
never introduce a new accepted statement. Stage outputs must still pass fresh
verification before publication/acceptance. Unopened irrelevant cache bytes
need not be authenticated independently if they cannot change that proof.

Prediction: original fixed/main transforms and commits occur once per segment;
replay performs zero such operations. Cost saved must exceed writing and reading
the additional LDE/layer bytes. Report read/write bytes, restored live bytes,
driver time, charged peak and complete detached verification. This alone is
not a 10x block forecast and does not eliminate the global challenge barrier.
Reject the default if complete driver time or resource usage materially worsens.

Qualification: byte-identical original/restored columns, roots and proof output;
fresh proof verification; wrong template/scope/root, truncation, noncanonical
fields, malformed topology, aggregate/per-file budget rejection; ordinary
proving plus fresh verification after a used column or Merkle mutation must
reject. Every allocation/error path is owned and bounded. Provider and joint
PCS reuse can adopt this same state boundary, but are not claimed implemented
by the first native integration.

## Ordinary-access extension: preserve the third tree and raw witness

The next duplication is in `block_v5_native_memory_stage_v1`: collection derives
integer-byte witness columns and commits their tree, then the warm fused/joint
stage derives and commits them again. Retain both the canonical raw auxiliary
columns and their committed extended evaluations/Merkle layers, together with
per-slot range-counter snapshots. Restore only lightweight views onto the newly
loaded native main columns. Derive the exact slot roster, frame, register-custody
mode and geometry independently from the original native proposal; bind those,
the native roots and original access root in a typed checkpoint header.

The saved snapshots remain untrusted producer inputs. Interaction generation
recomputes each range-counter snapshot from the loaded main/auxiliary witness;
its existing equality check and the final AIR/PCS/global-relation verification
remain mandatory. No snapshot can mint a receiver receipt. This eliminates the
extra pre-interaction census while retaining its later checked obligation.
Zero-access segments retain typed absence and do not acquire a fabricated tree.
The same restored `FirstRound` feeds both the existing fused proof and B6JP-v3
partitioned joint proof, which retain identical access witness algebra.

Measure auxiliary bytes and physical-tree bytes separately, plus load live
allocations. Falsifiers: changed slot/frame/custody/root must reject before
allocation; malformed raw values must reject; canonical changed auxiliary/LDE
cells or snapshots must fail interaction generation/proving/fresh verification;
restored proofs must equal recomputed proofs. The intended gain is fewer witness
construction passes and FFT/Merkle passes, with additional bounded disk I/O.

## Global provider reuse

The same duplicated commitment exists at the decoded-ROM provider, each native
lookup group, each sorted-RAM lane and each range16 shard. The shared CPU tree
codec now has typed adapters for all four. Identities derive from the complete
ROM plan; lookup-group plan and checked source-counter snapshots; RAM claim,
index, roots, security configuration, request count and counter digest; and
range shard/plan/counter digest, respectively. The cache never supplies any of
those expected values to the verifier. Unsupported lifted Merkle geometry is
rejected explicitly by the provider codec.

The RAM transport stores original raw fixed/main matrices as well as PCS state.
Its mapped raw-column reader writes directly into the restored trace's two owned
buffers; it does not allocate a second column matrix. After the original sorted
scan has checked completeness, cached proving can skip reconstructing that scan.
The original per-instance claim/roster admission, range census and counter digest
checks, AIR/PCS verification and global relation closure still run. A changed raw
file also fails its independently retained SHA pin. The transport is heap-owned
by global planning so a returned planning value cannot invalidate its pointer.

Each policy has per-file and aggregate disk limits; restored RAM checks the sum
of raw trace and PCS allocations. Provider I/O statistics count raw and PCS bytes
separately and retain a maximum restored allocation measurement. These counts do
not replace the whole-process allocator/RSS measurement or include subsequent
prover scratch. The optional policies permit rejecting a disk-heavy cache when
its added I/O exceeds the removed work; no default speed claim is implied.

## First assembled native-only evidence

The coordinator's matched complete-bundle CPU runs preserved identical native
proofs and detached-bundle bytes. Native restore/recommit time changed from
0.561 s to 0.234 s, while complete one-segment time changed 40.34 s to 39.03 s and
four-segment time changed 74.83 s to 75.31 s. These are individual matched runs,
not statistical speedup estimates. The native-only checkpoint is therefore a
qualified removal of repeated work, not evidence of a broad end-to-end speedup.
The access/global extension is necessary to address more of the duplicated work;
its complete-bundle timing remains to be measured.

## Global-provider qualification and caller extension

The focused RAM/range and lookup checkpoint gate passes all five tests
(`block_v6_global_commitment_store_test_root.zig`). Restored RAM proving forbids
source replay, preserves exact raw matrices and proof bytes, and freshly verifies
both RAM and range proofs. Lookup restores one fixed basis for the entire group
batch and one main tree per group, preserving proof bytes and fresh verification.
Changed source counters, frame/roster metadata, roots and resource caps fail
closed. Fixed-basis reads are counted once, separately from the number of restored
group first rounds.

The RAM experiment exposed a real ownership assumption: the word quotient
adapter previously required retained coefficients when extending a committed
LDE to its larger quotient domain. Checkpoints containing only evaluations must
recover coefficients, validate the entire high-degree tail, then evaluate on the
quotient domain. The existing validated packed-word recovery now supplies this
path. This removes repeated witness construction and Merkle commitment but does
not eliminate all FFT work; preserving original coefficients is a separate
bounded storage tradeoff. Byte-identical proofs with fresh verification qualify
the recovery path, not a claimed speedup.

Caller arithmetic uses the same independent descriptor, exact original fixed and
main roots and reconstructed raw witness/counter validation. The next transport
keeps its original physical trees rather than repeating their FFT/Merkle work.
External access needs both its raw integer witness and third committed tree; a
reused caller prefix alone does not eliminate this work. Readonly classification
also carries membership columns and interval counters and must receive its own
typed treatment rather than accepting a legacy external cache under that scope.

Optional `ram_commitments.retain_coefficients` now retains the first-pass native
coefficients and transports them alongside the original LDE/Merkle state. It is
false by default. This trades one extra raw-sized coefficient payload plus its
descriptors for avoiding repeated inverse transforms. The codec version and
identity bind this representation, enforce the exact protocol-native log for
each polynomial and account for coefficient storage in both disk and allocation
caps. Focused gates prove byte-identical RAM and range outputs in both modes;
the three-event fixture adds 604,160 bytes across RAM and range checkpoints.
This is an exact payload comparison, not a production performance prediction.

The caller/external transport gate now reconstructs actual SHA and Keccak source
matrices, retains their original arithmetic fixed/main trees and raw external
integer matrices/third tree, checks changed scope, source hash and allocation
limits, and compares physical roots/counters. Full-bundle qualification remains
the authority for final closed-relation acceptance. External selected trace
views are still recovered from caller PCS; eliminating that recovery would need
an immutable raw-view lease tied to the caller owner's lifetime. Readonly
classification and capacity-native modes explicitly reject these optional
caller caches and remain outside this slice.
