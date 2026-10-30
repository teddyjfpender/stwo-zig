# Bounded multi-window original STARK

The bounded multi-window path now proves all native windows, active callers, ROM, compact lookup and joint memory in one original STARK. Fresh verification reconstructs the full scope and closes every provider after all producer and original-proof owners are destroyed. This is qualified on the fixtures below, including canonical security for a 20,495-cycle, two-window workload. It is not a complete Ethereum-block benchmark or an unbounded streaming prover.

## Admission and placement

`prover/block_v7_multi_union_scope_v1.zig` accepts independently selected ELF/profile/terminal/configuration plus native pins, active caller pins, one decoded-ROM provider, one compact lookup provider and one joint-memory provider. It derives initial memory and ROM from the ELF, checks exact epoch family counts and source identities, couples each caller to its native window, derives table demand, and calls the original `Policy.validateWindows`. That checks contiguous cycles, PC/register custody, terminal first-halt completion and exact initial/final boundaries. No producer success receipt is an input.

The source roster is all natives in index order, all callers in index order, then ROM, lookup and memory. `block_v7_multi_union_placement_v1.zig` assigns shared fixed tree zero, every actual first-round private tree, then each family's actual interaction trees. A native source has three local trace trees without access or four with access. A caller has five. Each global provider has three. There is no fabricated empty access tree for a boundary-only native window.

Total proof commitments, including composition, are `8 + sum(native root_count) + 4 * caller_count`. Thus two natives with root counts 2 and 3 and one caller produce 17 commitments; one access-bearing native and one caller recover the existing 15-tree layout. The transcript binds this independently derived placement under the distinct B7UM version-1 domain. It does not accept the single-window proof tag with a different shape.

## Memory boundary

The mandatory `max_retained_pcs_bytes` policy is checked against raw-column geometry derived from the original native template/projections, active caller layout, ROM, compact lookup and joint-memory layout. The estimate includes materialized trace LDEs, coefficients, conservative full Merkle storage, descriptor arrays, and source fixed storage still retained while constructing the merged fixed tree. It is a planning bound for these listed trace allocations. It excludes composition/FRI working buffers, raw source witnesses, allocator overhead and process memory. Those require a separate hard allocator budget and measured peak.

Loading one immutable source checkpoint at a time limits raw witness residency. Once its polynomials are adopted into one original STARK, they remain needed for composition and openings. Therefore checkpoint streaming alone does **not** bound total private PCS residency independently of window count. The first production extension must refuse a group whose independently derived retained geometry exceeds its explicit limit.

## Qualified proof path

`block_v7_multi_union_proof_v1.zig` uses the admitted placement with the shared dynamic heterogeneous adapter. It adopts original private commitments with their original allocator/tree leases; it commits each original interaction tree and proves one composition/FRI over every original equation. All physical claims and the exact typed roster are transcript-bound. The merged fixed columns are rebuilt independently on verification, including the original log-2 physical-frame column for external-only native segments.

Fresh verification derives the scope, fixed columns, maps and verifier components from trusted metadata, checks every private root and the merged fixed root, then verifies the STARK. Only afterward does the original execution claim accumulator close every native window, its owning callers, ROM, six table buses, memory transition/census and state/register residuals. Joint memory's original physical-claim closure remains mandatory.

The current fixture keeps source stages resident until the union proof is created. Loading independently pinned checkpoints one at a time and releasing raw witnesses is a remaining production integration; the proof path itself already retains allocator-correct private commitment leases.

For jobs exceeding the admitted group's memory, proving separate groups yields **open** source relations. Such groups need an authenticated final reduction and the complete global provider closure. They cannot be labelled complete execution proofs independently, nor can their metadata be relabelled as successful recursive frames.

## Current checks

All five ReleaseSafe runs passed 467 tests with one unrelated skip. Every run includes the genuine static nine-tree native/caller regression, an original-proof oracle under the identical epoch, exact physical-claim equality, producer teardown, fresh independent verification, and hostile claim/root/roster/ELF/output mutations.

| Workload | Native windows | Callers | Proof trees | Separate originals | Union prove | Fresh verify | Proof bytes | Charged proof peak |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 20 cycles, cut 7, q8 | 3 | 1 | 20 | 7 | 2.360 s | 1.176 s | 1,261,735 | 240,858,652 |
| 20 cycles, cut 3, q8 | 7 | 1 | 29 | 11 | 2.448 s | 1.209 s | 1,276,430 | 366,006,408 |
| 20 cycles, cut 2, q8 | 10 | 2 | 39 | 15 | 3.170 s | 1.517 s | 1,538,501 | 470,682,840 |
| 20,495 cycles, cut 10,248, q8 | 2 | 1 | 18 | 6 | 3.121 s | 1.221 s | 1,287,171 | 342,366,001 |
| 20,495 cycles, cut 10,248, q70/PoW26 | 2 | 1 | 18 | 6 | 3.479 s | 1.389 s | 6,016,333 | 342,298,617 |

These timings are diagnostic, not a controlled speedup comparison. They exclude guest/source setup and the independent oracle from the prove timer. The canonical qualification process took 31.49 seconds with 357,531,648-byte maximum RSS, including the oracle, hostile checks and imported suite. That process time is not service latency. Cut 3 and cut 2 include an actual physical-frame native; cut 2 exercises different active caller inventories in separate windows.

The larger fixture contains 205 fixed columns but only 133 distinct columns. Deduplication could remove 367,652 of 1,156,984 fixed LDE cells (31.8%, about 1.47 MB of field data). That is a fixed-tree opportunity, not a comparable reduction of the full trace or total proof time.

Exact binary, source and log hashes and all metrics are in `performance/v7-multi-union-proof-qualification-20261029.json`. Earlier metadata-only qualification remains separately recorded in `performance/v7-multi-union-scope-qualification-20261029.json`.

## Bounded saved-artifact receiver

The subsequent `B7MUN001` transport is implemented in `block_v7_multi_union_codec_v1.zig`. Both the canonical two-window fixture and canonical ten-window/two-caller fixture were saved and verified in fresh processes with independently reconstructed ELF/output/security policy. The artifact includes canonical claims and STARK bytes; proposed typed source metadata remains external. The JSON fixture importer is not a production metadata parser. `ProofView` exposes a borrowed verifier view without a fake producer arena or ownership transfer.

Runtime postcard preflight derives the exact tree inventory from the independently admitted scope, including the ROM empty tree. It supports a bounded 257 commitments (256 traces plus composition), with no decoder-selected tree count. Existing four/five/static-tree behavior remains unchanged. Fourteen standalone preflight tests cover shape mismatches, empty-tree positions beyond a 32-bit mask, hard tree limits, length bombs and scalar framing. Full wire gates reject schema/epoch/config substitution, truncation, trailing data and allocation exhaustion; explicit lifting remains unqualified and rejected.

The complete proofs also exercise opt-in coefficient-backed joint-memory inputs and bounded quotient tiles. Proof-producing qualification passed 11 focused tests per fixture; fresh-process reload passed eight. See `vectors/reports/block-v7-multi-union-20261029/README.md`, its per-fixture receipts and `results.tsv`. This qualifies bounded original-proof transport, not full Ethereum execution, recursive publication or unbounded input residency.

## Active-layout V3 and producer capacity follow-up

The current active caller omits all five SHA components and their table
projections when the independently admitted SHA call count is zero. Active
collection omits the corresponding padded lookup requests and the verifier
requires every omitted physical claim to be zero. The layout identity advances
to V3; historical V2 artifacts above remain performance evidence, not fixtures
for the current verifier.

A canonical seven-window fixture isolates SHA, Keccak-only and SHA into three
caller windows. Its single original STARK matches all thirteen original family
proofs' physical claims, closes the real native/ROM/lookup/RAM relations and
verifies in a fresh process. This is the required zero-SHA global closure check;
an isolated caller's internal residual would not suffice. The omitted-SHA
Keccak composition circuit also matches its genuine original proof and rejects
mutated omitted fields; no new recursive parent is claimed by that gate.

The current two-window canonical fixture additionally consumes the source
memory producer after handoff and keeps input/interaction coefficients instead
of retained LDEs. Its explicit producer admission succeeds at 174,618,288 bytes,
below the old 187,993,904-byte retained-PCS model. Both models exclude other
phases, which remain bounded by the hard outer allocator. The actual tracked
proof peak is 311,708,246 bytes. Verifier admission, public statement and global
closure checks are unchanged by this producer resource option.

Current saved artifacts and receipts are in
[`block-v7-active-caller-v3-20261029`](../../vectors/reports/block-v7-active-caller-v3-20261029/README.md).
These are finite synthetic execution qualifications, not a full Ethereum proof
or a claim that the entire retained block fits one batch.
