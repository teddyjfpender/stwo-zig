# Authenticated input and read-only specialization

The current complete receiver already authenticates public input. There is no
missing input-value authority in its general RAM route. The remaining ID2 gap
is a specialized proof route that can remove input accesses from the mutable
clock chain while proving the same execution semantics. Address classification
alone cannot justify that removal.

## Current authority and semantics

* `runner/segment_session.zig` installs independently supplied input bytes into
  the loaded memory image. `runner/memory_state.zig:MemoryLayout.isInputAddr`
  only classifies an interval inside the RW union; it establishes no write
  protection. The first segment snapshot labels input words as initial public
  sources, retaining their actual final clocks and values.
* `runner/load_store_retirement.zig:Plan.publishAssumeCapacity` writes every
  admitted store with `Memory.writeU32AssumePrepared`. Neither that function
  nor `air/lang/typed_load_store.zig` applies an input-interval write ban.
  Typed memory reads/writes retain the ordinary clocked memory tuples.
  SHA, Keccak and signer memory words likewise use the shared mutable bus.
* `prover/block_v5_initial_source_receiver_v1.zig:check` checks input hash and
  length, derives little-endian words including the zero-padded partial word,
  matches the nonzero input roster and reconstructs the full initial RW root.
  Its exact first-touch tuples close the fresh sorted initial relation.
* `prover/block_v5_rw_endpoint_sources_v1.zig:check` accepts both input and
  private-RW endpoints, merges their actual final values with untouched initial
  leaves and checks the independently pinned full final root. Input words are
  retained when untouched and updated when touched; they are not forced to
  equal their initial values.
* `prover/block_v5_ram_lanes_receiver_v1.zig:verify` freshly verifies each
  independently sized lane/range proof, exact link/initial/final buses and
  source files. `prover/block_v5_word_memory_join_v1.zig:finish` closes their
  transition sum/count against the freshly verified native/caller fused access
  partitions. `prover/block_v5_global_receiver_v1.zig` closes the remaining
  universal memory and arithmetic accounting.

This mutability is intentional in existing fixtures:
`prover/block_v5_initial_source_test.zig:initial` includes an input transition
from `input_value` to `input_value+1`. A policy that silently treats all input
addresses as immutable would reject a currently admissible execution or, if
it simply dropped accesses, accept an unproved read. The name "read_only" in
ordinary opcode register-read layouts also means before=after for one access;
it does not independently prove a cell's entire global lifetime immutable.

## Proposed independently admitted protocol

Add an explicit, versioned `ReadonlyInputPlan` containing bounded ordered
immutable input intervals, the public-input hash/length, independently pinned
layout, exact interval digest and resource limits. Empty intervals retain the
current RAM route. The plan is an independent execution policy, not a selector
inferred from register mode, a host observation or received proof metadata.
Every selected address must lie inside the public-input interval. Bytes and
zero padding determine all provider values, including zero words omitted from
the sparse image. A writable-input job can select an empty plan; it retains
the current semantics.

The native and caller composite proofs must partition **every** real memory
access using an authenticated membership selector. Prove selector Booleanity,
aligned u32 address membership/nonmembership against the admitted ordered
intervals, and exact slot/ordinal coverage. Range checked address/gap witnesses
are necessary: an unconstrained host selector or a supplied address list does
not prove nonmembership. For selected accesses prove before=after and request
the public tuple `(byte_address,u32_value)` from a distinct input-read relation.
Caller accesses must use the same classification, including all actual output
words; checking ordinary loads alone leaves a write bypass.

The first cohesive route preserves every original ALL-RW universal-memory
opposite and byte-range request. These still cancel the unchanged native/caller
base AIR and its original clock-gap requests. There is no selected-universal
subtraction in the final residual. Only the packed-transition relation and its
sorted RAM census change: the classifier exports the mutable transition sum,
and selected accesses prove before=after=the independently derived input value.
The input-read relation has a distinct domain/tag/ABI. Public providers close
classification and reads with bounded exact nonnegative request multiplicities.
Closure is per independently field-safe source/group, never only a block-wide
scalar or counts modulo M31.

Unselected accesses retain all lane transitions, clocks, endpoints and RW
custody. Selected accesses initially retain their original byte witnesses and
14-per-event byte requests as well; removing those is a separate base/access
recipe migration and is not necessary to remove their sorted clock/value chain. The new memory plan binds
`all_real_RW = mutable_lane_events + readonly_input_accesses` together with
each authenticated source partition; no access or ordinal disappears.
Initial/final full-image roots still include every input word. Selected
intervals have no mutable endpoints and retain initial values; independent
nonmembership classification ensures no mutable lane event can modify them.
Public input read checks preserve byte/halfword alignment and sign-extension
semantics through the unchanged instruction equations.

## Cohesive engineering boundary

First implement isolated plan/source/component/protocol modules and scalar,
mask, degree and mutation fixtures. Suggested new files under `prover/` are
`block_v5_readonly_input_{plan,source,component,protocol}_v1.zig`. Before
canonical integration, review the concrete classification witness layout and
degree bound; a projection-only subtraction is not acceptable.

Integration must then cover the native and caller fused component/proof/
receiver/stage modules, first-pass replay/planning/source writer, B5SS
policy/digests, strict independently capped artifact/store policy, Programs
hooks, MemoryJoin and Global accounting. Preserve ALL-RW access descriptors
and byte-demand counters; add separate mutable/readonly census fields.
Source-family roots and identities must change with the actual new witness and
claim grammar. The current frozen recipe files must not be edited during their
qualification. RAM lane proof/Stage/PCS and GPU files belong to the resident
lane batch and require coordination; they should only consume a genuinely
reduced mutable plan, with unchanged lane equations.

Meaningful fixtures should cover all of: real LW/LB/LH unsigned/signed input
reads and unchanged instruction/access ordinals; zero and partial final words;
native/caller writes inside selected intervals rejected; the existing input
write fixture accepted with an empty readonly plan; SHA/Keccak/signer overlaps;
forged selectors, intervals, address/value/clock/claim counts; cross-group
provider bounds; untouched selected words in both sparse roots; exact mutable
and readonly census parity; wrong protocol/key/mask rejection; and actual cold/
warm/store/global function-body generation. Full fresh proofs remain a later
root-authorized qualification step. No source/run performance benefit is
established by this design.

Savings depend on actual read-only access counts. The historical 675,177 input
**first touches** describe distinct source addresses, not total input events
and not a proved immutable census. They cannot be used to predict memory proof
count, bytes or speedup. Collection needs an exact separate admitted readonly
access census before any such comparison.

## Isolated source implementation

The isolated `block_v5_readonly_input_{plan,protocol,component,proof,receiver}_v1`
modules now implement this first acceptance boundary. A public plan derives a
complete ordered partition of the aligned u32 address space: selected input
words are immutable singleton intervals with independently derived values;
all complementary intervals remain mutable. The classification witness has
103 main columns, one independently reconstructed fixed activity column,
20 interaction columns and 205 equations of degree at most three. Thirty
Boolean word-address bits and two thirty-bit interval differences prove
membership and nonmembership without reducing u32 addresses modulo M31.
Separate LE16 limbs retain full u32 values and all four u64 clock limbs.

A genuine shared PCS/STARK producer and CPU verifier bind the new ABI, original
source identity, independently admitted plan, exact logical event census,
physical geometry and configuration. Exact nonnegative integer provider
multiplicities close classification and input reads against public input.
The original all-RW packed transition relation and count close the source
multiset. The receiver consumes original native/base-composite or
caller/base-composite proof bytes and freshly verifies them internally before
accepting this partition. No externally supplied scalar receipt is authority.
Their original register, ROM, table, universal-memory and byte obligations
remain available in the returned scoped source receipt.

The nonproving root is `block_v5_readonly_input_unit_test_root.zig`, filter
`block-v5 readonly input`. It retains actual producer and fresh CPU receiver
function bodies without invoking them. Its behavioral fixtures cover selected
zero/partial input words, mutable fallback, stale bytes/source/subset pins,
membership/nonmembership, coherent classification and high-clock substitution,
exact provider/source counts, padded cells, scalar/SIMD/OODS mask parity,
resource/owned-matrix validation and exhaustive collection allocation failures.
These sources have not been compiled or executed by this agent.

This isolated protocol adds its own genuine proof; it does not yet fuse the
classification into existing native/caller commitments. No classifier partition
can enter `MemoryJoin` or subtract RAM events until the complete consumer and
transport batch lands. That batch must bind the plan in the common seal and
source-family grammars, independently cap the new wire arrays, stage the actual
classification witness, account all source events once, send only classified
mutable transitions to lane planning, preserve ALL-RW byte/universal obligations, retain full
initial/final input roots and close public classification/input providers before
`MemoryJoin` finishes. Source matrix limits bound host matrix storage, not total PCS/LDE/FRI workspace or peak RSS.

No canonical policy, default recipe or writable-input semantics were changed.
No build, test, guest, segment, STARK, device or benchmark was run.


## Concrete canonical integration boundary

The smallest implementation changes the existing native/caller fused proof,
not the separately retained base arithmetic proofs. Append classifier witnesses
to the actual access-witness tree and open original address/clock/value columns;
do not regenerate another arithmetic matrix or copy the original eight clock/
value limbs into a separate classifier tree. Bind the classifier ABI, public
selection/final plan digests, exact rosters and the new real access root in
versioned family 3/13 access entries and family 4/12 fused identities. The
existing standalone classifier remains scoped while this is implemented. A
permanent extra source family/proof is unnecessary for the fused route.

The isolated classifier's degree-three bound assumes an independently fixed
activity column. In native load/store RW-only slots, actual activity can be
`enabler * space`. Its readonly value constraint can therefore have degree
four. Source-mask and quotient degree must be derived from the authenticated
native/caller source DAG and the actual remapping, including arbitrary OODS
values. Reusing the isolated degree-three ABI without this derivation is unsafe.

The canonical all-RW fields `ordinary_events` and caller `expected_rw_events`
currently determine byte demands, source proof census and provider bounds.
Keep their meaning. Add independently admitted `all_rw_events`,
`mutable_events`, and `readonly_events` per source, with checked exact integer
identity `all_rw_events = mutable_events + readonly_events`. Claim/provider
arrays need independently derived per-source/group bounds and preallocation
limits. Public interval multiplicities can be shared by all classifier slots
inside one source proof; their exact total must equal that source's all-RW
census and their selected mass its readonly census. No field-safe closure may
be replaced with a global-only sum.

Ownership/files for the coherent batch are:

* Public authority, policy and seal: `block_v5_cpu_driver_admission_v1`,
  `block_v5_source_seal_v1`, `block_v5_cpu_receiver_policy_file_v1`,
  `block_v5_cpu_assembly_v1`, `block_v5_cpu_bundle_policy_v1`. Use an explicit
  tagged mutable-only/selected-input policy, not register-mode or address
  inference. Bind it in job/source identity and B5SS. Reject old fused grammar
  under the selected-input policy.
* Source/fusion: `block_v5_native_memory_stage_v1`, native fused v2 component/
  proof/receiver/stage, caller fused schedule/component/proof/receiver/stage,
  `block_v5_caller_pipeline_v1`, ordinary/external access trace/evaluation and
  a shared classifier adapter. Preserve source slot/ordinal identities and
  byte-counter snapshots; retain each source's original universal opposite.
* Collection/lifecycle: `block_v5_cpu_collect_v1`, `block_memory_replay`,
  `block_v5_cpu_global_plans_v1`, `block_v5_sorted_memory_replay_v1`,
  `block_v5_memory_source_writer_v1`, staged native/caller loaders and CPU
  driver. Project original u64 clocks before deterministic mutable filtering;
  sort only actual mutable events. Keep full initial input files.
* Transport: `block_v5_cpu_stark_codec_v1`, `block_v5_cpu_bundle_store_v1`,
  bundle policy and manifest/metadata. Independently cap each distinct claim
  and counter array before allocation; derive tree columns/root counts/logs/
  configuration and grammar from trusted rosters. Existing Store publication
  mutex and ownership remain mandatory.
* Fresh closure: `block_v5_program_native_batch_common_v1` composite hooks, `block_v5_word_memory_join_v1`,
  `block_v5_native_table_join_v1`, `block_v5_global_receiver_v1`, initial/final
  source receivers and tagged sorted receiver. Programs freshly verifies the
  original base plus new fused proof once, closes public classification/read
  providers and passes the scoped partition through private hooks. Only its
  mutable sum/count cancel sorted lanes. TableJoin still consumes ALL-RW byte
  requests. Independently planned range16 providers follow actual mutable
  lane rows. No change to the final native/universal accounting equation is
  needed in this first slice.

First-touch and final endpoint rosters must reject selected addresses. Their
full image merge still retains selected words from the independently verified
initial input roster; zero words and partial final input words follow the same
public derivation. An empty subset has the existing writable-input semantics.
No-RW sources have independently reconstructed typed absence. All-readonly
sources still require real base/fused/classification proofs, while sorted RAM
and range16 have zero real instances and use existing fresh empty source/root
checks. Mixed selected and unselected stores remain mutable except that every
selected access must keep the derived public value. Summary/metadata must
report all-RW, mutable and readonly counts separately.

## Two-pass proposal and late binding

There is a concrete dependency: Plan v1 binds `InitialSources.Pins.digest()`,
which includes first-touch file pins. Those files depend on the mutable stream,
so the final digest is unavailable when first-pass collection must classify.
Do not synthesize provisional file pins or treat a provisional source digest
as final authority.

The source-owned proposal seam should separate these phases:

1. **Independent selection admission.** A bounded `SelectionAuthority` contains
   actual initial full RW root, input layout, independently pinned input
   hash/length, ordered selected addresses and caps. Derive intervals and
   values from the actual supplied bytes using the same canonical interval
   kernel as Plan v1. Its digest excludes event/first-touch files. This is a
   trusted job policy; it never infers immutability from a trace observation.
2. **Physical collection.** `collect(a, Selection, ActualSource, Limits)` returns
   an owned small `Proposal` binding source kind/index/frame, source-roster
   digest, selection digest, real prefix/access/classifier roots, physical
   geometry/configuration, exact all/mutable/readonly counts and counter/witness
   file pins or snapshots. It does not retain witness matrices, PCS trees or
   an accepted receipt. Cross-check the actual source access stream and staged
   columns; host classification is only candidate witness generation. Keep
   replay mutable filtering disabled until complete canonical closure lands.
3. **Final-plan binding.** Once real mutable first-touch/source files exist,
   `Proposal.bindPlan(a, Selection, ActualInitialSourcePins, ActualSourceBinding)`
   independently derives the final Plan v1. Require actual input hash/length,
   layout/initial root and all intervals/values equal the collected selection,
   and require physical roots/rosters/geometry/census unchanged. Produce actual
   common-seal entries and independent receiver pins. There is no fake initial
   source artifact and no relabeling of a provisional digest.
4. **Seal/challenge binding.** Entry identities bind final plan and source
   geometry but must not depend on the final seal digest, because that digest
   already includes entries. After the roster is sealed, derive the isolated
   source identity/challenges from the actual seal, actual source instance and
   roots. Keep pre-seal instance IDs distinct from this post-seal challenge
   identity; otherwise the protocol has a circular dependency.
5. **Staged warm production/fresh receive.** Reopen original staged columns,
   derive the identical classifier witness once, recommit the exact collected
   access root and compare rosters/census/counter snapshots. Borrow the live
   base fixed/main prefix into the common proof. Success consumes the local
   fused proof at durable publication; errors release local ownership while
   leaving borrowed base ownership valid. Fresh CPU verification reconstructs
   the public plan from independent pins/bytes and opens the same component,
   with no caller-supplied scalar shortcut.

## Source-owned proposal seam

The bounded seam is now implemented in new
`block_v5_readonly_input_selection_v1.zig` and
`block_v5_readonly_input_proposal_v1.zig` modules. It remains isolated and does
not activate canonical RAM filtering. Shared additive `InitialSources` layout
and little-endian input-word helpers preserve the original validation, and
Plan v1 now forwards interval/value construction to the same kernel used by
Selection. Its public API and final digest grammar remain unchanged.

`Selection.derive/admit` own the exact ordered subset and complete interval
partition, checked against actual immutable layout/initial root/input bytes
and independently expected selection digest/caps. `Selection.require` also
rejects mutation of the owned interval/value arrays after admission.
`Proposal.ForBackend(Backend).collect` takes the original live two/three-tree
PCS prefix plus independent source kind/index/frame/roster/root/config/census
pins. It compares actual prefix roots, validates already-global u64 access
clocks without projecting them twice, builds candidate classification rows,
commits real bounded classifier fixed/main roots, and releases all local trace
and PCS ownership. The original prefix remains borrowed and unchanged. The
returned Proposal is a fixed-size value retaining roots/census/event and
counter snapshots only; it is not a fresh source receipt.

`Proposal.bindPlan` checks an independent Expected physical/census pin,
selection authority, actual InitialSources.Pins and independently expected
actual source-plan digest. Changed initial root/layout/subset/input/caps,
physical roots/roster/census and source-file hashes reject. It derives and
owns the final Plan v1 using actual source-file pins and requires exact shared
interval/value equality. `Bound.pinAfterSeal` derives only the later
classification proof pin after requiring the actual common seal, source entry
and access root; it keeps this seal-dependent challenge identity out of
pre-seal Entry identities. No classification proof/RAM authority is issued by
these constructors.

The new root is `block_v5_readonly_input_proposal_test_root.zig`, with filter
`block-v5 readonly proposal` (six new named fixtures; the root also imports
the existing isolated classifier tests). It includes actual small CPU PCS
source/classifier commitments and recommit parity without invoking a STARK.
Those source columns are candidate commitment fixtures, not authenticated
native/caller AIR or Complete receipts. Tests cover shared derivation,
independence from eventual source files, stale authority/actual-source/physical
pins, high-u64 clock/census checks, writable fallback/all-readonly/no-RW typed
absence, borrowed-prefix lifetime, exhaustive selection/trace/bind allocation
failures and actual collection/post-seal function-body retention.

Canonical fusion, source-seal policy/entries, strict transport, private fresh
hooks and mutable lane/source closure remain the next cohesive scope. Existing
base arithmetic, register custody, ALL-RW byte/universal closure, default
recipe and mutable-input semantics are unchanged. Host matrix/census caps do
not imply a total PCS/FRI/peak-RSS budget; full production allocation/resident
accounting must retain the repository's independent budget and coordinator
limits. Root qualification of this seam is recorded below.

## Focused root qualification

The isolated source gate now passes14/14 (seven named contracts and seven import
checks), including the actual producer and internally fresh native/caller receiver
bodies without invoking them. The corrected malformed-wire census case also
passes2/2 in Debug. All eight frozen code hashes match. The generic quotient row
kernel now grants compiler evaluation proportional to main-column width; its
runtime equations and degree bounds are unchanged. The malformed fixture now
corrupts a raw limb after constructing a valid claim, rather than violating a
field constructor's canonical-input precondition.

Evidence is retained in `cpu-performance-gates-v1/readonly-input-source-qualified-v1.json`
and its linked logs under the Ethereum block delivery notes. This is isolated
classification qualification. Canonical source/fusion/transport integration and
reduced mutable RAM planning remain outstanding. No fresh STARK,
segment, device or benchmark was run.

The additive Selection/Proposal seam now passes20/20 focused checks (six new
named contracts, seven prior classifier contracts and seven import checks).
Tiny CPU commitments exercise actual borrowed-prefix and classifier replay;
producer, binding and post-seal bodies compile without being invoked. Evidence
and twelve source snapshots are recorded in
`cpu-performance-gates-v1/readonly-input-two-pass-proposal-qualified-v1.json`.
The existing native zero-RW seal uses a mandatory family3 entry with a nonzero
typed-absence hash; the proposal's required access identity preserves that
policy even when no access tree or classifier commitment exists. This is not
canonical RAM filtering or a completed block proof.
