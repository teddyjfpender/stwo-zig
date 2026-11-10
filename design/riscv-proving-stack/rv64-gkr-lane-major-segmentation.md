# Lane-major segmented local GKR: source/cost gate

This is a proposed new source protocol. Existing row-major formats, fingerprints,
proof bytes, admission and defaults remain unchanged. The accompanying source
census ran only the first 4,000,000 actual retirements of the pinned selected
OP121065789 guest, matching the independent Unicorn PC and all32 registers.
No new GKR/PCS/root proof was produced. The modeled source is a conditional CPU
fragment with outstanding global obligations and prefix-only INIT.

## Why this is a structural lever

The existing `sponge_cpu/source_inputs.zig` Reader flattens
`physical_row * padded_lane_count + lane`, with dummy fractions N=0,D=1.
`Frame.splitPoint` takes each instance's suffix of the common GKR point and
splits that suffix into row-prefix, lane-suffix. Splitting the14 CPU lanes into
8+4+2 therefore changes its row point across segments. Giving every segment
its own existing16-column binding is expensive.

The proposed source flattens `lane * rows + physical_row`. With MSB-first MLE
coordinates, the local point is now lane-prefix, row-suffix. Every segment of
one original source role and row_log R uses exactly the last R coordinates of
the common point, regardless of lane width. Its lane coordinates are the
preceding log2(width) coordinates. The physical-row to logical-circle mapping
is unchanged. This is not an application of the old split helper.

A canonical descending dyadic cover partitions consecutive real query lanes.
CPU14 becomes [0,8),[8,12),[12,14); MUL97 becomes [0,64),[64,96),[96,97).
The receiver derives this cover from trusted source geometry and a pinned
policy, never from proof-proposed segment boundaries. Role identity includes
origin, offsets and row_log; head/tail sources are distinct even if names match.

## Authentic cost result

| Source policy | GKR instances | Padded facts | Reduction | Metadata envelope |
|---|---:|---:|---:|---:|
| Existing row-major |30|149,605,184|—|6.414MB|
| Segment every role |68|121,295,904|18.92%|10.117MB|
| Segment six high-yield roles |40|123,652,928|17.35%|7.135MB|

The six roles are CPU, MUL, ALU, LS32, BINARY and SHIFT. They capture91.67% of
the possible lane-padding saving with only10 additional GKR instances. Both
policies fit a proposed strict128-instance receiver cap. Max variables26→25;
common batched sumcheck rounds325→300. Per-instance layer/mask records increase
533→732 for the high-yield policy, so proof-size and recursive-verifier cost
must be measured rather than inferred from fewer facts.

The existing conservative52B/fact checkpoint planning model plus numerical
metadata goes from7.786GB to6.437GB for high-yield segmentation. This is a
source-planning estimate, not an observed memory measurement. Native FIXED and
MAIN cells do not change. The same original roles retain143,011,328 local
binding cells if late aggregation below is soundly integrated. Naively adding
one binding per segment instead adds197,132,288 cells for the high-yield policy
(230,047,232 for all roles), defeating the point. No additional physical FIXED
or MAIN column is required by the proposed constant-weight binding equation.
Public source descriptors and recursive verifier arithmetic still grow.

Active/padded row examples: ALU882,634/1,048,576; BINARY202,790/262,144;
SHIFT247,714/262,144; LS32 413,581/524,288; MUL159,744/262,144. These are
captured metadata rows, not nonzero query counts. Padded source rows still emit
unit range fractions and MUST remain in this proposal. Structural tables retain
their full support domains, regardless of multiplicity. Only dummy LANES are
removed. The receipt contains all32 role/bridge/frontier rows, including roles
with no local GKR scope. Requested census peak1.752GB/32GiB, final live/external0.

## One physical binding for all same-role segments

Let segment s have width2^k, lane point u_s, and terminal claims N_s,D_s.
All segments of role r share row point z_r. Complete and receipt-bind the entire
GKR proof before drawing a fresh field coin rho_r for each segmented role.
Use lambda_s=rho_r^s in canonical segment order. Draw an independent fresh mu
for numerator/denominator compression after the full receipt as well.

For each real query lane q in segment s, define its constant binding coefficient
`W_q = lambda_s * eq(u_s, q - first_lane_s)`. The verifier derives the target
`T_r = sum_s lambda_s * (N_s + mu * D_s)`. The existing Eq/prefix construction
can enforce, for this ONE source role,

`sum_rows eq(z_r,row) * [sum_q W_q*(N(row,q)+mu*D(row,q)) + mu*P_r] = T_r`.

P_r is the known weighted sum of any dummy N=0,D=1 lanes retained by an unsplit
low-volume role. High-yield segmented roles have P_r=0. Removing this constant
for the unsplit roles would be a soundness bug. The uniform prefix target uses
T_r/rows; rows are below the base characteristic and invertible. The same
Eq8+prefix8 planes suffice. A constant-weight combination preserves the existing projection degree per
role; aggregation itself adds no degree. CPU REG products/FUNCTION projections
remain nonlinear, and an ALU fixture cannot establish CPU projection linearity.

`prepared_projection.zig` currently requires a power-of-two weight vector and
adds a padded constant. It cannot simply be called with13 aggregate weights.
A clean adapter can instead retain the original power-of-two weight array:
write each derived aggregate coefficient into its original real-query lane and
set coefficients of removed dummy lanes to ZERO. The unchanged projection then
adds a zero padding constant for a segmented role. For an unsplit role, retain
the actual dummy coefficients and its D=1 constant. This reuses the existing
physical projection/binding authority, with a NEW trusted source constructor
for weights/point/target; it must never call the old row-major Data.initChecked
on segmented artifacts. Physical original-role components still emit all
canonical real queries and bind the immutable source MAIN.

Two errors can cancel if lambda is fixed to1. With source MAIN committed and
all segment terminal claims bound before rho, a nonzero role error polynomial
has degree at most segment_count-1. A union bound adds the sum of those degrees:
10 for the high-yield policy,38 for all roles, divided by the secure field size.
The independent N/D compression contributes its own error event. These are
additive conditional soundness terms, not a certified whole-protocol128-bit
claim. Late challenges must not be chosen/retried by the producer, and the
source bounds must include every segment/mask/count plus aggregation terms.

## Trusted version and transcript are mandatory

Current `sponge_cpu/native.zig:draw` and legacy Challenges.drawForInstances infer
v3 challenge selection from a CPU instance with exactly14 terms. CPU8+4+2
would lose that sentinel and silently select the wrong namespace. The new
protocol needs explicit receiver-owned source version and relation-schema
selection. Never scan incoming segmented instances to guess the version.

The new scope/key identity must bind the source format, lane-major order,
ordered canonical segment roster, original role offsets, R, full query count,
challenge namespace and aggregation rule. Mix the FULL proof receipt and the
role/segment identities before drawing late coins. Existing local magic/domain,
old split helpers and old source fingerprints must reject this new format.
All shared fractions, physical globals and execution closure remain unchanged
obligations. No source layout may be selected by an unauthenticated manifest.

Recursion must implement the new point split, all segment verifications and
late weights; fewer facts do not imply a cheaper leaf. No production source
format/worker/receiver/recursion switch has been implemented by this design.

## Gates before admission

1. An isolated small actual GKR child over lane-major segmented CPU/ALU source,
   with independently derived canonical roster and explicit source version.
2. One physical source binding that closes every segment under late powers
   aggregation. Test malformed covers, duplicated/omitted/reordered lanes,
   wrong row-prefix/suffix, wrong key/version, stale or early coins, padded
   constants, full-coordinate forgeries and coordinated segment errors.
3. A source-derived composed security ledger, strict128-instance and memory
   admission, bounded codec and fresh independent verifier.
4. Recursive cost/identity and complete global/execution closure qualification.
   Only then compare a real conditional4M child, followed by a separately
   authorized complete block. No heavy execution/proof is needed for this gate.

`scripts/rv64_gkr_lane_segment_report.py --self-test` checks canonical covers,
MSB/LSB row-suffix semantics and late-aggregation multilinear identities over
base-field samples. These are algebra/source-order tests, not physical proof
rejections or security certification. The committed receipt records the
source-only capture and reproduction paths.

## Reader feasibility and small prototype boundary

Lane-major ordering changes contiguous source reads. The existing row-major
reader emits all T queries once per row. Naively calling that same full emitter
for each single lane-major fact would compute up to T² denominators per row,
not T, and could erase the entire saving. A dense N/D cache is not a remedy
within this proposal. The first bounded ALU prototype instead switches on its
trusted lane: lanes0..11 extract exactly one saved U16 value; lane12 extracts
one FUNCTION payload. Every requested fact is checked against the original
committed-MAIN fraction emitter. Production CPU and other roles need equivalent
per-lane specialization or independently bounded tiling before any speed claim.

The retained4M phase measurement was0.659s fused source/tree construction versus
2.751s traversal/regeneration. It does not establish what either bucket will
become under the changed ordering. More segment metadata, point projections and
masks can offset the saved facts; no wall multiplier follows from18.92%.

The ALU prototype intentionally leaves FUNCTION/range closure outstanding. It
verifies an actual3-instance GKR child (416facts, old512), derives a single
late-aggregated physical binding over the original47 MAIN columns and16 binding
columns, and retains the original ALU degree3/2n authority. It is a conditional
source-binding experiment, not a new execution route. Neither its key nor its
local envelope is registered with OP production admission.

## Qualified isolated ALU binding gate

The closed `sponge_cpu/segmented_lane/alu.zig` prototype and its test pass a
ReleaseSafe physical gate: three actual source-checkpointed GKR instances,
416facts, original47-column ALU MAIN and ONE16-column binding. It deliberately
uses the existing OM31/Blake2s role-test PCS authority with B4/q72 parameters;
it is not a production Pure-P2 OP proof or a new live source admission.
A fresh receiver decodes the distinct bounded local envelope, verifies every
segment and derives the late coefficients/target independently. No incoming
physical key, free terminal claims or legacy row-major binding artifact is used.

A valid proof first rejects a different independently known source context,
then the same unchanged proof accepts under its correct context. Malformed
source version/cover/order and local-envelope magic/count reject separately.
The physical controls retain invalid PCS proofs and require a fresh receiver
to reject them: opposite constant denominator errors with a valid GKR child
and cancelling unweighted terminal errors; early all-one aggregation whose
numerical cyclic prefix still closes; Eq mutation; prefix mutation. Thus these
are not merely host parse failures or a prover refusing to build bad witnesses.
The source extraction is compared against the original committed-MAIN fraction
emitter for every row/lane, including padding. Global row-suffix behavior is
also tested with an11-coordinate common point and differently sized segments.

The additive guard keeps the unchanged conservative native cap ledger and adds
this three-instance scope:252 sumcheck degree weight,40 instance mixing,3 late
binding (conservatively covers fresh mu),30 degenerate point weight, and2 for
the fresh rho degree(segment_count−1). It still requires the existing151-bit
raw-modulo algebraic envelope. The new aggregation/independent compression
alone has a union bound≤3/|OM31|. This is a128-bit security target under the
existing documented hash/FRI/Fiat-Shamir assumptions, not certified whole-protocol
security. Full same-role aggregation in a live scope still needs its own exact
source-derived ledger, recursion and global closure qualification.

All71 focused tests pass; positive requested peak2,629,652bytes/2GiB, all
live bytes return to zero after every case. No speed measurement is claimed.
FUNCTION/range output debts remain unclosed: this gate proves conditional source
binding, not complete lookup, execution, block or root acceptance.
