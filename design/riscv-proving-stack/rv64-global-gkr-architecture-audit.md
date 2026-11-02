# Global GKR: authenticated closure, cost and protocol staging

Status: source-derived engineering review, 2026-11-02. No new execution protocol,
GKR security theorem, production acceptance path or GPU speedup is qualified here.
The control remains the existing CPU-local-GKR / truth-classic-OM31 profile.

## First result: a direct replacement is a small cell reduction

The complete 25-CPU / five-truth roster has 17,461,658,112 committed MAIN+INTER
M31 cells (per-proof FIXED excluded). Its global classic arguments occupy
832,155,648 cells. A separate GKR instance and authenticated Eq/prefix binding
per role and namespace would require 716,283,904 binding cells, saving
115,871,744: **0.664% of MAIN+INTER**, before any new GKR work. The corresponding
unpaired input catalog has 103,416,320 power-of-two-padded facts.

| Physical group | Current OM8 INTER columns | Separate GKR binding columns | Difference |
| --- | ---: | ---: | ---: |
| LS RAM (two signed queries) | 16 | 16 | 0 |
| INIT / TEARDOWN RAM (one query) | 16 | 16 | 0 |
| Keccak bridge RAM + KIO | 32 | 32 | 0 |
| secp bridge RAM + Wire | 56 | 32 | 24 |
| Keccak truth KIO (25 queries) | 208 | 16 | 192 |
| secp truth Wire, each product / linear (three queries) | 32 | 16 | 16 |

This uses the current 8-coordinate Eq plus 8-coordinate running binding. It
keeps each namespace's terminal claim independently authenticated. It assumes
unchanged MAIN and statement authority, not free unproved host marginals.
The exact roster, source digests and per-family cell arithmetic are recorded in
`vectors/reports/rv64-gkr-tree-checkpoints-20261102/global-gkr-counterfactual.json`.
Source authorities are `global_cpu.layout/queriesFor`, `truth_global`, and the
current `binding` / `frame` layout. Keccak's current 5,368 INTER columns include
only208 global columns; replacing KIO alone does not remove its local lookup
proof. Native cells also do not equal lifted opening or recursive gate cost.

An additional GKR can remove inverse/prefix-generation work even when its
binding has the same committed width. Whether it wins CPU/GPU time is a measured
question: it adds a product tree, sumcheck, terminal projection and verification.
There is no justified large multiplier from the global replacement alone.

## Existing authority that must survive

`manifest.verifyAndSeal` independently checks the complete ordered worker roster,
receiver-derived statements, FIXED roots, MAIN roots and actual local child
proofs. Its canonical seal binds the local terminal marginals before deriving
shared OM31 RAM14, KIO11 and Wire35 compression challenges. The complete receiver
then authenticates the same physical roots and separately closes all three
claims. Absent-relation claims must be zero. Characteristic/mass preflight runs
before allocation/challenge derivation; declarations are receiver-reconstructed.

CPU global queries come from `global_cpu.queriesFor`: LS before/after RAM,
INIT negative and TEARDOWN positive RAM, bridge RAM and service I/O. Native
metadata uses the same tuple authority and survives owned MAIN transfer. Truth
KIO and Wire queries use the original crypto equation authority. No new mode may
replace these by unrelated host-generated tuples or claim-only summaries.

A valid GKR output is a projective (N,D) pair. The receiver must require D!=0
before division, including zero-weight poles. Every terminal input marginal must
be bound to the original committed MAIN (and independently admitted FIXED / public
endpoints); a numerically valid GKR child is not execution verification.

REG / OWNER and function buses are currently proof-local and carry different
semantics from global RAM. They must not become unconstrained cross-shard debts.
INIT / TEARDOWN remain anchored to independently expected image and terminal
cells, including sparse initialization, unchanged words and final output. Worker
sequence coverage, CPU endpoints, epochs and service ID coverage remain mandatory.

## Safe but modest first implementation option

Keep the existing stage-one manifest unchanged. After its shared draw, construct
one explicitly scoped global GKR child per worker from the committed MAIN and
retained metadata, with separate receiver-owned instance catalogs per namespace.
Bind the child digest, claims and terminal artifact into the physical worker
transcript before late binding challenges and INTER commitment. The independent
receiver replays the child transcript from expected profile, statement, ordinal,
FIXED, MAIN and sealed manifest. It verifies each projective claim, pole guard and
native physical terminal binding, then sums RAM/KIO/Wire separately at execution
root. No producer-selected optional group or unknown relation is accepted.

This is mechanically bounded and reuses the streamed source and immutable
retained store. It needs a distinct explicit protocol/version and matching wire
and recursion statement. It is suitable as a measured counterfactual, not an
assumed speed improvement. Delay retiring narrow RAM/bridge metadata until this
child's terminal binding has been produced. Spill/restore preserves coefficients,
Merkle roots, child artifacts and all unclosed obligations; original MAIN rows
must not be rebuilt or kept merely to supply GKR inputs.

## Larger architecture: one point and binding per role

The current ordering is local child -> manifest -> shared globals. Reusing the
local GKR point for global relations would be circular: the point was drawn
before global challenges, while the manifest includes that child. A sound unified
protocol can instead seal ordered statements/FIXED/MAIN/catalogs first, draw all
scoped local and global namespaces, then run worker GKR and physical binding.
Local child digests are then bound by the subsequent native proof, not used to
derive their own preceding relation challenges. This is a full transcript change.
It changes the stage-one barrier and metadata retirement timing and therefore
needs measured retained-memory admission, independent receiver and recursion.

Sharing an Eq between multiple instances is not automatically sound. Current
`frame.splitPoint` is row-major: local point=common suffix, row point=its prefix,
lane point=its suffix. Different lane logs therefore give different row points,
even within one role. The existing code correctly keeps separate obligations.
One possible new layout is lane-major indexing, putting row bits at the common
point suffix. Instances of one role can then share its row point despite different
lane counts. A late independently weighted combination of all terminal N/D
marginals could authenticate them through one Eq/prefix per role. This requires:

- An explicit index/point authority shared by producer, native receiver and circuit.
- Exact per-instance terminal marginals from GKR, followed by independent late
  batching challenges. A host-declared unproved claim vector is insufficient.
- No mixing of relation closure semantics: retain separate RAM/KIO/Wire aggregate
  claims and either per-proof REG/OWNER claims or independently reviewed scoped
  batching with exact namespace separation and stated failure bound.
- Packed kernels and streamed metadata reads that respect the new layout without
  rebuilding full N/D planes; checked mixed-height resource and lifetime bounds.

Even eliminating every current global INTER column with zero additional binding
would remove only4.77% of this roster's MAIN+INTER cells. Substantial additional
headroom is in truth-local lookup columns, repeated Eq/binding representation,
opening/hash cost and actual numerical/PCS kernels. No global-only design should
be sold as the complete GKR payoff.

## Qualification gates before any switch

1. Shared tuple catalog and scalar/packed/circuit agreement, including all padded
   rows, signed/Boolean weights and exact producer/receiver degree declarations.
2. Real LS/INIT/TEARDOWN and Keccak/secp bridge/truth children, terminal claims and
   physical MAIN binding under independent fresh receivers; global closure only
   at the complete receiver.
3. Reject changed MAIN/FIXED, ordinal, epoch, scoped namespace, instance count,
   geometry, service ID, public endpoint, child byte, terminal marginal and D=0.
   Include balanced wrong RAM read/write and cross-shard/service witnesses that
   pass local fragments but fail intended complete ancestry/closure.
4. Bounded decode, preflight characteristic/support bounds, all-OOM cleanup,
   parked abort, later-worker failure, no borrowed-source escape, retained proof
   lifetime after cache/store handle release, and no silent dense fallback.
5. Same-field/profile/request/FIXED/MAIN matched A/B: cells and padded facts,
   per-stage wall/user/system, numerical requested peak, original backing capacity,
   RSS/footprint, proof/child bytes, fresh receiver cost and recursion opening cost.
   Do not compare QM31 classic against OM31 GKR as a GKR-only speed claim.
6. Complete block with independent expected endpoints/output and all physical
   claims closed, plus recursion admission/statement binding for the new profile.
   Whole128 remains fail-closed until the separate FS/FRI/lookup/secp construction
   and recursive composition review is complete.
