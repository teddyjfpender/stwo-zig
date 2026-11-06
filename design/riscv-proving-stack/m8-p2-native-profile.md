# M8 P2/P4 preparation and remaining authority

Status: engineering preparation only, based on frozen source
`b68e02081b9e23de646346715c548eae38a63d6d`. Default D2, truth coalescing,
automatic arena and one lane remain selected. No S2 profile is registered by
this change, and no runtime call selects the new Keccak policy.

## P2 numerical kernel pass

**Superseded (2026-11-06, M8 poseidon-witness).** The register-packed variant
measured 15.140 ms on the 479x2^20 retained tree against 15.882 ms for the
common-rotate control [M] and was deleted. The kernel is now
`poseidon2_m31_fused.cuh` (pipe-balanced, 12.19 ms [M], byte-identical
roots); see `rv64-m8-recursion-backbone.md` and
`vectors/reports/rv64-m8-20261106/poseidon-witness/`. The text below is the
original hypothesis record.

Hypothesis, recorded before source changes:
`vectors/reports/rv64-m8-20261106/p2/hypothesis.json`.
`poseidon2_m31_register.cuh` packs each rate block with constant state indices,
uses the existing common M31 arithmetic and exact 31-bit diagonal rotation,
and unrolls width operations while keeping round loops rolled. This may let
the compiler retain the state in registers. Register count, spills and GPU
time are **UNMEASURED**.

Only the numerical benchmark and smoke gate select it, explicitly with
`-DSTWO_P2_REGISTER_PACKED`. With no define they select the original substrate.
The existing generated fast-reduction control remains selectable with
`-DSTWO_P2_FAST_REDUCTION`; defining both is rejected. Existing source and
generation scripts are unchanged. The benchmark reports `p2_variant`, and its
small tree tail uses the same selected parent implementation as its layers.

Pinned parameters are unchanged: width **24 [source]**, full rounds
**8 [source]**, partial rounds **22 [source]**, exponent **5 [source]**, rate
**12 [source]**, capacity **12 [source]**, digest **9 M31 limbs [source]**.
Parent compression still absorbs **18 limbs [source]** with the mandatory
marker and therefore takes **2 permutations [derived]**. No truncated
permutation compression or reduced round count is introduced.

The unchanged transcript smoke entry point is the old v1 u64-counter numerical
reference. It is explicitly imported from that reference; it is not a v2
device transcript implementation. New commitment code is not linked into the
production PCS. The CPU formula check covers arithmetic, independent dense
permutation equivalence and packed absorption boundaries. Its receipt is
`vectors/reports/rv64-m8-20261106/p2/static-check.json`. It does not compile or
execute CUDA.

Owner-run next checks, after P1 and P3 qualification: compile both numerical
controls and the new selector against one frozen source; inspect register and
spill reports; run permutation/leaf/parent KATs and canonical-limb rejection;
compare every retained small-tree node with the independent CPU model and
large roots with the retained common-rotate reference; run Compute Sanitizer;
measure matched retained-tree GPU seconds. Keep raw logs on the pod by SHA,
and retain only compact summary receipts here. A kernel win cannot establish
native-block or Ethereum request savings.

## S2 native interface proposal; not implemented

Reserved suite name:
`rv64-om31-p2m31-native-localgkr-128-CANDIDATE/v1`.
The current `services/poseidon2_native` fixture is a named mixed suite:
Poseidon v2 physical PCS/FS with raw-Blake local GKR/manifest and P0. Its
accepted fixture cannot qualify this all-Poseidon S2 name or a conjectured128
production profile.

Required boundary changes, to be assigned by the integration owner:

- A separate device ABI family with canonical **36-byte roots [source]**;
  commitments, decommitments, FRI roots, prefix banks, FS and PoW must never
  reinterpret the existing **32-byte Blake type [source]**. Preserve existing
  backend calls and numerical inference behavior. Exact profile and suite
  types must be receiver-selected before reading proof data.
- A named v2 device channel, matching CPU `Om31ChannelV2` initial framing,
  checked u32 draw counter and one indexed draw per felt. Refuse exhaustion
  instead of wrapping. State, full roots and sampler identity must agree;
  there is no implicit reuse of the numerical v1 callback.
- Full canonical nine-limb roots throughout FIXED/VK, local-GKR transcript,
  manifest, shared/scope/frame authority and global closure. Any remaining
  Blake wrapper needs a separately named mixed suite. Parameter equality is
  insufficient authority to substitute either suite.
- A receiver-owned native profile carrying source/AIR/GKR roster, field
  degree, sampler, retry limits and all PCS parameters before roots. Preserve
  P20 and at least the current conjectured128 FRI arithmetic; no weaker
  parameters, SNARK wrapper or hash-security claim is introduced here.

Soundness work remains open. Ideal birthday work of approximately
**139.5 bits [derived]** for nine canonical M31 limbs is not a whole-protocol
certificate. Charge all Merkle/FS/PoW/VK/manifest/frame work in the new suite:
collision union `Q(Q-1)/(2*p^9)`, preimage terms `Q/p^9`, sampler bias and
adaptive transcript unions. For query log `k<=30 [source limit]`, canonical
M31 low-bit draws have maximum residue mass `2^(31-k)/p`; do not reuse the
raw-u32 reduction accountant. The permutation and algebraic random-oracle
assumptions, algebraic PCS/GKR reductions and retry caps remain explicit.
The target remains conjectured128, hash based and post-quantum.

Fresh cache-disabled CPU receivers on both development blocks and source-owned
tamper cases are mandatory before S2 qualification: foreign suite/version,
v1/v2 substitution, noncanonical limbs at every root/path/frame ingress,
truncated or reordered limbs, FIXED/VK/manifest substitution, wrong sampler,
changed query/PoW/fold parameters, counter exhaustion and missing global
closure. Then measure complete block GPU seconds in the composed stack.
No authority is delegated to proof-supplied numeric parameters.

## P4 pure Keccak policy and CPU23 boundary

Hypothesis, recorded before source changes:
`vectors/reports/rv64-m8-20261106/p4/hypothesis.json`.
The restored pure module is
`services/gkr_local/keccak_family_profile.zig`; it preserves deferred profile
`m7_keccak_early_late_b16_q27_p20_fold4_v1` and its original identity domain.
It leaves legacy framing as a no-op, pins compact triple-v2 source geometry,
and returns b16/q27/P20/fold4 only after explicit receiver policy selection.
The arithmetic **4*27+20=128 [derived, conjectured FRI term only]** is unchanged.
This is not a security certificate or registered production format.

`requireTruthsForTotal` requires an independently source-owned expected total.
It checks contiguous first IDs, nonzero spans, exact ceil/floor partition,
minimal logs within the original source cap and exact AIR policy. It charges
the paired-slot mass across both physical proofs together. A mere
`requireTruths` call checks canonical shape only; global closure must still
authenticate the total. Adjacent tests cover holes, overlaps, reorder,
missing suffix, zero/extra spans, overflow, padded geometry, foreign policy,
parameter changes, aggregate source mass and legacy transcript preservation.
These tests are written and syntax-formatted, **NOT executed** in this pass.

Production integration remains open: planning must publish these physical
declarations; coordinator/worker/fixed authority must select the same policy
before roots; the receiver and recursive wrapper must rebuild it exactly;
FIXED descriptors must explicitly admit this blowup. Do not infer policy
from supplied proof bytes. Source mass, bounds and the existing global
closure cannot be weakened. Owner-run fresh CPU/tamper checks on both dev
blocks precede GPU qualification and matched timing. Current coalescing means
the resulting leaf count and any gain are **UNKNOWN** until actual plans are
compared. Historical leaf-count projections are not measurements here.

CPU23 remains **OPEN**. Current local-GKR source authority rejects CPU logs
above **22 [source]**; tests explicitly reject the classic-valid log23 fused
wide-clock geometry. Existing clock/range authority and canonical rung tables
are untouched. A future source-bound clock/range/GKR review and new named
strict roster are required; raising a cap or fabricating padded rungs is not
an admissible implementation.

Qualification remains ordered P1 → P3 → P2 → P4 → P5. Only blocks 26235156
and 24628607 are development inputs. All builds, GPU locks, complete-run
receivers, matched timing, source freezes and commits belong to the owner.
