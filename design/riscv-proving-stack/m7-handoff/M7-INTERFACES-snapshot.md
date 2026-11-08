# M7 interfaces (append-only; one section per stream; baseline codex/rv64-m6-integrate @ 26ca20793)

Rules: append your own section / dated updates only; never edit another stream's text. Live items carried forward from
M6-INTERFACES.md stay in force unless a section below supersedes them (see each stream's "carried" line).
M6 DEFAULT FORMAT = m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1 (scripts/rv64_m3_pod.py DEFAULT_PRODUCER_ENV); byte identity
for scheduling streams is against the M6 default receipts (vectors/reports/rv64-m6-20261105/integrate/).


## profiles (branch codex/rv64-m7-profiles, worktree ~/Coding/ge-wt/rv64-m7-profiles) — 2026-11-05 v1

Sole owner of `om31_security_candidate.zig` (PROFILES / CANDIDATE_PROFILES / FORMAT_VERSIONS + soundness arithmetic tests),
every soundness/binding note, and the negative corpus (`scripts/rv64_m5_negative_corpus.py`, spec/run/coverage).
Carried from M6-INTERFACES §profiles: P2 corpus v4 IDs, P3 review protocol, P4 LOCAL_RELATIONS decision, the hook rule
(zig test named `corpus <ID> ...`; `python3 scripts/rv64_m5_negative_corpus.py coverage --src <tree>` counts it).
Open M6 review items that are now M7 blockers: DW-R1 (REOPEN, outer GKR eq column), DW-R3 (fused Blake one-instance, BG08 over ALL
XOR consumers), NV-R2/NV-R3 (native v2 version-before-stage-one, per-relation source-bound mass), FV-R1 (FIXED root U test),
FV-R2 (fold v3 itself).

### PR1. Reserved NAMES for M7 proof-format streams (OFF BY DEFAULT until integrate promotes; registered in FORMAT_VERSIONS)
All are on the M6 default base (r1 PCS 1/108/20/fold4 + kary-v1(k=4) + merkle-cap-v1(c=3, fold circuits only)) unless noted.
| name | owner | base PCS | domain / components (hashed, length-prefixed, in this order) |
|---|---|---|---|
| m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1 | outer-gkr | 1,108,20,4 | `stwo/circuit/native-om31/m7-outer-gkr-k4-cap3-q108-p20-fold4/lens-v1`; `stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v2` (v2 = DW-R1 fix: eq endpoints + carry + cyclic prefix), kary-v1(k=4), merkle-cap-v1(c=3, ...) |
| m7_outer_gkr_fblake_k4_cap3_r1_b2_q108_p20_fold4_v1 | outer-gkr | 1,108,20,4 | `.../m7-outer-gkr-fblake-k4-cap3-q108-p20-fold4/lens-v1`; GKR v2 + `fused_blake2s_v1/one-instance` + kary k4 + cap3 |
| m7_native_v2_gkr_b2_q108_p20_fold4 | native-gkr | 1,108,20,4 | `rv64-m7-native-chi-chain/v2+native-gkr/v2/conjectured128_b2_q108_p20_fold4\0`; `rv64-m6-native-chi-chain/v2`, `v2-gkr`, `stwo/rv64/native-gkr/om31-strict-draw/lane-major/v2`, rung roster id (post it) |
| m7_outer_fold_v3_k4_cap3_r1_b2_q108_p20_fold4_v1 | fold-circuit | 1,108,20,4 | `.../m7-fold-v3-k4-cap3-q108-p20-fold4/lens-v1`; `rv64-m7-fold-v3/v1` (in-circuit T_rec, NS chain, PCD self-VK), kary k4, cap3 |
| m7_compress_c1_b16_q27_p20_fold4_v1 | compress | 4,27,20,4 | `stwo/circuit/native-om31/m7-c1-b16-q27-p20-fold4/lens-v1`; `rv64-m7-compress/c1/v1` (verifies exactly one root, NS passthrough) |
| m7_compress_c1_b8_q36_p20_fold4_v1 | compress | 3,36,20,4 | `.../m7-c1-b8-q36-p20-fold4/lens-v1`; `rv64-m7-compress/c1/v1` |
| m7_compress_c2_b64_q18_p20_fold3_v1 | compress | 6,18,20,3 (last layer 2^3) | `.../m7-c2-b64-q18-p20-fold3/lens-v1`; `rv64-m7-compress/c2/v1` (verifies exactly one C1 under a constant C1 VK) |
| m7_compress_c2_b16_q27_p20_fold3_v1 | compress | 4,27,20,3 (last layer 2^3) | `.../m7-c2-b16-q27-p20-fold3/lens-v1`; `rv64-m7-compress/c2/v1` |
| m7_outer_gkr_fold_v3_k4_cap3_r1_b2_q108_p20_fold4_v1 | integrate (compose) | 1,108,20,4 | GKR v2 + fold v3 + kary k4 + cap3 (+ fblake if shipped: post) |
If your real domain/component string differs, post it in your section; profiles updates the registry (you do not edit it).
Every entry: conj. bits = log_b*q + pow = 128 exactly; Johnson x2 >= 148; domains/identities pairwise distinct and distinct from
every admitted/candidate/M6 identity; tests in om31_security_candidate_test.zig. Outer-GKR entries additionally pass
requireOuterGkrBits(real class facts, 151) and requireOuterGkrCharacteristic(real per-relation mass) (M10); fused-Blake entries
requireBlakeTableMass over ALL consumers of each XOR table (BG08); compress entries: the C1 VK is NOT a T_rec member (CP05).

### PR2. Corpus v5 case IDs (M7; tier R = fresh receiver process, U = unit test, W = witness/constraint mutation)
Carried and re-owned: DW01/DW02/DW07/DW10/DW11 -> owner outer-gkr (they gate the GKR v2 names); NV06 -> native-gkr; F301-F308,
RO10 -> fold-circuit; CP01-CP04 -> compress.
- outer-gkr: OG01 succinct in-circuit eq aux (first/second/carry at the OODS point) differs from public_aux.zig at a random point (U,
  differential); OG02 strict draw admits a row coordinate z_i = 1 (U); OG03 GKR section of another node of the same class spliced in
  (R); OG04 instance (relation, component) tag relabel, claims kept (W); OG05 per-relation mass >= p admitted (U, characteristic);
  OG06 GKR-v2 proof under the M6 default (no-GKR) receiver and the reverse (R, --alt-format-run); OG07 GKR v1 (unfixed binding)
  proof bytes under a v2 receiver (R or U: version word refuses).
- native-gkr: NG01 native GKR section byte flip on a production v2-gkr proof (R); NG02 mass gate fed the producer-claimed mass instead
  of the source-bound mass (U); NG03 segment whose rows != its rung (incl. cpu_single / terminal rung) (W); NG04 v2-gkr proof under
  v2-strict / M6-default receiver and reverse (R); NG05 rung roster id of another roster (U).
- fold-circuit: F309 fold v3 on k4-cap3: cap slot guessed (DW12 on v3) (W); F310 null slot counted in the segment chain (W);
  F311 v3 root accepted root-only WITHOUT --audit (accept control, R); F312 v3 root under the M6 table profile
  rv64-m4-fold-v2-compat/v0 and reverse (R).
- compress: CP05 fold admits a C1 proof as a child / C1 VK in T_rec (W); CP06 C1 output NS != child NS (any field incl. bus, mass,
  ctr, steps, E, depth) (W); CP07 C1 child is a non-root node with a consistent NS (W: interval must cover every segment); CP08 C2
  verified under C1 parameters (R, = M03); CP09 root proof (uncompressed) presented as the C2 artifact (R); CP10 C2 proof of the other
  dev block with this block's statement (R).
profiles runs the R tier against your pushed branch heads periodically and posts results here (receipts under
vectors/reports/rv64-m7-20261105/profiles/). Please post "PROOF PAIR READY <run dirs> @ <sha>" for each named format with both dev blocks.

### PR3. Review protocol (profiles is second reviewer of outer-gkr DW-R1 fix + wired GKR/fused Blake, native-gkr v2-gkr + rungs,
compress C1/C2, fold-circuit fold v3 in circuit)
Post "REVIEW READY <note path> @ <sha>" in your section. profiles answers here with SIGN-OFF / CONDITIONAL / REOPEN <ids>; a REOPEN
blocks integrate's promotion of that name. Findings text: design/riscv-proving-stack/rv64-m7-profiles-review.md.

## outer-gkr (branch codex/rv64-m7-outer-gkr, worktree ~/Coding/ge-wt/rv64-m7-outer-gkr, from 26ca20793) — 2026-11-05 v1
Owner (sole writer this milestone): recursion circuit construction om31_native/{execution_wrap,outer_wrap,proof}.zig,
rv64_recursion/om31_outer.zig, outer_gkr/*, fused_blake/* hooks, om31_native/fold_tape.zig records for any guess change (same commit).
NOT mine: om31_security_candidate.zig (profiles), corpus spec (profiles), ready_dag (sched), trace_commit/pcs_native/outer_source* (enqueue
owner of M6; I will post exact hook signatures here before touching them), CUDA kernels other than the outer GKR bench/prover.
Proof format: NEW named profiles only; the k4-cap3 default stays byte-identical until integrate promotes.

### OG1. Order of work (each step lands separately, tested, pushed)
1. DW-R1 closure (FIRST, blocking): outer binding v2 = the reviewed native construction (services/gkr_local/binding.zig emitFor) per
   GKR-bound component: E endpoints (E-eq0)*first+(E-eq1)*second, recurrence E - E_next2*carry, CYCLIC prefix
   Pre - Pre_prev - E*v + target_per_row (target = boundary / 2^r). first/second/carry are NOT committed: verifier-derived from the
   GKR row point z_row via the SUCCINCT O(log^2 N) evaluator logup_gkr/mle_point.zig evalAnchorsFor/evalCarryQuotientFor
   instantiated over OM31 (CPU receiver) and over the circuit lane F (in-circuit OODS). Guard: every z_row coordinate != 0,1
   (MleEvalPoint.init DegenerateEvalPoint -> the section is rejected; completeness loss <= r*2*2^-248).
   Differential tests: succinct(OM31) == interpolate(public_aux.zig columns) at random OM31 circle points; circuit(F) == CPU(OM31).
   Corpus hooks (profiles P2 names): `corpus DW10 forged E with Pre recomputed` (U/W: violates recurrence or endpoint),
   `corpus DW11 non-cyclic prefix edge` (Pre[0]=0 form rejected / cyclic form required). Note: design/riscv-proving-stack/rv64-m7-outer-gkr.md.
   -> profiles: please RE-REVIEW DW-R1 against that note (I will post "DW-R1 ready" here with the commit).
2. Outer AIR hook: per GKR-bound component (triple_xor, m_31_to_u_32, blake_g_gate, verify_bitwise_xor_12) the classic LogUp part is
   dropped and the 3 binding constraints + 16 interaction base columns (E, Pre as OM31) replace it; interaction 304 -> ~128 base cols [D].
   Transcript: MAIN commit -> GKR header+salt+section (strict draws) -> gamma, rho_g -> INTERACTION commit (classic + E/Pre) -> ...
   closure: sum classic claims + sum_root n/d + public bus = 0. Wire: section after the interaction claims, class-constant length.
3. GPU: outer GKR prover with FUSED projection (MAIN columns -> fractions inside the first tree layer; no 258 M materialized
   fractions) so it fits next to the 22 GiB arena (unfused 26.9 GB [M5 M]). E/Pre generated on device.
4. Fused Blake2s ONE instance per node (blake-gadget AIR fused_blake2s_v1/one-instance), after 2/3 run end to end.
5. Retry m3_b4_q51_p26 for folds/root once interaction width drops (the 304-col interaction LDE was the OOM).

### OG2. Names (profiles: please register; component strings hashed in this order)
| name | base PCS | domain | components |
|---|---|---|---|
| m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1 | 1,108,20,4 | `stwo/circuit/native-om31/m7-outer-gkr-k4-cap3-q108-p20-fold4/lens-v1` | `kary-v1(k=4)`, `merkle-cap-v1(c=3, fold circuits only)`, `stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v2-cyclic-eq` |
| m7_outer_gkr_fb1_k4_cap3_r1_b2_q108_p20_fold4_v1 | 1,108,20,4 | `stwo/circuit/native-om31/m7-outer-gkr-fb1-k4-cap3-q108-p20-fold4/lens-v1` | above + `fused_blake2s_v1/one-instance` |
| m7_outer_gkr_fb1_k4_cap3_m3_b4_q51_p26_fold4_v1 | 2,51,26,4 | `stwo/circuit/native-om31/m7-outer-gkr-fb1-k4-cap3-m3-b4-q51-p26-fold4/lens-v1` | same (folds/root only if it fits) |
Outer GKR profile identity v2: `outer_gkr_om31_strict_v2` / `stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v2-cyclic-eq` (v1 = M5
reference, kept for its tests). Selector: STWO_RV64_OUTER_PROFILE=<name> on producer AND receiver (same rule as k4-cap3).

### OG3. Requests
- profiles: register OG2; corpus IDs DW10/DW11 (above), OG01 E column forged at one row (W), OG02 z_row coordinate in {0,1} (U),
  OG03 GKR section of another class (R, = G18 on v2), OG04 fused Blake instance count != 1 (W, = DW05).
- integrate/measure: the receipts for this stream go to vectors/reports/rv64-m7-20261105/outer-gkr/, ledger
  vectors/reports/progress/outer-gkr.jsonl (milestone "M7").
- fold-circuit / compress: if you change the in-circuit child verifier (om31_native/mod.zig verify order), tell me here first:
  the GKR section sits between MAIN and INTERACTION.
### outer-gkr v1a (2026-11-05): ADOPT profiles PR1/PR2 names, superseding OG2/OG3 where they differ
- Names: m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1 and m7_outer_gkr_fblake_k4_cap3_r1_b2_q108_p20_fold4_v1 exactly as PR1
  (component string `stwo/rv64/outer-gkr/om31-strict-draw/lane-major/v2`). My "fb1" names are withdrawn. q51 variant: I will ask
  profiles for a name only if it fits on GPU.
- Corpus: I own DW01/DW02/DW07/DW10/DW11 + OG01-OG07 as PR2 defines them (OG01 = succinct-vs-public_aux differential, OG02 = z_i in {0,1}).

## native-witness (branch codex/rv64-m7-native-witness, worktree ~/Coding/ge-wt/rv64-m7-native-witness, from 26ca20793) — 2026-11-05 v0
Owner (sole writer this milestone): `riscv_cuda/rv64/{cpu_replay,cpu_projection,core_witness,device_source,cpu_witness}.zig`, the
`backends/cuda/native/rv64/*_witness.cu` family (+ their .h), the streaming native commit path and native CUDA graphs of the
witness/commit path. Carried from M6-INTERFACES §native-stream: NS1 (native SCHEDULE harness hook, default 4x2 affinity 2 heaviest
first), NS2 (device-retained compact capture, replay seam `gkr_local/cpu_replay.zig` Stage{estimate, prepare -> Owner{park, restore,
release}} unchanged), NS3 (compact records + per-image decode table; this section freezes its layout as NW2 before any consumer).
NOT mine: `services/gkr_local/*` (native-gkr owns the native AIR boundary / coordinator this milestone; I coordinate there),
`pcs_native.{zig,cu}`, `trace_commit.zig`, `channel.cu`, `transcript.cu` (whoever owns them in M7: I will post exact hook
signatures here before touching them), capture's `word16_execution/cpu_source.zig` Scan (capture stream).
Proof format: UNCHANGED. Gate: every native + root proof byte identical to the M6 DEFAULT receipts (k4-cap3) on both dev blocks.

### NW1. What I attack (M6 measured, 24628607 warm): native 4.45 s vs kernel busy 1.58 s (GPU0) / 2.35 s (GPU1); one owner thread
per GPU runs every callback synchronously (callback -> owner->sync()) so host work inside callbacks and between submissions leaves
the GPU idle (1.1-2.0 s per GPU); H2D 213-223 B/instr (largest: CPU metadata 56 B/row ~1.57 GB, n2b/b2n staging, memory facts).
First step (in progress): fresh nsys of the M6 default (m6-integrate binaries) to attribute the native critical path per job.
### NW2. Compact CPU record (DRAFT, frozen in v1 before use): per executed row <= 16 B (rom_row u32, rd-result lo/hi u32 x2,
dynamic next-pc / branch bit folded), register-file values + last-access clocks rebuilt ON DEVICE by a per-segment scan seeded
with the 32 entry registers/clocks; widened by cpu_witness.cu into the 37 CPU MAIN columns exactly as today (byte-identical).
### NW3. Requests (will be concrete in v1): capture — emit the compact record alongside (later instead of) `Metadata` in
`cpu_source.zig` Scan (I can supply the writer as a pure function); native-gkr — tell me if v2-gkr changes which CPU MAIN columns
exist (the widening kernel follows the AIR layout `X.layout.mainCount`).
Reports: vectors/reports/rv64-m7-20261105/native-witness/, ledger vectors/reports/progress/native-witness.jsonl (milestone M7).
