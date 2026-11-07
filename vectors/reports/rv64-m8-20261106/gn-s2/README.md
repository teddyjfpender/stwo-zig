# gn-s2: native Stage-2 device oods_constraint + seal (flat digest, truthRoot)

Branch `codex/rv64-m8-gn-s2` (from `origin/codex/rv64-m8-gpu` @ b289b021f). Labels [M] measured, [D] derived, [E] estimate.

## What landed
- `rv64/jobs/native_encode_oods.zig` + `NAT/rv64/jobs/native_encode_oods.cu`: **Check.oods_constraint on device**. A per-class
  program (built once at warm by `build` / `fromPlan`) holds every composition role's `secure_polynomial_program_v2` DAG (the
  DAG the AOT composition kernels are generated from, `joined_codegen.record`), mask reads resolved to PCS-image sample indices,
  coset constants and composition-table offsets of each role's parameters and hc rows. The kernel evaluates it at the device
  OODS point (with the local-binding auxiliaries is_first / is_second / carry quotient evaluated succinctly, `mle_point`),
  folds roles in Horner order and compares with the composition samples' reconstruction. It writes the Verdict word
  (+ optional [evaluated | extracted]). Host mirror `hostCheck` = the kernel on host memory.
- `native_device_stage2.zig`: Stage2Job runs the check after the PCS (reads `pcs_out` samples, the PATCHED composition
  `table_device`, device alpha, device OODS field) when the class carries `ClassFraming.oods` and `Symbols.oods` is loaded;
  otherwise the word stays unset (fails closed, as before).
- **Seal consumes Exchange.truthRoot**: `RosterEntry.truth` / `.truth_device`; the seal awaits every truth root slot and reads
  it like a segment root (chi kernel custody now admits slots laid out after the seal slot).
- **Flat manifest digest on device** (`stwo_rv64_native_seal_flat_v1_on`, `FlatScript`, `Factory.Request.flat`). FINDING: the
  gate / D2 golden runs `STWO_RV64_NATIVE_VERSION=v1-flat`, whose manifest digest is the flat Blake2s of
  `manifest.emitCanonical` (incl. each CPU entry's local receipt digest + marginals), NOT the m6_v2_gkr chi chain the n-stage2
  seal computes; the chain seal cannot be byte-identical to D2. The flat seal is a per-request digest script (constant byte runs
  + exchange reads + flag tests).
- `gpu_native.zig` (additive, defaulted): `Exchange.receipts` + `Exchange.receipt(segment)` slot (receipt digest per segment).
- Harness `rv64_m8_gn_s2_parity_main.zig` (`build-rv64-m8-gn-s2-parity`).

## Real-block parity [M] (`parity-1.json` 26235156, `parity-2.json` 24628607)
Legacy pipeline on GPU0 with pass-through recorders (composition alpha/roles/items, the real enqueue-only PCS image run by
`PcsJob` on GPU1 from the legacy request, the legacy proof, the pending manifest). Post hoc ONE job per segment on GPU1 runs
**seal (flat) -> shared draws -> oods_constraint -> ProofEncoder -> root_match back to back** from recorded inputs only.

| | 26235156 | 24628607 |
|---|---|---|
| segments, all checks accepted (oods, pcs_status, encode_bounds, global_seal, root_match) | 4/4 | 7/7 |
| device [evaluated, extracted] == host engine evalCompositionPolynomialAtPoint / extract | 4/4 | 7/7 |
| device seal digest == pending manifest digest (v1-flat); shared draws == pending.shared | 4/4 | 7/7 |
| **encoder bytes == pipeline cpu-k.bin (byte identical)** | 4/4 | 7/7 |
| negatives fired (exactly the named word rejects, others accept) | 44/44 | 77/77 |

Negatives per segment: sample, parameter, hc row, alpha, composition sample -> oods mismatch; point status -> point;
non-canonical sample -> noncanonical (+ encode_bounds); descriptor -> descriptor; PCS header -> pcs_status; truth root flag
not landed -> global_seal; corrupted receipt digest -> seal digest != manifest digest.

Timing (CUDA events, warm, GPU1) [M]:

| per segment | 26235156 | 24628607 |
|---|---|---|
| oods_constraint GPU | 7.9-9.0 ms | 3.8-9.6 ms |
| encoder GPU | 2.35-2.57 ms | 1.30-2.63 ms |
| flat seal + shared GPU (per request) | 0.99 ms | 1.57 ms |
| tail job enqueue (host) | 37-68 us | 40-73 us |
| host engine OODS check it replaces (hybrid H11 part) | 11.6-29.8 ms | 12.3-30.0 ms |
| class OODS + encode program build (warm, once per class) | 20.6-45.3 ms | 7.6-52.2 ms |
| flat digest script build (host, per request) | 74 us | 73 us |

(Tail-job `stage_ns` 1.7-3.4 ms is the harness uploading the recorded PCS image; on the job path the image is already in the arena.)

## Remaining host work / open
- Receipt digest producer: the flat seal reads `Exchange.receipt(s)`; Stage 1 must compute the local-GKR receipt digest on device
  and publish it (asked in M8-INTERFACES `m8-gn-s2`). Until then the D2 seal cannot run inside a request.
- `ClassFraming.oods` must be set by the class builder (gn-shape: `native_encode_oods.fromPlan`), and gn-bind must load
  `Symbols.oods` and build `Factory.Request.flat` (+ `Exchange.receipts = true`) from the inventory.
- Full Stage2Job (globals/INTER/composition/PCS + this tail) in a request has not run: needs gn-shape's framing + gn-bind wiring.
- OODS kernel is one thread per role (~1.2k nodes/role, ~40k nodes/segment): ~8 ms/segment [M]; a warp-per-role or
  register-reused schedule is the obvious next cut.
- Host per request: flat script ~74 us [M]; roster/flat-entry packing from the inventory (driver).

## Gate [M]
- `rv64_gate.sh --stream m8-gn-s2` default: **PASS** at fb8e20588 (build, unit zig/python, small-block proofs byte-identical to the
  frozen D2 golden, fresh CPU receivers, negative corpus): `/workspace/m3/runs/m8-gn-s2/gate-1/gate.json` sha256 96a45724a1ee26c5472d17c32827e7c308a23409b96fcc883a889d9e6cd5a965.

## Review (2026-11-07, review stream on e0129f186)
Checked against the code: byte identity / transcript order, fail-closed device checks, custody / memory / stream order, host
work on the critical path, measurement validity.
- **Byte identity:** FlatScript emits exactly manifest.zig `emitCanonical` (PROFILE, execution, u64 8, u64 n, per entry
  kind / relations / mass / ordinal / statement / fixed / MAIN, u64 local?, receipt digest, u64 instances, u64 values.len, felts
  as canonical LE u32 coordinates; Writer.integer = u64 LE). Assumption, documented here: every native local-GKR instance has
  exactly 2 terminal marginals (the claims slot holds 16 words per instance; the script emits `u64 2`). An instance with another
  arity would produce a different digest, so the seal would not match the receiver. That costs liveness only, not soundness, and
  it holds on all 11 recorded segments.
- **Fail closed:** the oods_constraint word stays `unset` when ClassFraming.oods or Symbols.oods is missing. The driver memsets
  the status words per request, so a stale accept can't survive. The kernel re-checks the header, spans and indices on the device,
  and a refusal takes the minimum detail through atomicMin, so the reported detail doesn't depend on thread order. Flat seal:
  every slot it reads (root, receipt, claims, truth root) gets a flag-tag test, and a non-canonical marginal refuses with detail 3.
- **Custody / stream order:** the chi- and flat-seal custody ranges ([0, slot) and [slot+16, end) read-only, the slot
  read-write) match what the kernels read. Root and flag offsets are bounded by `exchange_words` before custody. The OODS kernel
  reads `pcs_out` samples, the `oods` field and `alpha` after the PCS enqueue on the same stream. It reads the composition
  `table_device` after the composition kernel copied the claim slots in. That table is per-job staged memory
  (NComp.Plan.stage `s.alloc`), so the instance lease ending at enqueue does not race it.
- **Finding fixed (test coverage):** `fromPlan`, the production builder gn-shape calls at warm, had no test. The parity
  harness builds its descriptor with `build` over its own compact table, so it never checks the plan's `t_params` / `t_hc`
  offsets. Added the host test "native OODS fromPlan reads parameters / hc rows at the composition plan's table offsets":
  it builds a real NComp.Plan with two roles (one plain, one local-binding with hc rows), checks that the descriptor offsets
  equal t_params / t_hc / table.len, checks that the evaluation equals `build` over a compact table, checks that a patched
  plan-table parameter changes the evaluation, and checks the shape faults (program count, swapped programs).
- **Not exercised by the parity (stated, not fixed):** the claims layout (`fromItemsWith(..., false)` keeps the claims inside the
  parameters; production zeroes them and copies them from the device claims buffer). The full Stage2Job in a request.
- **Host / latency on the critical path (open, not changed):** the flat seal is one thread, byte-serial, and sits on the seal
  barrier: 0.98-1.58 ms per request [M]. A word-wise fast path when `fill % 4 == 0` is a cheap cut. The OODS check is one thread
  per role in one block: 3.8-9.6 ms per segment [M], serial before the encoder on the segment stream. It could run on a side
  stream next to the encoder, or warp per role. FlatScript.build costs ~74 us of host time per request [M] and could move to
  `beginRequest`.
- **Reuse (open):** gn-truth's `truth_oods.build` (M8-INTERFACES) is a second secure_polynomial_program_v2 point interpreter.
  The two should converge on one kernel.
- **Measurements:** device times are CUDA events on the job stream, 3 repeats. The reported ranges include the first repeat,
  which runs up to 1.4 ms slower on 24628607 seg 0. The host engine check (11.6-30.0 ms) is a single timed run per segment, n=1.
  Both are labelled [M] correctly.
