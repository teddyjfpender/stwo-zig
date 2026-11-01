# Handover: prover-curves track (codex/rv64-guest-prover-curves)

Paused at the user's instruction on 2026-11-01. The branch is a fast-forward
of `codex/rv64-guest-prover-v3-integration` (ae1ff00fa: SHA-256, arith256_mod
and bulk memory already merged), plus a forced WIP checkpoint (f4e0d7a62) and
this commit.

## Design decisions (fixed)

- Seven admitted v3 ops, one services family each, appended after arith256_mod:
  families / Wire35 kinds / bridge kinds 5..11 = `bn254_g1_add`,
  `bn254_g1_double`, `bn254_fp2_mul`, `bls12_381_fp2_mul`, `arith384_mont`,
  `bls12_381_g1_add`, `bls12_381_g1_double`. Tags are the candidate tags
  (0x30100/01/02, 0x30112, 0x30121, 0x30110/11).
- ABI change from the candidates: packets are INLINE and 32-byte aligned (the
  candidates used 8-byte aligned pointer packets). The Word16 bridge binds
  contiguous 32-byte coordinates; pointer indirection would need a new bridge.
  Outputs overwrite the leading operands in place. Layouts are documented in
  `src/frontends/riscv/rv64/ethereum_services/curves.zig` and
  `air/delegations/curves/spec.zig` (`def`). Guest glue must copy operands into
  an aligned packet (cost not yet measured). This must go into the design doc.
- One generic truth AIR (`air/delegations/curves/`), comptime-specialised per
  op: one call per row, degree 3, own PCS, local BYTE table, exact integer
  relations `sum coef*a*b + sum coef*(v<<8s) + K*p - q*M = 0` over byte limbs
  with signed carries; carry width / grouping (1 or 2 coefficients) is chosen
  and CERTIFIED at comptime (`spec.deriveRelation`: max|G_j| + 2^(bits-1)(R+1)
  < 2^31-1). Canonical checks `x + D + 1 = M` (16-bit chunks, Boolean carries,
  no final carry) on every output and on curve inputs; one-hot chunk + inverse
  nonzero proof for x1 != x2 (add) and y != 0 (double); arith384_mont proves
  m odd (m_0 = 2 HALF + 1, HALF < 128 via two BYTE queries) and r < m.
  BLS G1 ops use the Montgomery slope mu = lambda R (linear sides shifted 48).

## Done and verified

- Truth AIR (`src/frontends/riscv/rv64/air/delegations/curves/*`), test step
  `zig build test-riscv64-curves-truth -Doptimize=ReleaseSafe` (Debug is too
  slow: >10 min). Last run (ReleaseSafe): compiled, and every test passed
  except ONE: "adversarial: arith384_mont even modulus, r >= m and
  non-canonical quotient limbs" — the non-canonical-q sub-case expects MAIN to
  accept `q_i + 256, q_{i+1} - 1` but constraint 36 (a relation group) fails.
  Likely a test bug: with group = 2 the borrow across a group boundary changes
  the carried value only if i is the odd limb of a pair; or the q limb index
  crosses into the top limb. Investigate before trusting; it is a rejection,
  not an acceptance, so not a soundness hole. Passing tests include: the
  geometry certificates, the big-integer oracle (std.math.big, Fermat
  inverses) for all 7 ops, group law ([r-1]G = -G for BN254 and BLS12-381
  Montgomery, points on curve), candidate-executor agreement, wrong/
  non-canonical outputs and wrong slopes rejected, equal-x / y = 0 / non-
  canonical inputs rejected, every single-cell perturbation rejected, activity
  prefix, interaction claim = native Wire35 sum with all residuals zero,
  forged BYTE multiplicity rejected, packed == scalar and degree <= 3.
  The same run printed a failing candidate_curves keccak-sponge test line in
  the runner output; check whether that is pre-existing (it is not my code).
  A temporary "debug: first failure per op" test at the end of tests.zig
  should be deleted.
- Measured truth cells per call (MAIN + INTERACTION, exact layout):
  bn254 add 2036, double 1884, fp2 1126; bls fp2 2088; arith384_mont 1256;
  bls add 3460, double 3502. Bridge adds 378 cells per 32-byte coordinate
  (4, 2, 4, 6, 5, 6, 3 coordinates respectively).

## Written but NOT compiled/tested

- Execution: `ethereum_services/curves.zig` (execute + test vs candidate
  pointer-packet executor), `session.zig` (`CurveCall`, `Event.curve`,
  dispatch, `CurveServiceDomain`), `execution_profile.zig` (`CURVE_TAGS`,
  `isCurveTag`, admitsV3), `compact_tape.zig` (`curve_calls`, `appendCurve`),
  `compact_tape_wire.zig` (curve count in the former reserved extension word,
  424-byte records after arith256 records; arith-only tapes unchanged),
  `boundary_capture.zig`, `ethereum_execution.zig` (`curve_calls: [7]u64`
  report field; census counts curves as plain ECALL).
- Bridge: `secp256k1/word16_bridge/types.zig` kinds 5..11 (equations unchanged).
- Services lane: `services/types.zig` (families, `Logs` fields, V3 list,
  helpers), `curves/roster.zig` (TruthSetup, TruthSource/Component unions),
  `services/{roster,collector,protocol,air_components,worker,pipeline,wire}.zig`,
  `gkr_local/{dispatch,global_cpu,native_provider}.zig`,
  `word16_execution/prepared.zig` (capture admits curve tags).
- Fixture + tests: `services/curves_fixture.zig`, `services/curves_test.zig`,
  step `test-riscv64-word16-curves-services` (registered in build_support).
- Ethereum driver: only `ethereum/plan.zig` (bridge logs, log16 truth spans).

## Next steps

1. Fix the arith384_mont q-limb test; delete the debug test; rerun
   `zig build test-riscv64-curves-truth -Doptimize=ReleaseSafe`.
2. `zig build test-riscv64-execution` (tape-wire round trip with curve
   records; add a test like the arith256 ones in tests/tape_wire_test.zig and
   session tests in tests/ethereum_services_test.zig).
3. Compile and run `zig build test-riscv64-word16-curves-services
   -Doptimize=ReleaseSafe`; fix compile errors (expect some in wire.zig JSON,
   roster `takeCurve`, collector indexing).
4. Re-run the existing suites (ReleaseSafe): word16-combined-services,
   word16-arith256-services, word16-v3-services, word16-bulk-services,
   sha256-truth, arith256-truth, word16-secp-bridge.
5. Byte identity: build `rv64-word16-combined-services-fixture` at ae1ff00fa
   and at head; compare `produce` (v2), `produce-v3 sha256`, `produce-v3 all`
   bundles (bundle.json, cells.bin, cpu-*.bin, truth-*.bin) and cross-verify.
6. Driver: `ethereum/keys.zig` (curve TruthSetup owners keyed by (op, log)),
   `main.zig` admitProfile (reject curve bridges/truths unless v3),
   `role_cost.zig`, `telemetry.zig`; native jobs: `rv64_ethereum_batch.zig`,
   `rv64_ethereum_native_prepare.zig`, `rv64_work_packet_admission.zig`,
   `rv64_work_packet_budget.zig`, `word16_execution/packet.zig` (curve counts,
   v3 extension curve count).
7. Docs: design/riscv-proving-stack/rv64-curve-services.md and a
   soundness_review.md section (exactness certificate, canonical checks,
   nonzero proof, Montgomery forms, inline-packet ABI change).
8. Recursion support is not started (same gap as SHA-256/arith256).

## Risks

- Inline packets change the guest glue (copies); the measured candidate gains
  assumed pointer packets.
- `native.blsRInv` is a comptime constant; trace generation calls `fill`
  three times per row (counts, MAIN, interaction) — fine for correctness, slow.
- Truth width: BLS G1 rows are ~3.5k cells; MAX_LOG 16 per span.
