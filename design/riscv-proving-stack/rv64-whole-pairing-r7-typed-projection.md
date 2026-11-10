# Whole-pairing typed recursive projection expression seam

2026-11-10. Closed prototype under `src/integrations/riscv_cpu/delegations/op_pairing_r7/typed_projection.zig`. This adds no source fingerprint, native transport, opcode, profile, constraint, key, live statement, production selector or admission. The qualified MAC12 `source`, `fixture`, `projection`, GKR and transport files are unchanged. No native/R7 proof or recursive source-cost census was run.

## API and authority

`ParamsFor(Lane)` contains the exact trusted native `N.Instance` descriptor, `weights: []const Lane`, `beta: Lane`, `ssa.offset: Lane`, `ssa.coefficients: [35]Lane`, `eta: Lane` and `target: Lane`. The helper accepts only one of the existing six exact family/role/row-log/lane-log descriptors and requires exactly its lane count in weights. Geometry and family must be receiver/source-owned; successful shape validation does not authenticate their provenance.

`evaluate(F, view, *ParamsFor(E.ConstFor(F)))` returns the original weighted numerator and denominator. `bindingResidual` returns exactly `Eq(row)*(N+eta*D)-target`, the pre-prefix binding expression. Eq and target normalization remain caller obligations; this helper does not manufacture Eq, reconstruct a child proof, select a transcript or validate claims. In particular, target must retain the existing per-row normalization already applied by the source's original Data constructor.

For packed base evaluation the parameters are shared OM31 challenge values and the results are packed OM31 secure values. For an external circuit lane the parameters themselves are that lane's dynamic values. There is no native OM31/QM31 challenge member or conversion inside the helper that would bake a numerical beta/SSA/weight into a recursive key. Only trusted integer literals (kind, unit, layout offsets) enter as constants.

The tuple order and signs match the current source exactly:

- BYTE arithmetic: main active / `(beta-byteQuery)` for all 353 real lanes; remaining 159 lanes are **N=0,D=1**.
- BYTE hints: fixed active / `(beta-mainByte)` for all64 lanes.
- BYTE table: negative multiplicity / `(beta-fixedByte)`.
- SSA arithmetic: 25 negative unit-weight input consumers and one fanout-weighted result writer; six remaining lanes are N=0,D=1. Tuple `[kind,1,id,32 value bytes]` keeps every input port, including source-fixed zero-coefficient ports.
- SSA hints: one fixed-active × fixed-fanout canonical writer.
- SSA frontier: one main-active × fixed-weight writer/consumer.

Inactive real lanes do not become dummy denominators: they keep the original D expression while N follows the original zero mask. Keeping dummy D=1 is also essential when random lane weights are not normalized. BYTE and SSA remain distinct child families; this expression seam does not permit their total debts to cancel.

Hint95 is private to the frontend fixture and has no public import alias. The new file mirrors only projection offsets (MAIN95/FIXED3, active0, writer1, fanout2, value bytes0..31), guards its widths at compile time, and pins the entire expression through original-emitter conformance. It copies no canonical/integer equations. Those continue to use the unchanged `G.fixture.emit`.

## Qualification

Run from the repository root:

```
scripts/rv64_pairing_r7_projection_test.sh --test-filter 'MAC12 typed R7'
```

All five ReleaseSafe tests pass (focused root plus four substantive cases):

1. All six original instances with arbitrary full8-coordinate OM31 MAIN, FIXED, beta, SSA offset/35coefficients, every lane weight, eta, target and Eq. Three mask cases include arbitrary masks, zero active masks and unit active masks. Every individual lane agrees with unchanged `C.byteFraction`/`C.ssaFraction`, and weighted N/D agrees with unchanged `P.evaluate`. This explicitly checks inactive lanes and all arithmetic padding lanes.
2. An external degree8 arithmetic wrapper satisfies the existing external-lane method contract. Its dynamic parameters carry dependency labels through operations; changing beta, SSA offset, all SSA coefficients, eta, one lane weight and target continues to match the original native expression. Every result retains exactly the relevant family challenge, weights, eta, target, view and Eq dependencies. This is a numeric contract/dependency test, **not an actual circuit witness or proof**.
3. Unknown geometry, shortened weight vectors and out-of-range lanes reject.
4. All six instances also match the original packed-base16 projection. Each secure output lane and Eq/eta/target residual is separately compared with a scalar native evaluation.

The native constructor's MLE-point field is not used by `P.evaluate`; the test supplies a valid nondegenerate one-coordinate point solely to initialize that unused field. These tests do not assert that arbitrary random lane weights come from a verified child point. That is intentionally a future circuit gate.

## Remaining circuit gate

A real whole-pairing Statement must obtain beta/SSA/eta, common point, lane weights, marginals and receipt from the **in-circuit verified** six-instance child, then feed those wires into this helper. It must preserve all shared transcript, source masks, global lifted-domain semantics, target normalization, independent BYTE/SSA closure, physical PCS OODS and source identity checks. The existing source-owned four-role integer constraints are reused unchanged; the separate same65-residual Horner helper can later optimize their evaluation without changing their meaning.

This closes the native-Q-only expression API obstacle identified in `rv64-whole-pairing-op-p2-r7-integration.md`; it does not close the complete Statement, immutable-input-key split, global Wire/RAM bridge, VM semantics or execution-root admission. No actual R7 cell/time saving is claimed.
