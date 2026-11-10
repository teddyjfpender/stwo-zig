# Universal signed BN254 MAC source gate

This is a new, unadmitted provider-source experiment. It does not change any qualified BN254 bank, VM tag, profile, proof or receiver. The concrete numeric row has six products; the K=4/8/12 alternatives are cost models, not additional implemented AIRs. No physical MAC proof has been produced. The production target remains **128-bit security under documented assumptions**, not certified security.

The source equation is `Σ ci ai bi + acc − out − signedQ p = 0`, with six immutable coefficients of magnitude at most18,13 canonical input fields,33 quotient bytes,64 signed byte carries and a canonical output. Its width is722 MAIN/22 FIXED; planned BYTE and SSA terminal bindings add32 INTER. All input canonicality must be inherited through a complete unit-weight SSA argument with source-owned unique writer IDs/fanout. The numeric checker is not that argument. `source.fixed` rejects coefficients, IDs and fanout outside their bounds and nonzero inactive ROM fields; global SSA and multiplicity bounds remain a future physical obligation.

`bounds.zig` independently counts BYTE convolution terms at each of65 coefficients. `opstack/tools/mac6/bounds.py` repeats the interval calculation with Python integers. At byte position n, bound six signed products by `6*18*255²*numberOfPairs(n)`, quotient convolution by `255*Σ p[j]` over valid33-byte quotient indices, and `acc−out` by255, not510. Adding the permitted signed carries gives a maximum integer residual495,174,076 below M31's modulus. The valid witness recurrence requires carries of magnitude at most884,951, fitting the21-bit biased encoding. The signed quotient magnitude is at most `108p−215` (261bits); this follows by dividing the extrema `±108(p−1)² + acc` by p with canonical output. No16-bit multiplication convolution is used: WORD16 only proves the linear output/distance comparison. Its15 Boolean borrows and16 base65536 equations prove `out+distance+1=p`.

The source polynomial has degree at most3 with arbitrary FIXED coefficients. Tests exercise signed extrema, random canonical inputs, coherent output+p with recomputed quotient/carries, sign/magnitude/carry/distance/borrow mutations, inactive padding, both representations of quotient zero, carry-top BYTE overflow, and generic degree≤3. The trusted ROM constructor does not accept advice-selected programs. Source normalization preserves ordered expressions and uses fresh SSA temporaries; its allocation failure leaves caller ID custody unchanged. ZERO/ONE literals and all final zero/one assertions must remain independently source-owned.

## Coupled source cost

Counts come from every expression of the actual four-pair Miller ROM (`5f99ad975`) and joined pairing ROM (`712787aaf`), not synthetic dense operations. The joined ROM contains31,996 arithmetic writers,1,438 canonical private hints,54 initial fields and1,460 immutable zero/one assertions. Normalization seeds the accumulator from one positive unit linear term where possible, then chunks the remaining terms. No assertion is removed.

| K | Miller rows / padded | MAC cells | MAC opening columns | Joined rows / padded | Joined cells | Joined facts | Joined opening columns |
|---|---:|---:|---:|---:|---:|---:|---:|
|4|21,022 /32,768|21,037,056|642|44,738 /65,536|42,516,992|34,738,432|874|
|6|17,495 /32,768|25,427,968|776|36,751 /65,536|51,298,816|34,738,432|1,008|
|8|15,671 /16,384|14,909,440|910|34,335 /65,536|60,080,640|35,787,008|1,142|
|12|14,599 /16,384|19,300,352|1,178|32,543 /32,768|39,043,584|17,961,216|1,410|

Cells sum native FIXED+MAIN+INTER at each component's independent padded height, before LDE blowup. Miller columns/cells include only MAC; joined figures additionally include the existing95-column hint bank (log11), source frontier (log11) and BYTE table (log8). Opening columns count one of each committed column, not the extra mask/OODS samples or recursive gates. Separate BYTE512 and SSA16/32 instances supply the fact count. No unreviewed typed-union saving is assumed.

The width model is MAIN=`64K+338`, FIXED=`3K+4`, INTER32. K8/12 require22-bit carries rather than the concrete K6 row's21-bit bound;3 carry bytes and one shifted top-byte query still suffice. Independent interval maxima for K4/6/8/12 are valid-carry591,227/884,951/1,178,675/1,766,123 and residual at most420,265,277/495,174,077/839,566,909/989,384,509 respectively (the latter conservative symmetric estimate differs by one from the exact K6 interval). All remain below M31. These are candidate bounds, not qualification of new physical rows.

K8 wins the standalone Miller cell count, but loses on the actual composite. K12 crosses the composite log16→log15 cliff and halves its GKR facts relative to K6, at40% more opening columns. K4 is the narrowest opening but has about9% more native cells and93% more padded local facts than K12. This rules out choosing K6 merely because it is the first implemented numeric row. It does not establish which candidate minimizes recursive proving: full mask/opening graph counts and physical source evaluation remain necessary.

Reproduce the eight focused Safe numeric/source/model tests with:

```sh
zig test -O ReleaseSafe --dep stwo_core -Mroot=src/frontends/riscv/rv64_bn254_mac6_test_root.zig -O ReleaseSafe -Mstwo_core=src/core/mod.zig --test-filter MAC6
python3 opstack/tools/mac6/bounds.py
```

The next gate is one concrete selected row and complete immutable SSA lowering, including private hint writers and all endpoints, then physical degree/range/terminal binding and fresh independent receiver controls. Existing source fingerprints remain untouched. [Machine-readable receipt](../../vectors/reports/opstack-cpu-20261110/mac6-source-cost-v1.json).
