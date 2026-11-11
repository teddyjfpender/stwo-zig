# Conditional positive residue physical fixture

This isolated five-component proof binds the complete `bn254_residue` source program to committed arithmetic, private canonical hint and public frontier rows. It is a field-certificate fixture; no VM tag, guest default, production profile or recursive receiver admits it.

The source uses 64 general Fq12 squares, 42 dense multiplies and three Frobenius maps. The 36 Frobenius scalar equations occupy the square component's existing padding. Every free seed/scale/inverse field comes from the shared canonical hint writer. Scale has only six free Fq fields; its upper six Fq12 coordinates read the immutable ZERO source ID. Both the inverse check and final result have twelve explicit ONE obligations.

`native.zig` proves eight heterogeneous local instances. BYTE and SSA have distinct challenges and independent closure checks. `projection.zig` derives each actual row point from its global GKR terminal and binds the numerator/denominator to the same MAIN/FIXED expression emitted by the arithmetic component. The BYTE provider multiplicities are committed MAIN values. `trace.zig` lays out the five independently sized components in one PCS.

The positive fixture uses the retained real four-pair certificate. A fresh receiver reconstructs its expected public initial values and immutable source FIXED, then verifies the proof and rejects altered equality masks, binding samples, source challenges and source keys. This key is input-specific because the public initial bytes are in FIXED. A reusable production key and authenticated Miller/input joins remain open.

The off-subfield attack uses false z, seed=ONE and unrestricted c=z^-1. Arithmetic and both ONE endpoints hold. A test-only reader lies about the high c input values so the child GKR closes. The actual committed input bytes disagree with the source-bound terminal expression; the fresh physical receiver rejects the retained unverified proof. These test-only reader/projection helpers are compile-time forbidden outside test builds.

Run the bounded fixture with:

```
STWO_RESIDUE_OUT=<artifact-parent> zig build test-riscv64-op-dense-local-gkr \
  -Doptimize=ReleaseFast -Driscv-test-filter='BN254 residue physical'
```

The fixture uses a 2 GiB requested-memory budget and toy OM31 q12/P0 parameters. It does not claim a production security level or a measured speedup. Exact costs, artifact hashes and remaining gates are recorded in `vectors/reports/rv64-opstack-performance-20261109/guest/positive-residue-physical-v1.json`.
