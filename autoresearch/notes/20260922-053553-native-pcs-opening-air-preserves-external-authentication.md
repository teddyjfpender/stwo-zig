---
title: Native PCS opening AIR preserves external authentication
author: Teddy Pender
created_utc: 2026-09-22T05:35:53Z
---

# Native PCS base-query opening AIR

Implemented native_pcs_opening4_v1: a typed degree-two weighted accumulation with
29 main and 13 fixed columns, five constraints and ten relation events. Four
base-field queries live directly in the row; accumulator, weights and output stay
QM31. Each query emits its original recursion_wire tuple with multiplicity two,
retaining the hash-encoding and read-only authentication consumers.

Semantic identity:
`b09d44b29bdd1e3791e6bbcd2c7ce0e1ade52550e19f115249bcc6cc845dca93`.

The exact signed-multiset oracle compares the new row against the old generic
dot4 plus four scalar producers at multiplicity three. Old arithmetic consumes
one use, so the net external multiplicity is two. The check passes with zero,
one and field-edge query values and nontrivial extension weights. Mutating every
fixed coordinate breaks external equivalence. Every main coordinate is mutated
across twelve nonzero examples and fails arithmetic constraints; zero padding is
inert. Degree analysis confirms degree two, and noncanonical schedule fields reject.

Focused command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
```

Exit 0, 4/4 steps, 7/7 tests; run 522 ms / 2 MiB, compile 5 s / 542 MiB.
This includes the five existing detached PCS matcher/arithmetic/closure tests.
An initial identity-discovery run used a zero placeholder and failed as expected;
the derived identity is now explicitly pinned and checked.

The native component is not yet selected by row preparation or the prover roster.
Next: admit exact candidate/scalar metadata, replace matched rows, preserve the
complete graph-input inventory, bind new key/codec geometry and independently
verify full native proofs. The measured 134 groups imply a conditional 536-row
reduction, not implemented savings or a speed result. Production and Metal remain
unfinished. No security parameters or production defaults changed.
