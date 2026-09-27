# Actual BLAKE3 PCS captures to typed paths — 2026-09-22

The focused gate generates and successfully verifies native BLAKE3 PCS proofs,
then consumes verifier-owned trace/FRI captures. Mixed-size columns cover logs
[3,2] for fold schedules 1/2 and [5,3] for schedule 4. Seventeen raw queries
ensure duplicates in the first two cases. Every captured trace and FRI opening
reconstructs its complete native root through typed path witness preparation.
One actual packed FRI opening also verifies in a complete five-component typed
CPU outer proof, with independently built preprocessing and altered-leaf
preprocessing rejection. Native final transcript digests and counters agree.

The first integration attempt failed with InvalidBlake3MerklePath because FRI
capture positions are raw evaluation positions and capture paths start ABOVE
the folding subtree. The new adapter recovers the first original leaf, computes
its intra-subtree siblings, and appends the captured upper path. Native packing
is one QM31 per leaf for fold1 and four for larger folds. The capture API comments
now state these semantics. This corrects the adapter; native proof semantics
and production hashing have not changed.

Validation includes invalid query index, value count, fold width and position;
allocation-failure injection checks every allocation in the adapter. Fold4
covers a multi-leaf packed subtree, and subsequent fold1 tails are exercised.

Command:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-pcs-capture -Doptimize=ReleaseSafe --summary all
```

Final result: all four build steps succeeded, one guarded test passed, runtime
approximately 3 seconds and max RSS 352 MiB; compilation 21 seconds on M5 Max.
Formatting and diff checks pass. This is a correctness/integration gate, not a
benchmark or production security profile. Inner PCS PoW is 4 bits; outer proof
uses existing development parameters (8 queries, blowup1, PoW0).

Limits: the complete typed proof authenticates ONE recovered leaf path, not the
whole PCS verifier. Other folding-group values produce sibling witness digests
on the host and are not yet constrained to recursive arithmetic wires. The PCS
fixture supplies zero outer composition/OODS metadata because it has no outer
STARK transcript; these fields are not used as authenticated challenge evidence.
No full DEEP/FRI composition, production key transition, Metal BLAKE3 backend or
parent-of-parent qualification is claimed. Production stays on Poseidon. No
end-to-end BLAKE3 speedup is claimed; the original performance goal is unfinished.
