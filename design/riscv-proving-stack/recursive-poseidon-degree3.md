# Compact universal Poseidon provider

The detached recursive parent admits `stwo.recursion.poseidon2-universal-degree3.v1` separately from the retained Stark-V universal provider. The permutation constants, input/output relations, two partial claims, quotient expansion and composition split remain the same. The physical AIR and its admission identity change; new parent proofs require new keys.

| At 185,430 calls, padded to 2^18 rows | Retained universal | Compact universal |
| --- | ---: | ---: |
| Main columns | 445 | 303 |
| Interaction columns | 8 | 8 |
| Preprocessed columns | 1 | 1 |
| Direct constraints | 430 | 288 |
| Interaction constraints | 2 | 2 |
| Maximum constraint degree | 3 | 3 |
| Quotient domain | 2^19 | 2^19 |
| Composition split | 1 | 1 |
| Main + interaction trace bytes | 453 MiB | 311 MiB |

The exact base-trace saving is 142 MiB. At blowup one, the corresponding expanded-column saving is 284 MiB. This is a physical-geometry calculation, not a measured total-process memory reduction or a runtime claim. Row padding and FRI parameters have not been reduced.

Each of the 142 S-boxes stores `s = x²` and `y = x*s²`. Both constraints have degree at most three. All rows, including padding, satisfy the complete permutation. Only lookup multiplicities use the enabler. Padding therefore contains the valid zero-input permutation with enabler zero, rather than an all-zero row.

The new admission digest binds the versioned AIR, round schedule, constants, and shared legacy matrix implementation sources. It does not claim to hash all backend code. The existing Ethereum narrow layout uses the same round-schedule implementation and prepared component. The new universal layout adds all 16 inputs and preserves narrow, wide and atomic-IO lookup modes. Witness generation and constraint replay use one round schedule. Native and symbolic composition call the same selected AIR. The legacy provider, its digest and its verifier remain available for retained child proofs.

Prepared composition evaluates direct constraints over M31 and only the lookup recurrence over QM31. Large domains use bounded, disjoint row ranges on the existing task pool; tasks join before publishing a fresh accumulator. The compact universal provider does not advertise the narrow-only Metal composition capability. Metal polynomial and commitment work remains available through the backend, while this provider's composition uses its admitted host evaluator.

## Gates

Run `python3 scripts/recursive_poseidon_degree3_proof.py` for the complete CPU gate. `air-fusion-poseidon-semantic-admission-final.log` under the small-detached-recursion report directory records 12 passing focused tests on the final admission identity. The earlier 11-test iteration took 14.45 seconds including compilation. The final tests cover:

- 192 randomized permutations spanning narrow, wide and atomic-IO modes, exact live lookup tuples and partial-claim denominators against the retained provider.
- Mutation of every input and S-box witness column in active and padding rows; invalid flags, conflicting modes, noncanonical input and all-zero padding rejection.
- Degree and padded-storage calculations, native/prover geometry and callback admission.
- 64 random off-domain rows across both layouts: the actual prepared base-field evaluator agrees with full QM31 evaluation under non-base relation challenges, claims and accumulation coefficients.
- Serialized complete CPU proofs with producer destruction and fresh verification for both compact universal and existing narrow providers; altered claim rejection.

The standalone Metal gate is `python3 scripts/recursive_poseidon_degree3_proof.py --metal --bundle PATH --manifest-sha256 SHA256`. `air-fusion-poseidon-metal-first.log` records a 22,932-byte proof identical to CPU at trace log 12, an actual GPU transform dispatch, producer destruction, fresh CPU verification and altered-claim rejection. It explicitly reports composition running on the host. That observation precedes the final source-identity expansion and private prepared-row extraction; final full-parent gates must cover those changes.

Full parent, parent-of-parent, CPU/Metal parity, changed-statement/key reuse and complete-request timing gates remain required before promoting this representation. A smaller local table does not establish an end-to-end improvement.
