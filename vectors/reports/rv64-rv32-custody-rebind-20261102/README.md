# Reviewed RV32 AIR source-custody refresh

This slice repairs the failing PR309 source-binding and aggregate-coverage gates.
It changes packaged source identities, dependent digest literals, generated Lean
embeddings, and the corresponding certificate/manifest evidence. No AIR equation,
selector, lookup, event, gate, theorem proof body, axiom policy, or source-binding
check is weakened or changed.

The fresh inputs are artifact `13115423519` from GitHub Actions run
`41386780977`, checked-out merge `e22f3242c6e0503a0a40ba03cd205acb288b86df`.
An independent review confirms that all 65 files in the declared production source
closures match the isolated refresh source byte-for-byte. This reuses that actual
CI export; it does not substitute a handwritten AIR program.

All 46 unsigned opcode programs are exactly equal to their previously reviewed
semantic objects **after the existing reviewed DAG-node layout normalization**.
Twelve are already equal before normalization; 34 differ only in node numbering.
The normalizer validates the complete ordered unsigned object against its pinned
canonical digest; it does not erase constraints, lookups or selector semantics.
Independent mutations of the modulus, column role, constraint root, lookup
numerator, next-PC projection, table hash and arithmetic constant are rejected.

The packaged semantic fields are unchanged; only `source_identity` and
`content_digest` change. `digest-map.json` records every old/new content digest.
The dependent manually reviewed Lean surfaces change exactly 100 quoted digest
literals across 13 files. Their guards, `rfl` proofs, other theorem statements and
proof bodies remain intact, as checked by independent full-text substitution.
Generated Lean embeddings likewise change only provenance metadata and matching
digests. The two older pilot JSON capsules change only their production bindings
and canonical digests.

The original failure is partly inherited. Against GitHub main merge base
`6692d40639c88becff2a203c45727f31cbe23ad3`, seven stale closure hashes already
exist; the PR additionally changes `qm31.zig` and lookup `entry.zig`. Against the
local RV64 branch base `caeb185e15c82136531dd7881a585ec13ed8fc59`, lookup `entry.zig`
is already changed and only `qm31.zig` is additional. The exact path/hash evidence
is in `initial-custody-triage.json`. These are source-custody differences, not an
observed change in normalized symbolic AIR semantics.

Regeneration uses the repository-owned command:

```
python3 scripts/riscv_refinement.py generate --no-export-air \
  --air-ir-dir /tmp/rv64-pr309-fresh-air-review/fresh-family-air \
  --air-program-ir-dir /tmp/rv64-pr309-fresh-air-review/fresh-opcode-air \
  --reuse-committed-sail-evidence
```

Carried Sail evidence is explicitly labeled carried. The generator rejects changed
Sail inputs and requires byte-exact reproduction of their committed artifacts.
No Sail oracle output or translation receipt is repinned, and this is **not a new
fresh-toolchain release receipt**. The independent semantic/source-closure and
literal-substitution review is included as `independent-review.json`.

Actual Lean4.29 rebuild, fresh axiom audit, measured mutation-target checks,
certificate regeneration and source-binding/coverage results are retained in the
accompanying logs. The intended coverage boundary is unchanged: Team A has 24
exact production-local program certificates and Team B has 22 existing family
certificates. These checks do not establish whole-frontend correctness or proof
system soundness, and do not certify the RV64 OM/GKR128 profile.

Final results: all 124 Lean build jobs pass; the fresh axiom audit contains 4,642
source-declared theorems and only `propext`, `Classical.choice` and `Quot.sound`.
All 178 manifest proof-source hashes match. The generator reproduces 60 artifacts
byte-for-byte. Both formerly failing source-binding and aggregate-coverage gates
pass. Certificate changes are limited to `air_digest`, measured `proof_time_ms`
and dependent canonical/index digests; claim boundaries and theorem/axiom lists
are unchanged. Aggregate coverage still reports 24/46 generated-Sail clause
bindings, 24/46 normalized retirements and 0/46 publication-level opcodes.
