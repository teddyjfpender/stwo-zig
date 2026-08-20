# 2026-08-14 — canonical recursive CSP profile registry

## Outcome

The production statement builder proves that the frozen recursion development
profile is not the shape of any EthProofs CSP workload. All 16 canonical
workloads have maximum column log degree 20, but none has the frozen
38/625/200 preprocessed/main/interaction column counts.

The benchmark boundary now has a bounded, identity-sealed registry for the
nine exact CSP geometries. It recognizes 16/16 canonical cases and rejects an
unknown or mutated shape. Recognition is not confused with implementation:
0/9 profiles are currently instantiated by the outer circuit, so 0/16 cases
are benchmark-executable and the cohort controller fails before creating an
artifact directory.

This is a fail-closed implementation result, not a recursive performance
measurement.

## Method

`statement_shape_inspection.zig` calls the production commitment-witness and
statement-geometry builders after running each real guest. It constructs no
trace columns, commitment, or proof, and it never infers dimensions from cycle
count. The ReleaseFast inspector emits those exact facts.

`profile_registry.zig` selects on all six facts: component count,
infrastructure count, three tree-column counts, and maximum column log degree.
Each entry has a domain-separated SHA-256 shape seal. A second registry seal
binds ordered profile seals, implementation status, and canonical incidence.
The Python evidence validator independently reconstructs both byte-level
seals before accepting an inspection or audit.

The sealed audit is
`vectors/riscv_csp/recursion-shape-audit-v2.json`.
The v1 artifact remains the immutable predecessor snapshot that established
0/16 admission against the single development profile.

## Exact workload matrix

| workload | input | components | infrastructure | preprocessed | main | interaction | max log | selected profile |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| SHA-256 | 128 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| SHA-256 | 256 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| SHA-256 | 512 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| SHA-256 | 1024 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| SHA-256 | 2048 | 13 | 11 | 56 | 951 | 480 | 20 | `sha256_2048` |
| Keccak | 128 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| Keccak | 256 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| Keccak | 512 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| Keccak | 1024 | 12 | 11 | 54 | 916 | 444 | 20 | `hash_compact` |
| Keccak | 2048 | 14 | 11 | 58 | 999 | 512 | 20 | `keccak_2048` |
| Poseidon2-M31 | 2 | 13 | 11 | 56 | 953 | 468 | 20 | `poseidon2_2` |
| Poseidon2-M31 | 4 | 14 | 11 | 58 | 988 | 504 | 20 | `poseidon2_4` |
| Poseidon2-M31 | 8 | 15 | 11 | 60 | 1023 | 540 | 20 | `poseidon2_8` |
| Poseidon2-M31 | 12 | 18 | 11 | 66 | 1144 | 644 | 20 | `poseidon2_12` |
| Poseidon2-M31 | 16 | 21 | 11 | 72 | 1271 | 740 | 20 | `poseidon2_16` |
| ECDSA secp256k1 | 32 | 94 | 11 | 218 | 4444 | 3624 | 20 | `ecdsa_secp256k1_32` |

## Why there is no maximum-padded universal profile

Padding every workload to the ECDSA geometry would make the common hash
profile pay approximately 4.85 times as many main columns and 8.16 times as
many interaction columns. Its total queried table width would rise from
1,422 to 8,294 columns, approximately 5.83 times larger. That cost is paid per
FRI query and would erase much of the point of specialized recursion.

All nine profiles share maximum log degree 20. The FRI depth and fold schedule
can therefore remain common while the exact tree widths, sampled value count,
queried value count, fixed-wire type, and transcript schedule are specialized.
This is a smaller and more cache-friendly dispatch surface than universal
maximum padding.

## Producer admission and dispatch state

Request schema v3 carries the selected profile name, its shape seal, and the
registry seal from the sealed plan. The producer checks the registry seal at
source admission. After guest execution, the production prover derives its
statement once and invokes a fail-closed admission callback before transcript
binding or trace construction. That callback selects the profile, checks both
request identities, and rejects `RecursiveProfileOuterUnavailable` unless the
entry is explicitly `outer_wired`. It does not rebuild the commitment witness
solely for profile admission.

The native proving call also receives the requested strict worker count through
the proof-scoped execution API. This removes a prior benchmark asymmetry in
which the worker count reached the outer proof but not the base leaf proof.

## Remaining implementation path

The registry closes selection, evidence, and fail-fast admission. Turning an
entry to `outer_wired` requires all of the following in one reviewed change:

1. parameterize segment transcript shape and fixed-wire dimensions from the
   selected exact profile;
2. instantiate `FixedStarkProofWire(dimensions)` and transcript witnesses in a
   bounded compile-time dispatch branch;
3. make the outer segment-transcript source generic over the same dimensions;
4. bind profile name, shape seal, and table-layout identity into the outer
   statement, verification key, receipt, and child-admission seal;
5. independently rebuild the selected branch in the outer verifier;
6. add wrong-profile, near-miss, permuted-roster, stale-seal, and branch-swap
   mutation tests; and
7. keep `production_ready=false` until a complete parent STARK verifies the
   child proof rather than only the verifier subsystem.

The natural implementation is a `switch` over nine compile-time profile
instances. Runtime-sized attacker-controlled proof arrays remain forbidden.
The common profile should be wired first because it covers half the suite,
then the seven moderate profiles, with the ECDSA profile isolated so its much
larger compile-time and memory footprint cannot contaminate common hashes.

## Reproduction

```sh
zig build riscv-recursion-shape-inspector -Doptimize=ReleaseFast
python3 scripts/riscv_recursion_csp_benchmark.py audit-shapes \
  --inspector zig-out/bin/stwo-zig-riscv-recursion-shape-inspector \
  --manifest vectors/riscv_csp/manifest-v2.json \
  --output /tmp/recursion-shape-audit-v2.json
python3 scripts/riscv_recursion_csp_benchmark.py validate-shapes \
  --audit /tmp/recursion-shape-audit-v2.json
```

The checked-in audit is append-only evidence. Regeneration must use a new path
and be reviewed against the prior matrix; it must never silently replace a
performance cohort.
