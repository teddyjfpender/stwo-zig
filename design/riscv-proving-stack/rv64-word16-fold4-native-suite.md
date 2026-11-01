# Experimental Word16 native FRI fold4 suite

Production remains the existing fold1,q70,PoW26,blowup1,last-layer-bound0 suite.
`pcs_suite.Suite.experimentalFold4()` changes only `fri_config.fold_step` to4.
The Merkle hasher, its domain separation, channel, lifting policy, AIR, role
geometry, physical claim ledger and native event semantics do not change.
There is no ambient or thread-local suite override and no new protocol enum.

## Receiver authority and transcript

The receiver selects a validated Suite when constructing immutable Core.Materials
or canonical service/truth Key owners. Old constructors delegate to production.
Validation accepts exactly the two concrete configurations, before key allocation;
it rejects query/PoW/lifting changes and all other fold schedules. An expected
suite is never read from a proof, bundle, receipt or producer-selected metadata.

Core `mixMaterials` mixes the admitted PCS configuration before commitments.
The existing native PCS config mixer already domain-separates nondefault fold
schedules while preserving the default transcript exactly. Canonical service
truths mix their own admitted key configuration before roots as well. All CPU and
truth keys must select the same suite, checked before stage1 work. Thus the full
ordered manifest binds the suite through every statement digest, even when
identical polynomial data give identical fixed/MAIN roots across suites.
Physical claims still enter the local transcript before constraint coefficients.

Each receiver checks decoded proof.config against its independently admitted
key's Suite and rejects revision configurations. No self-declared fold parameter
can select verifier policy. A source worker constructs its Scheme from its own
admitted key; seal checks the same configuration and actual roots. Existing
fixed column builders and shared tree leases remain the single data authority.
Changing fold scheduling does not re-encode immutable program/fixed polynomials.
Historical K-only/secp coordinators remain production-only controls and reject
experimental keys rather than acquiring new suite variants.

## Explicit experiment entry points

The current CSP/Sail tools keep `--prove` and `--verify` as production defaults.
The explicit `--prove-fold4` and `--verify-fold4` modes select the experiment from
the caller's command, with the same independently pinned ELF/input/oracle data.
The Ethereum driver similarly provides `produce-fold4`, `verify-prefix-fold4`
and `verify-fold4`; the ordinary commands remain production. Actual acceptance
still requires its usual complete/prefix statement and terminal checks.

These are experiment modes, not default activation or a claim that a whole
Ethereum block has been qualified under fold4. `--inspect-proof` on the CSP/Sail
tools reports serialized counts only and grants no acceptance authority.

## Native implementation and security assumptions

No FRI algorithm is copied: the existing native prover/verifier schedule clamps
`min(fold_step,remaining)`, including the final shorter round. The new path uses
the same base-field SIMD AIR and secure-field lookup/random accumulation.

Seventy queries,blowup1 andPoW26 are retained as configured parameters. Increasing
the round arity changes the FRI security analysis; the config's nominal bit-count
helper is not a proof that soundness is unchanged. QM31 has characteristic
`2^31-1` and cardinality below `2^124`; lookup/OODS and multi-instance error terms
remain separate obligations. No whole-protocol128-bit claim is made. Native
proof and mutation tests qualify behavior and authority boundaries, not a formal
FRI soundness theorem, independent Rust verification or recursive acceptance.

## Qualification and measurements

The tests exercise actual q70 proofs for both suites, bidirectional cross-rejection,
config relabel and FRI-root mutations, mixed-suite preflight, native16-worker
proof-byte parity and a five-proof CPU/K/ADD/DOUBLE experiment. Default fixed roots
and the service fixture's fixed/MAIN roots must agree across suites, while manifest
digests differ. Complete CPU and RAM semantics are checked against existing controls.

Real prefix4,complete CSP ECDSA and continuous Sail workloads use independently
expected input/image/output authority and fresh receivers. The receipt pins final
results. Performance comparisons require coordinated quiet runs and report whole
pipeline/proof bytes, FRI/decommit stages and fresh receiver timing. Decoded witness
and compressed hash counts are exact serialized work sizes, not inferred receiver
hash-operation counts. Fewer FRI rounds can increase per-query witness sizes;
no benefit is presumed and production remains fold1 pending evidence/review.

The coordinated same-binary F1,F4,F4,F1 runs (two observations per suite) gave:

| Workload | F1 / F4 proof bytes | F1 / F4 producer seconds | F1 / F4 fresh-process seconds |
| --- | ---: | ---: | ---: |
| Ethereum prefix4, seven proofs | 6,694,144 / 5,881,184 | 31.579 / 32.328 | 2.548 / 2.522 |
| Complete CSP ECDSA | 754,504 / 612,608 | 5.300 / 5.465 | 0.193 / 0.193 |
| Continuous Sail full ordinary ISA | 1,036,000 / 902,600 | 2.919 / 2.848 | 0.402 / 0.394 |

These are this host's short controlled observations, not a general performance
claim. Prefix4 used one proof job and commit batches of64 columns in both modes.
RSS was essentially equal within each workload. Prefix4's recorded FRI decommit
stage increased from0.0196 to0.4626 seconds; quotient-build/commit was4.725 versus
4.851 seconds. CSP's deterministic transcript-dependent PoW took0.011 versus
0.139 seconds, so its complete-wall difference should not be attributed wholly
to FRI. Sail does not currently emit the detailed prover-stage recorder.

For prefix4, sampled/queried PCS values were unchanged. FRI inner-layer count
fell123 to29 and compressed FRI hash witnesses fell40,701 to7,949, while FRI
field witnesses increased6,195 to21,620. These facts justify investigating
transport/recursive-verifier costs separately; they do not justify native
activation. No recursive circuit or whole-block Fold4 qualification is claimed.
