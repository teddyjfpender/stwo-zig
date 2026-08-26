# ADR-0034 — C-013 source-identical workload shapes and schedule

**Status:** accepted
**Date:** 2026-08-10

## Context

The normative M6 protocol already fixes the labels `core_only`,
`balanced_core_and_poseidon2`, and `poseidon2_dominant`, but it did not define
the executable work behind those labels. That omission prevented a capture
plan from authenticating exact ELFs and left room to tune a workload after
observing performance. C-013 also needs both arms to execute one semantic
function from one source without letting an optimizer erase the common core
work.

The existing dominant pair established semantic equality and one-call proof
correctness before this decision. Those diagnostics remain disclosed and are
not promotion samples. Numerical gates, call counts, sampling counts, and
statistical rules are unchanged.

## Decision

All three workload shapes are feature-selected builds of
`vectors/riscv_guests/poseidon2_m31_permute_v1/src/main.rs`. For every input
state they execute one measured permutation, using portable RV32IM in the
software arm and `CUSTOM-0` in the precompile arm. Before that measured
operation, both arms execute this exact number of additional portable
permutations:

| Frozen shape label | Portable background permutations per call | Candidate permutation mix |
| --- | ---: | ---: |
| `poseidon2_dominant` | 0 | 0% portable, 100% precompile |
| `balanced_core_and_poseidon2` | 1 | 50% portable, 50% precompile |
| `core_only` | 15 | 93.75% portable, 6.25% precompile |

`core_only` is retained because it is the frozen protocol label; its precise
meaning is core-dominated, not zero precompile calls. Keeping one compared call
in every shape preserves the call-count matrix and the same extension
semantics. `shape-balanced` and `shape-core-only` are mutually exclusive Cargo
features. `precompile` changes only the measured permutation.

The background state starts from the same canonical input. Each round applies
the exact portable permutation and a canonical lane perturbation. One result
word is written through the volatile guest-output boundary and then overwritten
by the measured operation's ordinary output. The background work is therefore
proof-visible, while public output remains the exact ordered Poseidon2 output
and is byte-identical between arms and shapes.

The C-013 launch order is also fixed in code. Shapes are outermost in the table
order above but with the protocol's canonical `core_only`, balanced, dominant
ordering; call counts are inner and ordered `0/1/8/64/512/4096`. Every one of
the eighteen cells has ten excluded warmups per arm and three measured rounds
of ten pairs per arm. Warmup pair order alternates; measured rounds begin
`AB`, `BA`, `AB`. Every attempt is separated by one second. Eighty A/A
calibration attempts launch first as the admission gate; only after they pass
do the 1,440 M6 child attempts launch. The allocation-free global schedule
identity is
`20153896cdcc903d6784499fba267f0ff5c8e532573b9b415b28121352775dd4`.

The A/A labels name the same executable and source identity. The schedule does
not authorize retries, outlier deletion, substitution, or parallel launches.
The later capture plan must additionally pin the clean source, six ELF files,
child executable, inputs, expected outputs, host/backend authority, and frozen
performance protocol before its first attempt.

## Consequences

- The workload distinction has a static semantic explanation rather than an
  arbitrary integer burn loop or an observed-time calibration.
- Both arms retain exactly one source, I/O contract, function, completion rule,
  and output corpus. Only the advertised extension operation differs.
- Core-dominated 4,096-call software proofs are intentionally expensive. A
  failed resource admission is `NO_VERDICT`; reducing the shape after seeing
  it is not permitted under this protocol version.
- One-call semantic preflight now admits all six ELFs. It is correctness and
  identity evidence, not the secure repeated C-013 receipt.
- The child schema records the shape and exact portable-background count so a
  path or feature substitution cannot be hidden by an unchanged label.

## Rejected alternatives

- **Calibrate a generic loop until timings look balanced:** rejected because it
  makes workload identity hardware- and result-dependent.
- **Use separate Rust sources per arm or shape:** rejected because source drift
  would be confounded with the precompile comparison.
- **Let `core_only` contain no compared Poseidon call:** rejected because call
  count and extension multiplicity would cease to mean the same thing across
  the frozen shape matrix.
- **Publish background results or append shape-specific output:** rejected
  because the semantic function and public output would differ across shapes.
- **Trust unused arithmetic to remain in the ELF:** rejected because LTO may
  remove it; the volatile scratch effect is explicit.

## Revisit when

Revisit only through a new protocol and capture-plan version if the frozen
core-dominated cohort cannot be admitted on the named authority host, if a new
guest function needs a different composition model, or if the historical
`core_only` label is replaced. Existing diagnostic or receipt data must never
be reinterpreted under a new shape definition.
