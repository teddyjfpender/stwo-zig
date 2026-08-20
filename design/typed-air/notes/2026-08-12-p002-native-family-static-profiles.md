# 2026-08-12 — P-002 native family static profiles

## Question

Does the deterministic P-001 profile cover the complete native typed opcode
inventory with reviewed bytes and an independent check against current
physical and LogUp geometry?

## Context and exact scope

The registry covers the 17 production witness-family enum values in protocol
order. It binds every value at comptime to one concrete native definition;
`base_alu_imm` binds `typed_addi`. Collection executes no witness, prover,
verifier, benchmark, or telemetry path. Production activation is recorded as
`not_assessed` rather than inferred from source names or dispatch.

Physical main width and authored program facts come from the native modules.
Singleton/pair batching is explicit audited protocol context. Before reviewed
bytes are accepted, a separate production-shadow compilation must match every
family's width, direct roots, lookup count, batch size/count, interaction
columns, and direct/numerator/denominator/final interaction degrees.

## Reviewed artifacts

- `design/typed-air/artifacts/p002-native-family-static-profile-v1/profiles-v1.tsv`
  contains inventory metadata followed by every field of the P-001 TSV schema.
- `design/typed-air/artifacts/p002-native-family-static-profile-v1/profiles-v1.md`
  is the deterministic readable projection.

The authenticated report digest is
`0dd67acd8705f77a5c482a8d3706b38929d799091b3971e995b20dcc44f56772`.
The TSV and Markdown file digests are
`d4b187cbdf5baee61f4eb2541acf1d69e8e84ddae91007b574ec4a6663a18c6b`
and
`52bf9cff23de5ea05da9588846a1af2e21be67ad16379fd580bb4057cab34d1c`.

## Exact aggregate

The independent-family sum is 644 physical main columns, 677 logical inputs,
545 direct roots, 242 typed effects/lookups, 155 LogUp batches, and 620 M31
interaction coordinates. The native expression DAG contains 3,079 nodes and
4,370 edges, of which 649 nodes are structurally shared; 3,034 nodes are in the
constraint/effect closure and 45 are outside it. Maximum direct, numerator,
denominator, and modeled interaction degrees are 3, 2, 2, and 3.

Native DAG counts intentionally do not cross-check the production-shadow
importer's source/canonical node counts. They are different construction
surfaces and are separately authenticated; equating them would turn a useful
static fact into a false compatibility requirement.

## Check and update

The default command regenerates both authorities and fails on absent or changed
bytes:

```sh
zig build typed-air-static-profile --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast
```

Reviewed replacement requires the explicit
`-Dtyped-air-static-profile-mode=update` option and uses atomic files. Golden
regeneration, corruption/truncation, report corruption, and exhaustive
projection-allocation failure tests are part of the focused registry root.

## What this does not establish

The report contains no timing, RSS, field-operation, FFT, proof-size,
critical-path, or backend fact. It changes no layout, batching, transcript,
statement, prover, verifier, or production dispatch. Those remain P-003 or
family-migration concerns.

## Decisions/tasks affected

P-002's acceptance is satisfied: the family-ordered report covers all 17
native typed families and independently cross-checks current layout and batch
authorities. P-003 remains queued on runtime telemetry prerequisites.
