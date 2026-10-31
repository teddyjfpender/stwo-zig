# Canonical full Word16 core: native 2n and split1

The concrete full Word16 core now uses the qualified degree-three DIV and MUL
components. All seventeen present core roles use a native 2n quotient domain,
bound `log + 1`, and common composition split1. An omitted empty DIV remains an
explicit count-zero physical class. This is one canonical protocol evolution,
`word16_execution.protocol.SCHEMA = 2`, not another runtime CPU policy enum.

## Arithmetic and ownership

DIV retains its existing 1135 main and eight interaction columns and its exact
1567-residual arithmetic authority. MUL retains its existing 87 main columns,
typed requests, and 96 BYTE queries per padded row. Its degree-three interaction
uses 200 columns instead of the legacy 132, with 192 residuals. Both production
native loaders use PackedM31 arithmetic and PackedQM31 random accumulation;
QM31 remains the OODS lane.

`Source.multiplication` remains the original trace owner. The new pointer-taking
`degree3_source.generateLegacy` writes the new interaction in place and retires
narrow request metadata only after success. The main witness and byte histogram
are constructed once by the existing recipe; no wide main matrix is rebuilt or
copied. Existing owned MAIN/INTER handoffs and allocator checks remain intact.
The standalone legacy RV64 DIV/MUL providers keep their existing 4n encodings.

The central transcript binds schema2, native split1, MUL200 and every physical
shape before the fixed/main commitments and relation challenges. Existing
physical claim mixing and all closure checks remain in their original order.
The global manifest's per-instance specification includes this central framing,
so actual stage1 roots cannot be reused with an unbound geometry declaration.

## Coordinate consistency

For a component trace log l, its new native quotient q has degree below
2^(l+1). With common bound C and split1, both the domain accumulator and OODS
sample q at the coordinate D^(C-l-1)(p). Merely changing the old 4n callbacks'
metadata would instead evaluate D^(C-l-2)(p), which is not the same polynomial.
The qualified native2n loaders remove that mismatch.

A separate, explicit `Components.proversForDegree4Join` /
`verifiersForDegree4Join` pair lifts **every** degree-three core contribution by
one bound log and uses split2. This includes DIV and MUL. The legacy integrated
Keccak protocol uses these helpers because its permutation still requires 4n.
It is qualified by its actual joined proof tests, rather than silently joining
incompatible native coordinates. A separate Keccak truth proof may keep split2
while a CPU plus degree-three bridge proof uses the default core split1.

## What the geometry does and does not save

The large CPU, ALU, LS and boundary native kernels were already 2n. Removing the
old common split2 lifts does not halve their constraint-row work. It removes
weighted quotient extension, reduces the common accumulation bound, and changes
composition chunks from sixteen M31 columns to eight at the same chunk log.
At CPU log22 the composition bound becomes23, the chunk log remains22, and the
largest sampled trace/FRI bound remains22. There is no claim of a 2x FRI reduction.

The real packet0 fixture has 4,194,303 instructions, 574,440 grouped ALU facts
(log20), 673,582 grouped BINARY facts, 5,051 MUL requests and zero DIV requests.
Its actual grouped source changes as follows:

| M31 source cells | Qualified split2 control | Native2n core |
| --- | ---: | ---: |
| Fixed | 67,168,160 | 67,168,160 |
| MAIN | 593,751,776 | 593,751,776 |
| INTER | 655,329,792 | 655,886,848 |

Only the 68 extra MUL interaction columns at log13 add source: 557,056 M31
cells, or 2,228,224 bytes. Raw plan-only Coverage counts conservatively select
ALU log21; they are not these actual grouped proof geometries and must not be
used as a measured source comparison.

The small closed proof's **decoded** opening-value counts are now
`[127,1605,792,8]` across fixed/main/interaction/composition. Omitting empty DIV
gives `[124,469,780,8]`. The 1151-value DIV difference remains independently
observed from actual proofs. These numbers count previous samples as samples,
not an invented second full matrix allocation.

## Qualification and scope

Safe/Fast core coordinator, prepared ownership, source, global RAM and legacy
Keccak joined tests verify actual STARKs. They include per-role native and
explicit degree-four-join bounds, decoded opening counts, claim attacks,
omission attacks, owned/borrowed commitments, and allocation-failure cleanup.
The standalone MUL tests additionally requalify the pointer-taking generation
path against its existing arithmetic and exact proof controls.

The 4,194,303-step packet0 proof is freshly verified against independently
loaded ELF/input/policy. Its entire CPU boundary (PC, all32 register values and
clocks), operation counts and 708,957 before/after RAM records match the pinned
split2 control. The 32,612,038-byte RAM sidecar is byte-identical. New proof
bytes intentionally differ: schema and geometry changed. Both old-proof/new-
receiver and new-proof/old-receiver tests reject, including after adapting only
the optional geometry JSON field to avoid a parser-only rejection.

This is a genesis-prefix and existing global-prefix protocol qualification,
not a new full-block or recursive acceptance claim. Runtime measurements must
use matched allocator, streaming batch, grouped geometries and a quiet whole-
job comparison; native row-area estimates alone do not establish a speedup.
