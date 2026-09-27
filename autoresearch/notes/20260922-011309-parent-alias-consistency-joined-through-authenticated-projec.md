---
title: Parent alias consistency joined through authenticated projections
author: Teddy Pender
created_utc: 2026-09-22T01:13:09Z
---

# Parent alias consistency without capture-dependent producer IDs

The complete BLAKE3 parent fixture now joins authenticated projected index bytes,
private opening-value producers, the read-only input adapter and sorted per-column
consistency. The old canonical scalar hash map, value-sharing IDs and alias-derived
producer multiplicities have been removed from blake3_opening_inputs. Early native
geometry/admission checks remain; circuit authority comes from the joined ports.

Projection reuses existing QM31 coordinate packing and the existing affine byte
routing AIR. A new validated affine constructor exposes its already-pinned matrix
equations; no AIR semantic identity changed. Callers must derive output byte bounds
from authenticated input bounds and fixed coefficients. Here source DEEP query bits
are already constrained boolean, and disjoint powers-of-two contributions sum to
at most 255 in each byte. No full index is reduced into M31.

For each distinct column log and raw query, groups of four selected bits feed a
shared byte accumulator. Raw bit zero is preserved; projected bit i>0 comes from
raw bit lifting-column_log+i. The last partial group repeats source bit zero in
unused slots with coefficient zero, retaining exact read accounting. Final index
ports have one use per column of the same log. All fixed schedules and bit-read
counts depend on geometry/query count, not query values or their duplicate pattern.

Each trace opening's scalar producer feeds DEEP arithmetic, leaf encoding and the
read-only adapter. Each column has separate table/chain namespaces, exactly q
sorted rows and a fixed zero sentinel. Sorted indices, values, gaps and permutation
order are private. The parent roster grows from 16 to 18 AIRs by including the two
previously qualified read-only components. Projection packing/routes reuse roster
members already present. FRI opening ownership is unchanged.

Validation: serial ReleaseSafe batch exited zero, 8/8 steps, 2/2 focused tests.
Projection regression: 512 ms / 2 MiB (compile 4 s / 480 MiB). Complete parent
gate: 32 s / 6 GiB (compile 42 s / 2 GiB). It produces and verifies its original
child fixture and the joined parent. These are qualification diagnostics, not
matched speed measurements or parent-of-parent throughput.

Regression coverage: native parity projection at lifting logs 6 and 31; repeated
column logs; changed raw queries and duplicate patterns with identical fixed
packing/routing rows, ports and read counts; direct affine constraints and output
mutation rejection; missing affine sources, self-routing and invalid geometry.
The 31-bit test reaches index 0x7fffffff without field-index aliasing. This does
not independently qualify all other parent components at that domain size.
The full parent proof checks the aggregate read balance and all added constraints
against independently constructed preprocessing. Existing sorted-table unit and
proof evidence remains in the preceding read-only-consistency snapshot.

An initial compile rejected unbraced nested assignment loops in the new affine
witness helper. Braces were corrected before qualification; the initial compiler
log is preserved. Formatting and git diff --check pass. All build sessions reached
terminal exit. No broad suite was rerun.

Remaining: production capacity classes/overflow admission, production child-proof
source and reusable-key/artifact qualification, Metal support, CPU/Metal
parent-of-parent proofs, then matched end-to-end performance. This removes one
specific source of query-dependent preprocessing; it does not establish a complete
reusable production key. Production still uses Poseidon.
