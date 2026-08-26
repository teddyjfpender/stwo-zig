# ADR-0038 — Pinned typed opcode authority and generated retirement

**Status:** accepted
**Date:** 2026-08-12

**Classification:** production execution, witness, AIR, and dispatch authority;
partially supersedes ADR-0031's shadow-only LUI classification

## Context

The original felt-to-AIR proposal requires one opcode-family definition to own
architectural execution, witness construction, direct constraints, and ordered
relations. Migrating only the witness writer does not meet that requirement:
the runner and AIR can still carry independent formulas, and a successful
typed-versus-production comparison can then be correlated rather than
independent.

Production row loops also cannot retain compiler arenas, strings, maps,
allocator calls, or indirect semantic dispatch. Conversely, replacing a
small fixed evaluator with a generic maximum-family value returned by value can
introduce stack traffic even when the typed formula itself is faster. The
activation boundary therefore needs both a strong authenticated identity and a
small fixed executable surface.

## Decision

### Each migrated family has one fixed executable authority

A production authority binds, at minimum:

- the typed semantic-program format and digest;
- the exact physical witness-recipe digest and column count;
- a stable architectural execution recipe;
- every direct-root recipe in production order;
- every relation domain, role, arity, access ordinal, and order;
- the physical lookup-batch policy; and
- a domain-separated digest of that complete binding.

Cold admission reconstructs and validates the authored arena and witness
binding. The admitted hot capability is immutable, pointer-free, and carries a
compile-time-pinned binding plus digest. Dynamic or test-authored definitions
must still enter through full validation; the static route is reserved for the
repository's pinned production program and is independently checked against
the authored graph.

The same authority supplies:

- the pure architectural retirement result;
- failure-atomic trace/access projection;
- direct-to-final-storage witness construction;
- caller-owned direct-constraint output;
- caller-owned ordered-relation output; and
- formal/runtime program export.

### Dispatch is compile-time exhaustive and fails closed

Architectural instruction decoding remains independent. A generated
retirement registry maps the dense decoded opcode enum to fixed authority tags
with one indexed load. Registry order and protocol opcode IDs are checked at
compile time; duplicate entries are compile errors. A migrated opcode either
commits its typed transaction completely or returns an error before logical
mutation. It may never fall through to the legacy executor, whose migrated
case returns `GeneratedRetirementRequired`.

The registry began with LUI and FENCE and now also carries BASE_ALU_IMM and
AUIPC. Later families extend the same numeric registry; no runtime name lookup,
hash table, allocator, or function-pointer dispatch enters the row loop.

### Retirement is failure-atomic

The authority first compiles a stack-local transaction from immutable runner
snapshots. It resolves architectural results, x0, aliases, access phases,
predecessor clocks, clock gaps, and row projection before publication. Every
fallible destination reserves capacity before the first CPU, trace, or
state-chain write. Any allocator call is followed by complete snapshot
revalidation. The warm admitted path performs no allocation; publication is a
sequence of infallible direct writes and assume-capacity appends.

Empty-effect families specialize this shape rather than paying for impossible
events. Small direct evaluators write into caller-owned storage so production
does not copy the maximum-family result buffer across a return boundary.

### Legacy code becomes an independent test oracle

Replaced semantic and runner formulas are renamed explicitly as legacy test
oracles and removed from production exports. Differential tests call those
oracles directly; production tests call the typed path. A test that compares
two routes through the same typed authority is not accepted as independent
evidence.

### Per-family activation gate

A family enters the generated registry only after all of the following hold:

1. exact physical rows, direct roots, ordered relations, manifests, and formal
   exports;
2. Sail or another independent architectural oracle over edge, random, alias,
   and x0 cases;
3. byte-identical proof and transcript output under the unchanged protocol,
   followed by independent verification;
4. malicious-row, relation, selector, allocation-failure, stale-transaction,
   and legacy-bypass rejection;
5. Debug, ReleaseSafe, and ReleaseFast focused gates; and
6. paired hot-path evidence showing no meaningful regression. Whole-proof
   evidence remains authoritative over an isolated microbenchmark.

LUI and FENCE satisfy this boundary without changing statement geometry,
relation order, challenge draws, proof bytes, or transcript state. Updating a
formal source-closure identity after retiring a production source file is an
expected generated-artifact change, not a protocol-layout change.

## Performance invariants

- No per-row allocation, dynamic string, hash map, arena traversal, or indirect
  semantic dispatch.
- One bounded opcode-indexed registry load before a compile-time-specialized
  family branch.
- Caller-owned exact-length direct and relation results in production loops.
- No duplicate execution of direct constraints while constructing lookups.
- Fixed stack-size budgets for staged plans and prepared tokens.
- Paired benchmarks rotate execution order and consume outputs; results taken
  during concurrent heavy compilation are diagnostics, not promotion evidence.

## Consequences

For a migrated family, execution, witness, AIR, and export can no longer drift
as separate production descriptions. Independent oracles remain available
without remaining executable production alternatives. The typed compiler pays
its validation cost once at admission, while the steady-state runner and AIR
loops retain fixed numeric code comparable to hand specialization.

The transition is intentionally family-by-family. Witness migration for all
seventeen families remains valuable substrate, but it does not imply that
execution/AIR single-source migration or handwritten composition retirement is
complete.

## Rejected alternatives

- Retaining the legacy runner as fallback for registered opcodes: this makes
  production authority dependent on an error path and permits silent drift.
- Authenticating semantic digests on every row: correct but unnecessary hot
  work once a fixed capability has passed cold admission.
- Returning a maximum-sized generic direct buffer by value: it can turn a
  faster small evaluator into avoidable stack copies.
- Treating the typed production path as its own independent oracle: shared
  authorship cannot expose a correlated semantic error.
- Switching all families at once: it removes the family-local proof,
  performance, and rollback boundary.

## Revisit when

Revisit when compiler-generated composition metadata can construct the same
fixed capabilities directly, or when a measured whole-proof profile justifies
a different registry, storage, or batching layout under an explicitly
versioned protocol decision.
