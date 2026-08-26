# Taste and engineering canon

**Status:** binding development style for this project
**Last updated:** 2026-08-04

Beauty here means that the easiest code to read is also the hardest code to
misuse. Performance is designed into data shape and ownership. Soundness
assumptions are visible at the point where they enter. Generated artifacts are
boring, deterministic, and explainable.

## The laws

### 1. There is one source of meaning

A migrated component has one typed semantic program. Production evaluation,
formal extraction, witness synthesis, and backend lowering may specialize it,
but no backend receives a separately handwritten semantic copy.

Generated source is an artifact, not an authority. A digest identifies it but
does not by itself prove equivalence to an independently reconstructed program.

### 2. Make invalid states unrepresentable

Use types for distinctions that affect soundness:

- bits are not arbitrary felts;
- bytes are not arbitrary felts;
- architectural words are not M31 values;
- register indexes are not addresses;
- current and next-row values are not interchangeable;
- relation domains and roles are not strings;
- read and write effects have ordered access slots;
- hints are not ordinary unconstrained values.

If a state cannot be excluded by the type system, the constructor validates it
once and returns a named error.

### 3. Effects are explicit and ordered

`regRead`, `regWrite`, `memRead`, `memWrite`, `programFetch`, and
`retire` are semantic operations. They must not be disguised as arbitrary
tuple emission.

Ordering is data. The three live accesses of one instruction carry distinct
subclocks. A refactor may not infer order from incidental source traversal.

### 4. Determinism is a protocol property

Given the same program, compiler version, policy, and target protocol, lowering
must emit byte-identical:

- node order;
- constraint order;
- relation-event order;
- column order and names;
- batching;
- source-to-layout map; and
- manifest serialization.

Hash-map iteration, pointer identity, thread scheduling, and profiler noise may
not affect output.

### 5. Compatibility precedes cleverness

The first lowering for an existing component reproduces its current columns,
constraints, events, and witness. Only after equivalence is established may an
optimizer change the layout.

No migration combines semantic repair, new abstraction, and performance
relayout in one review unit.

### 6. Every optimization carries a cost model and evidence

An optimization states:

- what resource it reduces;
- what resource it may increase;
- why the critical path should improve;
- which benchmark isolates the mechanism; and
- how rollback works.

Fewer source lines are not fewer trace cells. Fewer core rows are not
necessarily less total proving work. A faster run that does not verify is a
failure, not a benchmark.

### 7. Hot paths are data-oriented

- Prefer structure-of-arrays for committed columns.
- Allocate and validate storage before row loops.
- Do not allocate, format strings, hash names, or perform virtual dispatch per
  row.
- Give workers disjoint output ranges.
- Preserve canonical committed order independently of execution order.
- Keep backend-neutral data contiguous and trivially consumable.
- Measure cache, bandwidth, allocation, and synchronization behavior rather
  than guessing.

Comptime owns static shape. Runtime owns witness data. Use runtime polymorphism
only at coarse component boundaries where its cost is immaterial and measured.

### 8. Ownership is part of the API

Every owning object has one explicit `deinit`. Every borrowed view documents
its owner and lifetime. Partial initialization has `errdefer` cleanup.

No hidden allocator, process-global mutable state, or borrowed pointer may enter
the production proving path. Tooling-only global context must be isolated and
named as such.

### 9. Hints are guilty until constrained

A hint is a witness recipe whose result the prover may choose. Its declaration
must identify:

- inputs;
- output type;
- deterministic honest algorithm;
- constraints that bind the output;
- exceptional cases; and
- a mutation that demonstrates rejection.

Constraint code never trusts the honest hint implementation.

### 10. Relations are typed ABIs

A relation schema owns its domain tag, version, ordered field types, admissible
roles, multiplicity policy, and liveness rule. Consumers cannot alter those
properties at a call site.

Cross-proof relation summaries, when introduced, are transcript-bound public
objects. Two independently balanced but unrelated sums do not establish a
connection.

### 11. Recursion requires well-foundedness

Static function composition is allowed. Dynamic recursive activation is
forbidden until the language can carry and verify a decreasing rank or another
reviewed least-fixed-point argument. Multiset cancellation alone proves
balance, not reachability or termination.

### 12. Claims are narrower than evidence

Use the repository's existing claim language:

- differential agreement is not universal refinement;
- row uniqueness is not correctness;
- local AIR refinement is not whole-trace refinement;
- a successful proof is not an independent proof-system soundness theorem;
- parallel execution is not lower total work.

Documents and logs say exactly what was run and what it establishes.

## Zig style

- Prefer concrete named structs and tagged unions over loosely related slices.
- Prefer a small explicit interface over broad `anytype` duck typing. When a
  generic is justified, document the required operations next to it.
- Use exhaustive switches for semantic enums.
- Use checked conversions at representation boundaries.
- Return named errors for malformed external or generated data.
- Reserve assertions for internal invariants already established by validated
  construction.
- Never use `catch unreachable` where witness, artifact, host, or program data
  can reach the branch.
- Keep functions short enough that ownership, effects, and constraint order are
  visible without scrolling through unrelated machinery.
- Comments explain invariants and reasons. They do not narrate syntax.
- Protocol constants name their authority and have a test or manifest binding.

## AIR authoring style

- State every value's semantic type at construction.
- Keep architectural arithmetic distinct from field arithmetic.
- Gate constraints at one reviewed layer; avoid double and missing gates.
- Derive degree from the complete gated expression.
- Name materialized values after meaning, not compiler sequence numbers in
  source-facing diagnostics.
- Keep lookup ordering explicit and stable.
- Express repeated algebra as functions, but preserve source spans through
  inlining.
- Use static loops with compile-time known bounds.
- Refuse data-dependent control flow in constraints. Represent choice with
  constrained selectors.
- Ban silent truncation, implicit limb composition, and unchecked field-to-word
  conversion.

## API taste

A good API:

- has one obvious path for the common operation;
- requires soundness-relevant arguments;
- derives redundant protocol metadata;
- separates logical values from committed storage;
- can be interpreted without side channels;
- exposes deterministic introspection; and
- is difficult to call in the wrong order.

A bad API accepts a relation name, arbitrary tuple, optional clock, optional
selector, and a boolean saying whether it is a read.

## Review questions

Every review asks:

1. What is the semantic authority?
2. Is there now more than one source for the same fact?
3. Which invalid states became impossible, and which remain runtime checks?
4. Are all witness choices constrained?
5. Does event order remain canonical?
6. Can padding or a zero multiplicity activate an unintended path?
7. Did maximum degree include selectors and interaction constraints?
8. Did layout or transcript identity change?
9. What independent negative test fails without this code?
10. What allocation, bandwidth, or synchronization cost was introduced?
11. Does formal extraction consume the production object?
12. Is the claim made by the change no stronger than its evidence?
