# RISC-V production AIR IR v2 contract

**Status:** normative wire and interpretation contract for the first Team A
Level-2 AIR-binding PR in
[issue #136](https://github.com/teddyjfpender/stwo-zig/issues/136).

**Machine-readable companion:**
[`air-ir-v2.schema.json`](air-ir-v2.schema.json).

**Claim boundary:** this contract specifies how every production RISC-V
constraint program is represented and interpreted. All 17 families and all 46
manifest selectors now have deterministic, source-bound artifacts; the strict
Lean decode/evaluation integration remains focused on LUI. Satisfying this
wire contract does not by itself prove an opcode's AIR-to-architecture
theorem, refinement to generated Sail, publication coverage, or that an
accepted PCS/FRI proof satisfies this AIR. Those remain separate obligations in
[`UNIVERSAL_AIR_SAIL_REFINEMENT.md`](UNIVERSAL_AIR_SAIL_REFINEMENT.md).

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## 1. Design invariant

The shipped evaluator and the formal exporter MUST consume the same typed
`ConstraintProgram` built from production semantics. The production
interpreter evaluates that program over the QM31 embedding of M31. The exporter
serializes the same program as AIR IR v2, and Lean strictly decodes and
interprets that serialization over M31.

A second, hand-written list of constraints or lookup requests is not AIR IR v2.
A random production-versus-symbolic differential remains useful regression
evidence, but it is not the semantic binding. A digest identifies content; it
does not prove that independently reconstructed content is production content.

## 2. Exact top-level object

The top-level value MUST be one JSON object with exactly these members:

| Member | v2 value |
| --- | --- |
| `schema_version` | integer `2` |
| `kind` | string `stwo-riscv-air-constraint-program` |
| `field` | exact object `{"name":"M31","modulus":2147483647}` |
| `family` | one production family name from section 3 |
| `columns` | nonempty ordered typed-column array |
| `nodes` | nonempty ordered, hash-consed expression arena |
| `active_row` | expression-node index |
| `opcode_selector` | exact manifest identity and selector expression |
| `fixed_tables` | the six identities in section 6, in the listed order |
| `events` | one contiguous array as specified in section 7 |
| `projection` | relation-event and next-PC references from section 8 |
| `source_identity` | production builder and source closure from section 9 |
| `content_digest` | canonical content SHA-256 from section 10 |

Unknown, missing, or duplicate members at any depth are errors. An
implementation MUST NOT assign defaults to an omitted member.

## 3. Family and opcode identity

`family` MUST be one of:

```text
base_alu_reg  base_alu_imm  shifts_reg  shifts_imm
lt_reg        lt_imm        branch_eq   branch_lt
lui           auipc         jalr        jal
load_store    mul           mulh        div          fence
```

`opcode_selector` has exactly:

```text
{"manifest_id": Nat, "mnemonic": String, "expression": NodeId}
```

`manifest_id` and `mnemonic` MUST name the same entry in
`src/frontends/riscv/opcode_manifest.zig`, and that entry's family MUST equal
top-level `family`. The v2 mapping is:

| Family | Manifest ID and mnemonic |
| --- | --- |
| `base_alu_reg` | `0 add`, `1 sub`, `5 xor`, `8 or`, `9 and` |
| `base_alu_imm` | `10 addi`, `13 xori`, `14 ori`, `15 andi` |
| `shifts_reg` | `2 sll`, `6 srl`, `7 sra` |
| `shifts_imm` | `16 slli`, `17 srli`, `18 srai` |
| `lt_reg` | `3 slt`, `4 sltu` |
| `lt_imm` | `11 slti`, `12 sltiu` |
| `branch_eq` | `27 beq`, `28 bne` |
| `branch_lt` | `29 blt`, `30 bge`, `31 bltu`, `32 bgeu` |
| `lui` | `35 lui` |
| `auipc` | `36 auipc` |
| `jalr` | `34 jalr` |
| `jal` | `33 jal` |
| `load_store` | `19 lb`, `20 lh`, `21 lw`, `22 lbu`, `23 lhu`, `24 sb`, `25 sh`, `26 sw` |
| `mul` | `37 mul` |
| `mulh` | `38 mulh`, `39 mulhsu`, `40 mulhu` |
| `div` | `41 div`, `42 divu`, `43 rem`, `44 remu` |
| `fence` | `45 fence` |

`expression` is the opcode-identity expression produced by the same program
builder and placed in slot 1 of the program-access tuple. For a row claimed
for this opcode, Lean requires its canonical M31 value to equal
`manifest_id` (`35` for LUI). `active_row` separately evaluates to M31 one for
an active family row; a nonzero value other than one cannot be silently
coerced to an active Boolean.

The program-access event identified by `projection.program_event` MUST carry
`opcode_selector.expression` in the production selector slot. This check
prevents metadata from labelling another selector's program.

## 4. Typed ordered columns

Each element of `columns` has exactly:

```text
{"index": Nat, "name": String, "role": Role, "type": "m31", "width": 1}
```

The array is the production committed-column order. For element position `i`,
`index` MUST equal `i`. Names MUST be unique, nonempty ASCII identifiers
matching `[A-Za-z_][A-Za-z0-9_]*`. `role` is exactly one of:

- `input`: a value supplied through the local program/state/register/memory
  boundary;
- `output`: a value the row claims as an observable result; or
- `witness`: an internal witness value.

Roles describe proof use; they do not add constraints. Version 2 has only
scalar M31 columns, so `type` MUST be `m31` and `width` MUST be `1`. A wider
column or another field requires a new schema version.

## 5. Expression arena

`nodes` is an array indexed by zero-based `NodeId`. Its exact node shapes are:

```text
{"op":"const", "value": M31Canonical}
{"op":"col",   "column": ColumnIndex}
{"op":"neg",   "args":[NodeId]}
{"op":"add",   "args":[NodeId,NodeId]}
{"op":"sub",   "args":[NodeId,NodeId]}
{"op":"mul",   "args":[NodeId,NodeId]}
```

Every reference in node position `i` MUST be strictly less than `i`. A
constant is an integer in `[0, 2147483647)`; reduction of an out-of-range or
negative JSON number is forbidden. A column reference MUST be in range.
Exactly one `col` node MUST exist for every declared column.

The arena is hash-consed. No two nodes may have the same complete structural
shape. Operand order is structural: exporters MUST NOT reorder `add` or `mul`
operands, algebraically simplify nodes, or deduplicate events merely because
the resulting polynomial is equal. Node order is first production-construction
order.

Every node MUST be transitively needed by at least one of:

- `active_row`;
- `opcode_selector.expression`;
- a constraint root;
- a lookup numerator or tuple element; or
- `projection.next_pc`.

Column nodes are not implicit reachability roots. Thus an unused column node,
an unused lookup input expression, or any other dead expression component
fails closed.

Lean and production interpret the nodes in M31:

```text
const(v)    = v
col(i)      = row[columns[i]]
neg(x)      = -x
add(x,y)    = x + y
sub(x,y)    = x - y
mul(x,y)    = x * y
```

Production embeds these base-field results into QM31 where required; that
embedding does not change the M31 polynomial.

## 6. Fixed-table identities

`fixed_tables` MUST contain exactly the following six objects, in this order.
Each `schema_sha256` is SHA-256 of canonical compact sorted-key JSON for
`{"arity":arity,"domain":domain,"id":id,"log_size":log_size}`.

| `id` = `domain` | Arity | Log size | `schema_sha256` |
| --- | ---: | ---: | --- |
| `bitwise` | 4 | 18 | `7de3a5c8de009b1f2d9da74ce88f02b3705c26da488d0005d0c67b07b9a6daab` |
| `range_check_20` | 1 | 20 | `618f993093152e26cd08fc37b4ddc942a7a7e998444ee2e34d433d42667613e0` |
| `range_check_8_11` | 2 | 19 | `1fa99606e17949d62271f75ad3ecfdb68bc016dadaa1995579d8831417ab8976` |
| `range_check_8_8_4` | 3 | 20 | `c5894ccdf667ad77987691500806fbdb7f93b91fa40672785465e41fb393e1df` |
| `range_check_8_8` | 2 | 16 | `74691adaef966cf81ce717e97fc298c8272958c614327b87aee9dafea79c5102` |
| `range_check_m31` | 2 | 15 | `bf4f031af4d434f3d9ad028c3b8976822499b3f3cdfe81be0933e45baafd674d` |

The geometry digest distinguishes stable table identities; it is not a digest
of table meaning. `source_identity.files` MUST separately bind
`src/frontends/riscv/air/lookups/tables/schema.zig`, whose raw bytes own the
row functions. The Lean interpreter implements these exact membership
predicates:

- `bitwise(lhs,rhs,result,op)`: `lhs`, `rhs`, and `result` are bytes; `op` is
  in `[0,4)`; operations `0`, `1`, `2`, and `3` mean AND, OR, XOR, and zero.
- `range_check_20(x)`: `x < 2^20`.
- `range_check_8_11(lo,hi)`: `lo < 2^8` and `hi < 2^11`.
- `range_check_8_8_4(lo,mid,hi)`: byte, byte, and four-bit bounds.
- `range_check_8_8(lo,hi)`: both values are bytes.
- `range_check_m31(lo,hi)`: `lo < 2^8`, `hi < 2^7`, and
  `lo + 2^8 * hi < 2^15 - 1`.

The final physical `range_check_m31` row duplicates `(0,0)` and the tuple
`(255,127)` is absent. The local membership predicate above reflects that
fact; global multiplicity reasoning remains outside this row interpreter.

## 7. One ordered semantic event stream

`events` is one nonempty array. Every event has `ordinal` equal to its array
position. It consists of:

1. every direct constraint in production evaluation order; then
2. every unbatched lookup request in production construction order.

A constraint event has exactly:

```text
{"ordinal": Nat, "kind": "constraint", "root": NodeId}
```

Its meaning is that `root` evaluates to M31 zero. The constraint prefix
includes every family semantic constraint and the production placement
constraint actually evaluated by the shipped component. Serialization MUST
NOT add exporter-only alias constraints.

A lookup event has exactly:

```text
{
  "ordinal": Nat,
  "kind": "lookup",
  "domain": Domain,
  "numerator": NodeId,
  "tuple": [NodeId, ...],
  "role": "request" | "consume" | "emit",
  "table_id": FixedTableId | null,
  "liveness": "nonzero_numerator",
  "access_ordinal": PositiveNat | null
}
```

The domains and exact tuple arities are:

| Domain | Arity | Kind |
| --- | ---: | --- |
| `registers_state` | 2 | bus |
| `memory_access` | 7 | bus |
| `program_access` | 5 | bus |
| `merkle` | 4 | bus |
| `poseidon2` | 16 | bus |
| `poseidon2_io` | 32 | bus |
| `bitwise` | 4 | fixed |
| `range_check_20` | 1 | fixed |
| `range_check_8_11` | 2 | fixed |
| `range_check_8_8_4` | 3 | fixed |
| `range_check_8_8` | 2 | fixed |
| `range_check_m31` | 2 | fixed |

For a fixed-table domain, `table_id` MUST be that domain's identical fixed
table ID and `role` MUST be `request`. For a bus domain, `table_id` MUST be
JSON `null`. `role` records production request direction without changing or
normalizing the numerator.

`liveness` has one v2 spelling and meaning: evaluate the numerator in M31; the
event is live exactly when the result is nonzero. If a fixed-table event is
live, the ordered evaluated tuple MUST satisfy that table's predicate. If its
numerator is zero, it creates no membership fact. In particular, a proof may
not use the range of an inactive tuple. An event whose numerator directly
references the canonical `const 0` node is statically dead and MUST be
rejected; dynamically inactive requests are expected and remain serialized.

`access_ordinal` is source metadata, never inferred later from tuple adjacency.
For each logical architectural register or RW-memory access, production assigns
one-based contiguous ordinals `1..k` in first-occurrence order. Its
`memory_access` consume event, emit event, and associated
`range_check_20` clock-gap request all carry the same ordinal. Each group MUST
have exactly one consume, one emit, and its associated gap request. All other
events carry `null`. Adding, removing, relabelling, or reordering a member of
an access group is therefore observable.

Direct constraints are not sorted by node ID. Lookup events are not sorted by
domain, table, role, access ordinal, or tuple, and are not reordered for LogUp
batching. Identical repeated events remain repeated. Renumbering a reordered
array does not make it production order: the build gate MUST compare the
artifact with a fresh serialization from the source-bound program or with the
kernel-checked expected program identity.

## 8. Projection

`projection` has exactly:

```text
{
  "program_event": EventOrdinal,
  "state_events": [EventOrdinal, ...],
  "source_events": [EventOrdinal, ...],
  "destination_events": [EventOrdinal, ...],
  "next_pc": NodeId
}
```

All event references target lookup events in the same `events` array, not
indices in a lookup-only subarray:

- `program_event` targets the unique projected `program_access` event;
- `state_events` targets the ordered `registers_state` consume/emit events;
- `source_events` targets ordered `memory_access` consume/emit pairs supplying
  source registers or memory observations;
- `destination_events` targets ordered `memory_access` consume/emit pairs
  publishing destination registers or memory effects; and
- `next_pc` is the exact expression node for the row's claimed next PC.

`state_events` contains exactly one consume/emit pair.
`projection.next_pc` MUST be the same node ID as the first tuple element of
that emitted state event. The arrays preserve production order, contain no
duplicate ordinal, and do not overlap one another. An opcode with no source or
destination effect uses an empty applicable array; it does not invent a dummy
event. The projection is made from interpreted event tuples and expressions,
not from copied architectural values.

This v2 object freezes the AIR-side carrier needed by the first LUI slice. It
does not pretend to freeze the complete `Retirement`, `LocalRowEnv`, or final
row/tuple theorem interfaces; section 13 records those joint follow-ups.

## 9. Production source identity

`source_identity` has exactly:

```text
{
  "builder": RelativeSourcePath,
  "source_closure_sha256": LowerHexSha256,
  "files": [
    {"path": RelativeSourcePath, "sha256": LowerHexSha256},
    ...
  ]
}
```

Paths are unique, normalized repository-relative ASCII POSIX paths, with no
empty, `.`, or `..` segment. `builder` MUST name an entry in `files`.
`files` is nonempty and sorted by path. Each `sha256` is the lowercase SHA-256
of that file's raw bytes; text newline conversion is forbidden.

The v2 production builder is exactly
`src/frontends/riscv/air/constraint_program.zig`. The normative common closure
and per-family semantic additions are enumerated in
`scripts/riscv_refinement_lib/air_program_contract.py`. Each opcode artifact
MUST carry exactly the closure selected by its family; a same-family selector
therefore has the same source closure, while its content digest still binds
the selector's distinct manifest ID and mnemonic.

The artifact records the raw digest beside every one of these paths. The
digests are intentionally not copied into this prose: they are derived from
the exact source state being packaged and are then pinned by the generated
artifact and receipt.

`source_closure_sha256` is SHA-256 of the canonical compact sorted-key JSON
encoding of the `files` array itself. It MUST be recomputed, not trusted as
descriptive metadata. The generation gate also resolves every listed path
inside the repository, rehashes the current raw bytes, and rejects a missing,
extra, stale, symlink-escaped, or duplicate entry.

The closure is semantic, not merely a convenient build-file list. It includes
the field implementation, constraint-program construction, program lookup,
fixed-table schemas, opcode manifest, typed builder/interpreter, serializer,
shared semantic sources, and the selected family's semantic sources. A
mutation of a constraint, selector, column order, lookup tuple, table schema,
access ordinal, or event append order MUST invalidate at least one source
digest or the rebuilt content digest.

## 10. Canonical JSON and digests

AIR IR v2 uses the integer-only repository canonical JSON subset:

- UTF-8 JSON with one top-level object;
- exact JSON types, with a Boolean never accepted as an integer;
- no floating point, exponent notation, `NaN`, infinity, negative zero, or
  out-of-range integer;
- ASCII member names, identifiers, mnemonics, and paths;
- object keys sorted lexicographically;
- array order preserved;
- standard minimal JSON string escaping with non-ASCII escaped;
- no insignificant whitespace; and
- no byte-order mark or trailing newline.

For values in this schema, the result is exactly equivalent to:

```python
json.dumps(
    value,
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
```

It MUST also byte-match Lean's compact encoding of the decoded value. A parser
first rejects duplicate keys at every depth, then validates the object, then
re-encodes it and requires byte identity with the input. Accepting a pretty,
noncanonical spelling and hashing its parsed value is not strict v2 decoding.

To calculate `content_digest`:

1. remove the top-level `content_digest` member entirely;
2. encode the remaining object using the canonical algorithm above;
3. compute SHA-256 of those bytes; and
4. encode the 32-byte digest as exactly 64 lowercase hexadecimal characters.

The final artifact is the complete object, including that digest, encoded
canonically. Table geometry and source-closure digests use the same canonical
algorithm on the preimages defined in sections 6 and 9.

## 11. Strict fail-closed decoding

Conformance requires all of the following checks. The JSON Schema is a useful
structural precheck, but cannot replace checks involving source files,
canonical bytes, array positions, graph reachability, or digest recomputation.

A decoder or production-binding gate MUST reject:

- malformed UTF-8/JSON, a non-object root, duplicate keys, noncanonical bytes,
  or an incorrect content digest;
- any missing or unknown member, wrong JSON type, Boolean/integer coercion,
  unsupported schema/kind/field, unknown family, or invalid manifest mapping;
- empty, duplicate, reordered, wrongly typed, or noncontiguous columns;
- an unknown node operation, wrong node shape/arity, invalid M31 constant,
  missing/duplicate column node, invalid column reference, forward/self
  reference, structurally duplicate node, or dead/unreferenced node;
- an invalid active-row, selector, event, projection, numerator, tuple, or
  next-PC reference;
- a missing, extra, duplicate, reordered, geometrically changed, or
  incorrectly digested fixed-table identity;
- an unknown lookup domain or role, invalid tuple arity, inconsistent
  `table_id`, unknown liveness rule, or statically dead lookup;
- a noncontiguous event ordinal, a constraint after the first lookup, a
  missing constraint/lookup class, or any event sequence that differs from
  fresh production construction;
- a zero, gapped, reordered, inferred, incomplete, or inconsistently assigned
  access ordinal;
- a projection to the wrong event kind/domain, a duplicated/reordered
  projection event, or selector metadata not carried by the program tuple;
- an unsafe, unsorted, duplicate, stale, incomplete, or incorrectly hashed
  source path/closure; and
- a rehashed mutation whose digest is not the expected production-generated
  digest pinned by the proof build or clean regeneration.

Unknown future operations, table IDs, liveness rules, roles, or domains require
a new reviewed schema version. They are not extension points inside v2.

## 12. Production and Lean interpretation

For a row vector `r`, production and Lean use the following common
interpretation:

1. evaluate every node in topological order over M31;
2. require `active_row = 1` and require `opcode_selector.expression` to equal
   the canonical M31 embedding of `opcode_selector.manifest_id` for the
   selector-specific active-row theorem;
3. require every constraint-event root to equal zero;
4. preserve every lookup event's exact numerator, role, domain, tuple,
   access ordinal, and event order;
5. for each live fixed-table event, require exact membership in section 6;
6. expose bus events as ordered relation tuples to the row-environment bridge;
   local interpretation does not assume global multiset closure; and
7. derive the program/state/source/destination tuples and next PC only through
   `projection`.

A zero numerator makes one lookup inactive; it does not make the row inactive
and does not delete the event. Numerator sign and value remain available to
the production LogUp interpretation even though local table liveness tests
only zero versus nonzero.

Production MUST evaluate the shared program rather than retain a parallel
hard-coded evaluator after export is introduced. Lean MUST decode every
supported node/event/table form and MUST fail before theorem construction on
invalid input. Python normalization, an SMT solver, or random differential
testing MUST NOT supply a semantic premise to the publication theorem.

## 13. Trusted base and deferred joint interfaces

The AIR-side claim relies on:

- the Lean kernel and pinned Lean toolchain/dependency lock;
- reviewed Lean M31, expression, event, fixed-table, strict-decoder, and
  projection definitions;
- the production typed program builder and its shared QM31/export
  interpretation path;
- the Zig compiler/build path when relating source to the shipped executable;
- strict canonical JSON and SHA-256 implementations, plus collision resistance
  when a digest substitutes for direct byte comparison; and
- reviewed completeness of the source-closure enumeration.

Generated JSON, Python orchestration, random differential trials, mutation
drivers, and external solver output are evidence or untrusted inputs, not
semantic authorities. The exported theorem audit permits only the
repository-declared foundational Lean axioms (`propext`, `Classical.choice`,
and `Quot.sound`). `sorry`, `admit`, theorem-local axioms, unchecked opaque
certificates, `native_decide` in the proof conclusion, or imported solver
claims fail the gate.

The complete normalized `Retirement` (including optional memory read and
masked memory write), complete `LocalRowEnv`, final architectural
row/relation-tuple theorem signatures, and their compatibility with generated
Sail are deliberately not invented by this Team A document. They are jointly
versioned Stage A0/B0 work with Team B under
[issue #137](https://github.com/teddyjfpender/stwo-zig/issues/137).

Likewise, this file records no fictional approval. Signed review by the Team A
AIR DRI, Team B Sail/profile DRI, LH representative, DIV representative, and
independent formal reviewer remains a joint #136/#137 exit requirement.

## 14. Implemented rollout gates

The first-PR LUI acceptance gate remains:

The first AIR IR v2 PR is accepted when focused checks demonstrate:

1. production constructs one typed LUI `ConstraintProgram`, and both shipped
   QM31 evaluation and serialization consume it;
2. serialization is canonical and byte-identical from an empty output
   directory;
3. the strict Lean path decodes the exact LUI artifact, interprets every node,
   constraint, lookup, fixed table, liveness condition, access ordinal, and
   projection, and evaluates focused active and inactive rows;
4. event-by-event comparison proves identical direct roots and lookup
   operands/order to the production program;
5. the LUI program tuple carries manifest ID `35`, mnemonic `lui`, family
   `lui`, and the exact selector expression;
6. source identity covers the transitive LUI/program/table/manifest slice and
   source mutations invalidate regeneration;
7. focused negative tests exercise the fail-closed classes in section 11,
   including a rehashed event reorder; and
8. the Lean build and axiom/proof-escape audit pass without a broad repository
   build.

That result may be described as:

> LUI's production AIR constraint program round-trips through AIR IR v2 and
> the strict Lean M31/event/table interpreter.

The subsequent Stage A1 rollout additionally requires:

1. all 17 production families are built through the same typed
   `ConstraintProgram` path;
2. exactly one artifact exists for each of the 46 manifest selectors;
3. each artifact carries the correct family, selector expression, manifest ID,
   mnemonic, relation-event projection, and per-family source closure;
4. strict validation and production-binding checks pass for all 46;
5. two clean exports are byte-identical; and
6. the shift-family construction order remains compatible with the reviewed
   Team B family digests.

Passing that gate may be described as deterministic, source-bound AIR IR v2
coverage for 17/17 families and 46/46 selectors. It is input coverage, not
opcode refinement coverage.

It MUST NOT be described as “LUI publication-proved,” “1/46,” or “2/46
publication-level opcodes.” Publication coverage additionally requires the
joint generated-Sail normalization theorem, complete retirement/environment
interfaces, row-to-Sail composition, non-vacuity, load-bearing mutation, axiom
audit, and reviewer signatures required by issues #136 and #137.
