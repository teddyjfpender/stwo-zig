import RiscvRefinement.Air
import RiscvRefinement.Air.Generated.LuiProgram

namespace RiscvRefinement.Air.Tests

open RiscvRefinement

private def zeroDigest : String :=
  "0000000000000000000000000000000000000000000000000000000000000000"

/--
A deliberately small, fully reachable AIR program.  It exercises every v2
expression constructor and projects one ordered `program_access` tuple.
-/
def exampleProgram : ConstraintProgram where
  schemaVersion := 2
  kind := "stwo-riscv-air-constraint-program"
  field := { name := "M31", modulus := M31.modulus }
  family := .lui
  columns := #[
    { index := 0, name := "left", role := .input },
    { index := 1, name := "right", role := .witness }
  ]
  nodes := #[
    .column 0,
    .column 1,
    .const 1,
    .const (M31.reduce 35),
    .add 0 2,
    .sub 4 2,
    .mul 5 1,
    .neg 6
  ]
  activeRow := 2
  opcodeSelector := {
    manifestId := 35
    mnemonic := "lui"
    expression := 3
  }
  fixedTables := FixedTableId.all.map FixedTableIdentity.expected
  events := #[
    .constraint { ordinal := 0, root := 7 },
    .lookup {
      ordinal := 1
      domain := .programAccess
      numerator := 2
      tuple := #[0, 3, 4, 5, 6]
      role := .request
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    },
    .lookup {
      ordinal := 2
      domain := .registersState
      numerator := 2
      tuple := #[4, 0]
      role := .consume
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    },
    .lookup {
      ordinal := 3
      domain := .registersState
      numerator := 2
      tuple := #[4, 1]
      role := .emit
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  ]
  projection := {
    programEvent := 1
    stateEvents := #[2, 3]
    sourceEvents := #[]
    destinationEvents := #[]
    nextPc := 4
  }
  sourceIdentity := {
    builder := productionBuilder
    sourceClosureSha256 := zeroDigest
    files := luiSourcePaths.map fun path => { path, sha256 := zeroDigest }
  }
  contentDigest := zeroDigest

private def accepted {α ε : Type} : Except ε α → Bool
  | .ok _ => true
  | .error _ => false

private def rejected {α ε : Type} (result : Except ε α) : Bool :=
  !accepted result

def exampleJson : String :=
  exampleProgram.canonicalJson

#guard accepted (ConstraintProgram.decodeCanonical exampleJson)
#guard rejected (ConstraintProgram.decodeCanonical (exampleJson ++ "\n"))

-- Duplicate keys are overwritten by the JSON parser but fail reserialization.
private def duplicateKeyJson : String :=
  exampleJson.replace
    "{\"active_row\":2,"
    "{\"active_row\":2,\"active_row\":2,"

#guard rejected (ConstraintProgram.decodeCanonical duplicateKeyJson)

-- Constants on the wire are canonical representatives, never reduced inputs.
private def invalidConstantJson : String :=
  exampleJson.replace
    "{\"op\":\"const\",\"value\":1}"
    "{\"op\":\"const\",\"value\":2147483647}"

#guard rejected (ConstraintProgram.decodeCanonical invalidConstantJson)

private def booleanNodeReferenceJson : String :=
  exampleJson.replace
    "\"active_row\":2"
    "\"active_row\":true"

#guard rejected (ConstraintProgram.decodeCanonical booleanNodeReferenceJson)

-- The decoder also rejects unknown nested members before semantic evaluation.
private def unknownColumnFieldJson : String :=
  exampleJson.replace
    "{\"index\":0,"
    "{\"extra\":0,\"index\":0,"

#guard rejected (ConstraintProgram.decodeCanonical unknownColumnFieldJson)

private def unknownOperationJson : String :=
  exampleJson.replace
    "{\"args\":[0,2],\"op\":\"add\"}"
    "{\"args\":[0,2],\"op\":\"unknown\"}"

#guard rejected (ConstraintProgram.decodeCanonical unknownOperationJson)

private def forwardReferenceJson : String :=
  exampleJson.replace
    "{\"args\":[0,2],\"op\":\"add\"}"
    "{\"args\":[0,99],\"op\":\"add\"}"

#guard rejected (ConstraintProgram.decodeCanonical forwardReferenceJson)

private def duplicateNodeProgram : ConstraintProgram :=
  { exampleProgram with nodes := exampleProgram.nodes.push (.const 1) }

#guard rejected (ConstraintProgram.decodeCanonical duplicateNodeProgram.canonicalJson)

private def staticNonBooleanActiveProgram : ConstraintProgram :=
  { exampleProgram with
    nodes := exampleProgram.nodes.push (.const (M31.reduce 2))
    activeRow := 8 }

#guard rejected
  (ConstraintProgram.decodeCanonical staticNonBooleanActiveProgram.canonicalJson)

private def unreachableNodeProgram : ConstraintProgram :=
  { exampleProgram with nodes := exampleProgram.nodes.push (.const (M31.reduce 2)) }

#guard rejected (ConstraintProgram.decodeCanonical unreachableNodeProgram.canonicalJson)

private def deadLookupProgram : ConstraintProgram :=
  { exampleProgram with
    nodes := exampleProgram.nodes.push (.const 0)
    events := exampleProgram.events.map fun
      | .constraint event => .constraint event
      | .lookup event => .lookup { event with numerator := 8 } }

#guard rejected (ConstraintProgram.decodeCanonical deadLookupProgram.canonicalJson)

private def badTableProgram : ConstraintProgram :=
  { exampleProgram with
    fixedTables := exampleProgram.fixedTables.map fun table =>
      if table.id == .bitwise then { table with logSize := 19 } else table }

#guard rejected (ConstraintProgram.decodeCanonical badTableProgram.canonicalJson)

private def noncontiguousEventProgram : ConstraintProgram :=
  { exampleProgram with
    events := exampleProgram.events.map fun
      | .constraint event => .constraint { event with ordinal := 1 }
      | .lookup event => .lookup event }

#guard rejected (ConstraintProgram.decodeCanonical noncontiguousEventProgram.canonicalJson)

private def reorderedEventProgram : ConstraintProgram :=
  { exampleProgram with
    events := #[
      .lookup {
        ordinal := 0
        domain := .programAccess
        numerator := 2
        tuple := #[0, 3, 4, 5, 6]
        role := .request
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      },
      .constraint { ordinal := 1, root := 7 },
      .lookup {
        ordinal := 2
        domain := .registersState
        numerator := 2
        tuple := #[4, 0]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      },
      .lookup {
        ordinal := 3
        domain := .registersState
        numerator := 2
        tuple := #[4, 1]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }
    ] }

#guard rejected (ConstraintProgram.decodeCanonical reorderedEventProgram.canonicalJson)

private def reorderedProjectionProgram : ConstraintProgram :=
  { exampleProgram with
    projection := { exampleProgram.projection with stateEvents := #[3, 2] } }

#guard rejected (ConstraintProgram.decodeCanonical reorderedProjectionProgram.canonicalJson)

private def mismatchedSelectorProgram : ConstraintProgram :=
  { exampleProgram with
    opcodeSelector := { exampleProgram.opcodeSelector with manifestId := 34 } }

#guard rejected (ConstraintProgram.decodeCanonical mismatchedSelectorProgram.canonicalJson)

private def unsafeSourcePathProgram : ConstraintProgram :=
  { exampleProgram with
    sourceIdentity := {
      exampleProgram.sourceIdentity with
      builder := "../program.zig"
      files := #[{
        path := "../program.zig"
        sha256 := zeroDigest
      }]
    } }

#guard rejected (ConstraintProgram.decodeCanonical unsafeSourcePathProgram.canonicalJson)

private def incompleteSourceClosureProgram : ConstraintProgram :=
  { exampleProgram with
    sourceIdentity := {
      exampleProgram.sourceIdentity with
      files := exampleProgram.sourceIdentity.files.pop
    } }

#guard rejected
  (ConstraintProgram.decodeCanonical incompleteSourceClosureProgram.canonicalJson)

private def accessOrdinalStartsAtTwoJson : String :=
  Generated.luiProgramJson.replace
    "\"access_ordinal\":1"
    "\"access_ordinal\":2"

#guard rejected (ConstraintProgram.decodeCanonical accessOrdinalStartsAtTwoJson)

private def incompleteAccessGroupJson : String :=
  Generated.luiProgramJson.replace
    "\"ordinal\":14,\"role\":\"emit\""
    "\"ordinal\":14,\"role\":\"consume\""

#guard rejected (ConstraintProgram.decodeCanonical incompleteAccessGroupJson)

private def evaluationAccepted : Bool :=
  match exampleProgram.eval #[0, 0] with
  | .error _ => false
  | .ok evaluation =>
      evaluation.rowActive &&
      evaluation.constraintsHold &&
      evaluation.fixedLookupsHold &&
      evaluation.activeSelectorsAccepted &&
      evaluation.liveLookups.size == 3 &&
      evaluation.projection.programEvent.tuple.map M31.toNat == #[0, 35, 1, 0, 0]

#guard evaluationAccepted

private def m31 (value : Nat) : M31 :=
  M31.reduce value

-- Executable examples pin all six fixed-table meanings.
#guard FixedTableId.bitwise.contains [m31 0xaa, m31 0x55, m31 0xff, m31 2]
#guard FixedTableId.rangeCheck20.contains [m31 ((2 ^ 20) - 1)]
#guard FixedTableId.rangeCheck811.contains [m31 255, m31 2047]
#guard FixedTableId.rangeCheck884.contains [m31 255, m31 255, m31 15]
#guard FixedTableId.rangeCheck88.contains [m31 255, m31 255]
#guard FixedTableId.rangeCheckM31.contains [m31 254, m31 127]
#guard !FixedTableId.rangeCheckM31.contains [m31 255, m31 127]

#guard M31.ofNat? (M31.modulus - 1) |>.isSome
#guard !(M31.ofNat? M31.modulus).isSome
#guard !(M31.ofInt? (-1)).isSome

end RiscvRefinement.Air.Tests
