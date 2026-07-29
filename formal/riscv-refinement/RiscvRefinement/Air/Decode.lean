import Lean.Data.Json
import RiscvRefinement.Air.Eval

namespace RiscvRefinement.Air

open Lean
open RiscvRefinement

private abbrev JsonObject :=
  Std.TreeMap.Raw String Json compare

private def decodeFailure {α : Type} (context message : String) : Except String α :=
  .error s!"{context}: {message}"

private def exactObject
    (context : String)
    (keys : List String)
    (json : Json) :
    Except String JsonObject := do
  let object ←
    match json.getObj? with
    | .ok value => .ok value
    | .error _ => decodeFailure context "expected an object"
  if object.size != keys.length || !keys.all object.contains then
    decodeFailure context s!"object keys must be exactly {repr keys}"
  else
    .ok object

private def member
    (context : String)
    (object : JsonObject)
    (key : String) :
    Except String Json :=
  match object.get? key with
  | some value => .ok value
  | none => decodeFailure context s!"missing field {key}"

private def jsonString (context : String) (json : Json) : Except String String :=
  match json.getStr? with
  | .ok value => .ok value
  | .error _ => decodeFailure context "expected a string"

private def jsonNat (context : String) (json : Json) : Except String Nat :=
  match json.getNat? with
  | .ok value => .ok value
  | .error _ => decodeFailure context "expected a natural number"

private def jsonArray (context : String) (json : Json) : Except String (Array Json) :=
  match json.getArr? with
  | .ok value => .ok value
  | .error _ => decodeFailure context "expected an array"

private def decodeArray
    (context : String)
    (decode : Nat → Json → Except String α)
    (json : Json) :
    Except String (Array α) := do
  let values ← jsonArray context json
  (Array.range values.size).mapM fun index =>
    decode index values[index]!

private def isAsciiLetter (character : Char) : Bool :=
  decide ('a' ≤ character ∧ character ≤ 'z') ||
  decide ('A' ≤ character ∧ character ≤ 'Z')

private def isAsciiDigit (character : Char) : Bool :=
  decide ('0' ≤ character ∧ character ≤ '9')

private def isIdentifierStart (character : Char) : Bool :=
  isAsciiLetter character || character == '_'

private def isIdentifierRest (character : Char) : Bool :=
  isIdentifierStart character || isAsciiDigit character

private def isAsciiIdentifier (value : String) : Bool :=
  match value.toList with
  | [] => false
  | first :: rest => isIdentifierStart first && rest.all isIdentifierRest

private def isLowerHex (character : Char) : Bool :=
  isAsciiDigit character || decide ('a' ≤ character ∧ character ≤ 'f')

private def isSha256 (value : String) : Bool :=
  value.length == 64 && value.toList.all isLowerHex

private def isPathCharacter (character : Char) : Bool :=
  isAsciiLetter character ||
  isAsciiDigit character ||
  ['_', '-', '.', '/'].contains character

private def isNormalizedRelativePath (path : String) : Bool :=
  !path.isEmpty &&
  !path.startsWith "/" &&
  path.toList.all isPathCharacter &&
  (path.splitOn "/").all fun segment =>
    !segment.isEmpty && segment != "." && segment != ".."

private def uniqueStrings : List String → Bool
  | [] => true
  | value :: rest => !rest.contains value && uniqueStrings rest

private def strictlySortedFiles : List SourceFileIdentity → Bool
  | [] | [_] => true
  | first :: second :: rest =>
      decide (first.path < second.path) && strictlySortedFiles (second :: rest)

private def decodeColumn (index : Nat) (json : Json) : Except String Column := do
  let context := s!"columns[{index}]"
  let object ← exactObject context ["index", "name", "role", "type", "width"] json
  let wireIndex ← jsonNat (context ++ ".index") (← member context object "index")
  if wireIndex != index then
    decodeFailure context s!"index must be the contiguous array position {index}"
  let name ← jsonString (context ++ ".name") (← member context object "name")
  if !isAsciiIdentifier name then
    decodeFailure context "name must be a nonempty ASCII identifier"
  let roleName ← jsonString (context ++ ".role") (← member context object "role")
  let role ←
    match ColumnRole.ofWireName? roleName with
    | some role => .ok role
    | none => decodeFailure context s!"unknown column role {roleName}"
  let fieldType ← jsonString (context ++ ".type") (← member context object "type")
  if fieldType != "m31" then
    decodeFailure context "type must be m31"
  let width ← jsonNat (context ++ ".width") (← member context object "width")
  if width != 1 then
    decodeFailure context "width must be 1"
  return { index, name, role }

private def nodeReference
    (context : String)
    (upperBound : Nat)
    (json : Json) :
    Except String NodeId := do
  let reference ← jsonNat context json
  if reference < upperBound then
    return reference
  else
    decodeFailure context s!"forward or out-of-range node reference {reference}"

private def nodeArguments
    (context : String)
    (arity upperBound : Nat)
    (json : Json) :
    Except String (Array NodeId) := do
  let arguments ← jsonArray context json
  if arguments.size != arity then
    decodeFailure context s!"operation requires exactly {arity} arguments"
  (Array.range arguments.size).mapM fun index =>
    nodeReference s!"{context}[{index}]" upperBound arguments[index]!

private def decodeNode
    (columnCount index : Nat)
    (json : Json) :
    Except String ExprNode := do
  let context := s!"nodes[{index}]"
  let rawObject ←
    match json.getObj? with
    | .ok object => .ok object
    | .error _ => decodeFailure context "expected an object"
  let operation ← jsonString (context ++ ".op") (← member context rawObject "op")
  match operation with
  | "const" =>
      let object ← exactObject context ["op", "value"] json
      let value ← jsonNat (context ++ ".value") (← member context object "value")
      match M31.ofNat? value with
      | some canonical => return .const canonical
      | none => decodeFailure context s!"constant must be smaller than {M31.modulus}"
  | "col" =>
      let object ← exactObject context ["column", "op"] json
      let column ← jsonNat (context ++ ".column") (← member context object "column")
      if column < columnCount then
        return .column column
      else
        decodeFailure context s!"column reference {column} is out of range"
  | "neg" =>
      let object ← exactObject context ["args", "op"] json
      let arguments ← nodeArguments (context ++ ".args") 1 index (← member context object "args")
      return .neg arguments[0]!
  | "add" | "sub" | "mul" =>
      let object ← exactObject context ["args", "op"] json
      let arguments ← nodeArguments (context ++ ".args") 2 index (← member context object "args")
      let left := arguments[0]!
      let right := arguments[1]!
      match operation with
      | "add" => return .add left right
      | "sub" => return .sub left right
      | _ => return .mul left right
  | _ => decodeFailure context s!"unknown expression operation {operation}"

private def uniqueNodes : List ExprNode → Bool
  | [] => true
  | node :: rest => !rest.contains node && uniqueNodes rest

private def ExprNode.staticEval
    (values : Array (Option M31)) :
    ExprNode → Option M31
  | .const value => some value
  | .column _ => none
  | .add left right =>
      return (← (values[left]?).bind id) + (← (values[right]?).bind id)
  | .sub left right =>
      return (← (values[left]?).bind id) - (← (values[right]?).bind id)
  | .mul left right =>
      return (← (values[left]?).bind id) * (← (values[right]?).bind id)
  | .neg value => return -(← (values[value]?).bind id)

private def staticNodeValues (nodes : Array ExprNode) : Array (Option M31) :=
  nodes.foldl (init := #[]) fun values node =>
    values.push (node.staticEval values)

private def decodeField (json : Json) : Except String FieldIdentity := do
  let context := "field"
  let object ← exactObject context ["modulus", "name"] json
  let name ← jsonString "field.name" (← member context object "name")
  if name != "M31" then
    decodeFailure context "name must be M31"
  let modulus ← jsonNat "field.modulus" (← member context object "modulus")
  if modulus != M31.modulus then
    decodeFailure context s!"modulus must be {M31.modulus}"
  return { name, modulus }

private def decodeOpcodeSelector
    (nodeCount : Nat)
    (json : Json) :
    Except String OpcodeSelector := do
  let context := "opcode_selector"
  let object ← exactObject context ["expression", "manifest_id", "mnemonic"] json
  let manifestId ← jsonNat (context ++ ".manifest_id") (← member context object "manifest_id")
  let mnemonic ← jsonString (context ++ ".mnemonic") (← member context object "mnemonic")
  if !isAsciiIdentifier mnemonic then
    decodeFailure context "mnemonic must be a nonempty ASCII identifier"
  let expression ← nodeReference (context ++ ".expression") nodeCount
    (← member context object "expression")
  return { manifestId, mnemonic, expression }

private def decodeFamily (json : Json) : Except String Family := do
  let name ← jsonString "family" json
  match Family.ofWireName? name with
  | some family => return family
  | none => decodeFailure "family" s!"unknown production family {name}"

private def decodeDomain (context : String) (json : Json) : Except String Domain := do
  let name ← jsonString context json
  match Domain.ofWireName? name with
  | some domain => return domain
  | none => decodeFailure context s!"unknown lookup domain {name}"

private def decodeTableId
    (context : String)
    (json : Json) :
    Except String (Option FixedTableId) :=
  match json with
  | .null => .ok none
  | .str name =>
      match FixedTableId.ofWireName? name with
      | some table => .ok (some table)
      | none => decodeFailure context s!"unknown fixed-table identity {name}"
  | _ => decodeFailure context "expected a fixed-table identity or null"

private def decodeLookupRole
    (context : String)
    (json : Json) :
    Except String LookupRole := do
  let name ← jsonString context json
  match LookupRole.ofWireName? name with
  | some role => return role
  | none => decodeFailure context s!"unknown lookup role {name}"

private def decodeFixedTable
    (index : Nat)
    (json : Json) :
    Except String FixedTableIdentity := do
  let context := s!"fixed_tables[{index}]"
  let object ← exactObject context
    ["arity", "domain", "id", "log_size", "schema_sha256"] json
  let idName ← jsonString (context ++ ".id") (← member context object "id")
  let id ←
    match FixedTableId.ofWireName? idName with
    | some value => .ok value
    | none => decodeFailure context s!"unknown fixed-table identity {idName}"
  let domain ← decodeDomain (context ++ ".domain") (← member context object "domain")
  let arity ← jsonNat (context ++ ".arity") (← member context object "arity")
  let logSize ← jsonNat (context ++ ".log_size") (← member context object "log_size")
  let schemaSha256 ←
    jsonString (context ++ ".schema_sha256") (← member context object "schema_sha256")
  if !isSha256 schemaSha256 then
    decodeFailure context "schema_sha256 must be 64 lowercase hexadecimal characters"
  let identity : FixedTableIdentity := { id, domain, arity, logSize, schemaSha256 }
  let expectedId ←
    match FixedTableId.all[index]? with
    | some value => .ok value
    | none => decodeFailure context "the v2 program has exactly six fixed tables"
  if identity != FixedTableIdentity.expected expectedId then
    decodeFailure context "fixed-table identity, order, or schema digest is invalid"
  return identity

private def decodeOptionalNat (context : String) (json : Json) :
    Except String (Option Nat) :=
  match json with
  | .null => .ok none
  | value => some <$> jsonNat context value

private def decodeNodeIdArray
    (context : String)
    (nodeCount : Nat)
    (json : Json) :
    Except String (Array NodeId) := do
  let values ← jsonArray context json
  (Array.range values.size).mapM fun index =>
    nodeReference s!"{context}[{index}]" nodeCount values[index]!

private def decodeEvent
    (nodes : Array ExprNode)
    (staticValues : Array (Option M31))
    (index : Nat)
    (json : Json) :
    Except String Event := do
  let context := s!"events[{index}]"
  let rawObject ←
    match json.getObj? with
    | .ok object => .ok object
    | .error _ => decodeFailure context "expected an object"
  let kind ← jsonString (context ++ ".kind") (← member context rawObject "kind")
  match kind with
  | "constraint" =>
      let object ← exactObject context ["kind", "ordinal", "root"] json
      let ordinal ← jsonNat (context ++ ".ordinal") (← member context object "ordinal")
      if ordinal != index then
        decodeFailure context s!"ordinal must be the contiguous array position {index}"
      let root ← nodeReference (context ++ ".root") nodes.size (← member context object "root")
      return .constraint { ordinal, root }
  | "lookup" =>
      let object ← exactObject context
        ["access_ordinal", "domain", "kind", "liveness", "numerator", "ordinal",
          "role", "table_id", "tuple"] json
      let ordinal ← jsonNat (context ++ ".ordinal") (← member context object "ordinal")
      if ordinal != index then
        decodeFailure context s!"ordinal must be the contiguous array position {index}"
      let domain ← decodeDomain (context ++ ".domain") (← member context object "domain")
      let numerator ← nodeReference (context ++ ".numerator") nodes.size
        (← member context object "numerator")
      if staticValues[numerator]? = some (some 0) then
        decodeFailure context "lookup numerator is statically zero (dead request)"
      let tuple ← decodeNodeIdArray (context ++ ".tuple") nodes.size
        (← member context object "tuple")
      if tuple.size != domain.arity then
        decodeFailure context s!"domain requires tuple arity {domain.arity}"
      let role ← decodeLookupRole (context ++ ".role") (← member context object "role")
      let tableId ← decodeTableId (context ++ ".table_id") (← member context object "table_id")
      if tableId != domain.fixedTable? then
        decodeFailure context "table_id must equal the fixed domain, and must be null for bus domains"
      let livenessName ← jsonString (context ++ ".liveness")
        (← member context object "liveness")
      if livenessName != "nonzero_numerator" then
        decodeFailure context s!"unknown lookup liveness {livenessName}"
      let accessOrdinal ← decodeOptionalNat (context ++ ".access_ordinal")
        (← member context object "access_ordinal")
      match domain with
      | .registersState =>
          if role == .request then
            decodeFailure context "registers_state role must be consume or emit"
          if accessOrdinal.isSome then
            decodeFailure context "registers_state access_ordinal must be null"
      | .memoryAccess =>
          if role == .request then
            decodeFailure context "memory_access role must be consume or emit"
          match accessOrdinal with
          | some ordinal =>
              if ordinal == 0 then
                decodeFailure context "access_ordinal must be positive"
          | none =>
              decodeFailure context "memory_access requires an explicit access_ordinal"
      | .rangeCheck20 =>
          if role != .request then
            decodeFailure context "fixed-table role must be request"
          match accessOrdinal with
          | some ordinal =>
              if ordinal == 0 then
                decodeFailure context "access_ordinal must be positive"
          | none => pure ()
      | .bitwise | .rangeCheck811 | .rangeCheck884 | .rangeCheck88 | .rangeCheckM31 =>
          if role != .request then
            decodeFailure context "fixed-table role must be request"
          if accessOrdinal.isSome then
            decodeFailure context "this fixed-table access_ordinal must be null"
      | .programAccess | .merkle | .poseidon2 | .poseidon2Io =>
          if role != .request then
            decodeFailure context "request-only domain has a non-request role"
          if accessOrdinal.isSome then
            decodeFailure context "request-only domain access_ordinal must be null"
      return .lookup {
        ordinal
        domain
        numerator
        tuple
        role
        tableId
        liveness := .nonzeroNumerator
        accessOrdinal
      }
  | _ => decodeFailure context s!"unknown event kind {kind}"

private def constraintsThenLookups : List Event → Bool
  | [] => true
  | .constraint _ :: rest => constraintsThenLookups rest
  | .lookup _ :: rest => rest.all fun
      | .lookup _ => true
      | .constraint _ => false

private def validateAccessGroups
    (events : List Event)
    (nextOrdinal : Nat := 1) :
    Except String Unit :=
  match events with
  | [] => .ok ()
  | .constraint _ :: rest => validateAccessGroups rest nextOrdinal
  | .lookup event :: rest =>
      match event.accessOrdinal with
      | none => validateAccessGroups rest nextOrdinal
      | some ordinal => do
          if ordinal != nextOrdinal ||
              event.domain != .memoryAccess ||
              event.role != .consume then
            decodeFailure s!"events[{event.ordinal}]"
              "an access group must start with the next memory_access consume"
          match rest with
          | .lookup emitted :: .lookup gap :: tail =>
              if emitted.domain != .memoryAccess ||
                  emitted.role != .emit ||
                  emitted.accessOrdinal != some ordinal then
                decodeFailure s!"events[{emitted.ordinal}]"
                  "the second access-group event must be memory_access emit"
              if gap.domain != .rangeCheck20 ||
                  gap.role != .request ||
                  gap.accessOrdinal != some ordinal then
                decodeFailure s!"events[{gap.ordinal}]"
                  "the third access-group event must be range_check_20 request"
              validateAccessGroups tail (nextOrdinal + 1)
          | _ =>
              decodeFailure s!"events[{event.ordinal}]"
                "an access group must contain consume, emit, and clock-gap events"

private def decodeEventOrdinalArray
    (context : String)
    (json : Json) :
    Except String (Array EventOrdinal) := do
  let values ← jsonArray context json
  (Array.range values.size).mapM fun index =>
    jsonNat s!"{context}[{index}]" values[index]!

private def decodeProjection
    (nodeCount : Nat)
    (json : Json) :
    Except String Projection := do
  let context := "projection"
  let object ← exactObject context
    ["destination_events", "next_pc", "program_event", "source_events", "state_events"] json
  let programEvent ← jsonNat (context ++ ".program_event")
    (← member context object "program_event")
  let stateEvents ← decodeEventOrdinalArray (context ++ ".state_events")
    (← member context object "state_events")
  let sourceEvents ← decodeEventOrdinalArray (context ++ ".source_events")
    (← member context object "source_events")
  let destinationEvents ← decodeEventOrdinalArray (context ++ ".destination_events")
    (← member context object "destination_events")
  let nextPc ← nodeReference (context ++ ".next_pc") nodeCount
    (← member context object "next_pc")
  return { programEvent, stateEvents, sourceEvents, destinationEvents, nextPc }

private def decodeSourceFile
    (index : Nat)
    (json : Json) :
    Except String SourceFileIdentity := do
  let context := s!"source_identity.files[{index}]"
  let object ← exactObject context ["path", "sha256"] json
  let path ← jsonString (context ++ ".path") (← member context object "path")
  if !isNormalizedRelativePath path then
    decodeFailure context "path must be a normalized relative ASCII POSIX path"
  let sha256 ← jsonString (context ++ ".sha256") (← member context object "sha256")
  if !isSha256 sha256 then
    decodeFailure context "sha256 must be 64 lowercase hexadecimal characters"
  return { path, sha256 }

private def decodeSourceIdentity (json : Json) : Except String SourceIdentity := do
  let context := "source_identity"
  let object ← exactObject context ["builder", "files", "source_closure_sha256"] json
  let builder ← jsonString (context ++ ".builder") (← member context object "builder")
  if !isNormalizedRelativePath builder then
    decodeFailure context "builder must be a normalized relative ASCII POSIX path"
  let sourceClosureSha256 ← jsonString (context ++ ".source_closure_sha256")
    (← member context object "source_closure_sha256")
  if !isSha256 sourceClosureSha256 then
    decodeFailure context "source_closure_sha256 must be 64 lowercase hexadecimal characters"
  let files ← decodeArray (context ++ ".files") decodeSourceFile
    (← member context object "files")
  if files.isEmpty then
    decodeFailure context "files must not be empty"
  if !strictlySortedFiles files.toList then
    decodeFailure context "files must be unique and strictly sorted by path"
  if !(files.toList.map (·.path)).contains builder then
    decodeFailure context "builder must name one of the source_identity files"
  return { builder, sourceClosureSha256, files }

private def lookupAt?
    (events : Array Event)
    (ordinal : EventOrdinal) :
    Option LookupEvent :=
  match events[ordinal]? with
  | some (.lookup event) => some event
  | _ => none

private def projectionLookup
    (context : String)
    (events : Array Event)
    (ordinal : EventOrdinal) :
    Except String LookupEvent :=
  match lookupAt? events ordinal with
  | some event => .ok event
  | none => decodeFailure context s!"ordinal {ordinal} must reference a lookup event"

private def uniqueNats : List Nat → Bool
  | [] => true
  | value :: rest => !rest.contains value && uniqueNats rest

private def strictlyIncreasingNats : List Nat → Bool
  | [] | [_] => true
  | first :: second :: rest =>
      decide (first < second) && strictlyIncreasingNats (second :: rest)

private def validateMemoryProjection
    (context : String)
    (events : Array Event) :
    List EventOrdinal → Except String Unit
  | [] => .ok ()
  | consumeOrdinal :: emitOrdinal :: rest => do
      let consume ← projectionLookup context events consumeOrdinal
      let emit ← projectionLookup context events emitOrdinal
      if consume.domain != .memoryAccess || consume.role != .consume then
        decodeFailure context s!"ordinal {consumeOrdinal} must be memory_access consume"
      if emit.domain != .memoryAccess || emit.role != .emit then
        decodeFailure context s!"ordinal {emitOrdinal} must be memory_access emit"
      if emitOrdinal != consumeOrdinal + 1 ||
          consume.accessOrdinal.isNone ||
          emit.accessOrdinal != consume.accessOrdinal then
        decodeFailure context "consume/emit must be one adjacent architectural access pair"
      validateMemoryProjection context events rest
  | [_] => decodeFailure context "memory projections must contain consume/emit pairs"

private def validateProjection
    (events : Array Event)
    (projection : Projection) :
    Except String Unit := do
  let program ← projectionLookup "projection.program_event" events projection.programEvent
  if program.domain != .programAccess || program.role != .request then
    decodeFailure "projection.program_event" "must reference the program_access request"

  let allProgramEvents := events.filterMap fun
    | .lookup event => if event.domain == .programAccess then some event.ordinal else none
    | _ => none
  if allProgramEvents != #[projection.programEvent] then
    decodeFailure "projection.program_event" "must identify the unique program_access event"

  if projection.stateEvents.size != 2 then
    decodeFailure "projection.state_events"
      "must contain exactly the registers_state consume and emit events"
  let stateConsumeOrdinal := projection.stateEvents[0]!
  let stateEmitOrdinal := projection.stateEvents[1]!
  let stateConsume ← projectionLookup "projection.state_events" events stateConsumeOrdinal
  let stateEmit ← projectionLookup "projection.state_events" events stateEmitOrdinal
  if stateConsume.domain != .registersState || stateConsume.role != .consume ||
      stateEmit.domain != .registersState || stateEmit.role != .emit then
    decodeFailure "projection.state_events"
      "must be ordered registers_state consume then emit"
  if stateEmit.tuple[0]? != some projection.nextPc then
    decodeFailure "projection.next_pc"
      "must be the first tuple node of the projected registers_state emit"

  let allStateEvents := events.filterMap fun
    | .lookup event => if event.domain == .registersState then some event.ordinal else none
    | _ => none
  if allStateEvents != projection.stateEvents then
    decodeFailure "projection.state_events" "must identify every registers_state event"

  validateMemoryProjection "projection.source_events" events projection.sourceEvents.toList
  validateMemoryProjection "projection.destination_events" events
    projection.destinationEvents.toList

  for (name, ordinals) in
      [("state_events", projection.stateEvents),
       ("source_events", projection.sourceEvents),
       ("destination_events", projection.destinationEvents)] do
    if !strictlyIncreasingNats ordinals.toList then
      decodeFailure s!"projection.{name}" "event ordinals must preserve production order"

  let projectedMemory := projection.sourceEvents.toList ++ projection.destinationEvents.toList
  let allMemory := (events.filterMap fun
    | .lookup event => if event.domain == .memoryAccess then some event.ordinal else none
    | _ => none).toList
  if !allMemory.all projectedMemory.contains || !projectedMemory.all allMemory.contains then
    decodeFailure "projection"
      "source_events and destination_events must classify every memory_access event"

  let allProjected :=
    projection.programEvent ::
    (projection.stateEvents.toList ++ projectedMemory)
  if !uniqueNats allProjected then
    decodeFailure "projection" "projected event arrays must not overlap or contain duplicates"

private def ExprNode.references : ExprNode → List NodeId
  | .const _ | .column _ => []
  | .neg value => [value]
  | .add left right | .sub left right | .mul left right => [left, right]

private def Event.nodeRoots : Event → List NodeId
  | .constraint event => [event.root]
  | .lookup event => event.numerator :: event.tuple.toList

private def validateReachability
    (program : ConstraintProgram) :
    Except String Unit := do
  let internalReferences :=
    program.nodes.toList.flatMap ExprNode.references
  let roots :=
    [program.activeRow, program.opcodeSelector.expression, program.projection.nextPc] ++
    program.events.toList.flatMap Event.nodeRoots
  let references := internalReferences ++ roots
  for node in Array.range program.nodes.size do
    if !references.contains node then
      decodeFailure s!"nodes[{node}]" "node is not reachable from a semantic root"

/-- Decode a parsed JSON value and enforce every semantic invariant of AIR IR v2. -/
def ConstraintProgram.fromJson? (json : Json) : Except String ConstraintProgram := do
  let context := "constraint_program"
  let object ← exactObject context
    ["active_row", "columns", "content_digest", "events", "family", "field",
      "fixed_tables", "kind", "nodes", "opcode_selector", "projection",
      "schema_version", "source_identity"] json

  let schemaVersion ← jsonNat "schema_version" (← member context object "schema_version")
  if schemaVersion != 2 then
    decodeFailure context "schema_version must be 2"
  let kind ← jsonString "kind" (← member context object "kind")
  if kind != "stwo-riscv-air-constraint-program" then
    decodeFailure context "kind is not stwo-riscv-air-constraint-program"
  let field ← decodeField (← member context object "field")
  let family ← decodeFamily (← member context object "family")

  let columns ← decodeArray "columns" decodeColumn (← member context object "columns")
  if columns.isEmpty then
    decodeFailure context "columns must not be empty"
  if !uniqueStrings (columns.toList.map (·.name)) then
    decodeFailure context "column names must be unique"

  let rawNodes ← jsonArray "nodes" (← member context object "nodes")
  let nodes ← (Array.range rawNodes.size).mapM fun index =>
    decodeNode columns.size index rawNodes[index]!
  if nodes.isEmpty then
    decodeFailure context "nodes must not be empty"
  if !uniqueNodes nodes.toList then
    decodeFailure context "nodes must be structurally hash-consed"
  for column in Array.range columns.size do
    if !nodes.toList.contains (.column column) then
      decodeFailure s!"columns[{column}]"
        "every declared column must have exactly one hash-consed col node"
  let staticValues := staticNodeValues nodes

  let activeRow ← nodeReference "active_row" nodes.size (← member context object "active_row")
  if staticValues[activeRow]? = some (some 0) then
    decodeFailure context "active_row must not be statically zero"
  let opcodeSelector ← decodeOpcodeSelector nodes.size
    (← member context object "opcode_selector")
  if staticValues[opcodeSelector.expression]? = some (some 0) then
    decodeFailure context "opcode selector must not be statically zero"
  if !family.validOpcode opcodeSelector.manifestId opcodeSelector.mnemonic then
    decodeFailure context
      "opcode_selector manifest_id/mnemonic does not belong to the declared family"

  let fixedTables ← decodeArray "fixed_tables" decodeFixedTable
    (← member context object "fixed_tables")
  if fixedTables.size != FixedTableId.all.size then
    decodeFailure context "fixed_tables must contain all six identities exactly once"

  let events ← decodeArray "events" (decodeEvent nodes staticValues)
    (← member context object "events")
  if !constraintsThenLookups events.toList then
    decodeFailure context "all constraint events must precede all lookup events"
  if !events.any (fun event => match event with | .constraint _ => true | _ => false) then
    decodeFailure context "events must have a nonempty constraint prefix"
  if !events.any (fun event => match event with | .lookup _ => true | _ => false) then
    decodeFailure context "events must have a nonempty lookup suffix"
  validateAccessGroups events.toList

  let projection ← decodeProjection nodes.size (← member context object "projection")
  validateProjection events projection
  let programLookup ← projectionLookup "projection.program_event" events
    projection.programEvent
  if programLookup.tuple[1]? != some opcodeSelector.expression then
    decodeFailure "opcode_selector.expression"
      "must be the opcode-ID node in program_event tuple slot 1"
  if family == .lui then
    match programLookup.tuple[1]? with
    | some opcodeNode =>
        if staticValues[opcodeNode]? != some (some (M31.reduce 35)) then
          decodeFailure "projection.program_event"
            "LUI program tuple must carry canonical manifest ID 35"
    | none =>
        decodeFailure "projection.program_event" "program tuple has no opcode ID slot"
  let sourceIdentity ← decodeSourceIdentity (← member context object "source_identity")
  let contentDigest ← jsonString "content_digest" (← member context object "content_digest")
  if !isSha256 contentDigest then
    decodeFailure context "content_digest must be 64 lowercase hexadecimal characters"

  let program : ConstraintProgram := {
    schemaVersion
    kind
    field
    family
    columns
    nodes
    activeRow
    opcodeSelector
    fixedTables
    events
    projection
    sourceIdentity
    contentDigest
  }
  validateReachability program
  return program

private def jsonNatValue (value : Nat) : Json :=
  toJson value

private def jsonStringValue (value : String) : Json :=
  toJson value

private def Column.toJson (column : Column) : Json :=
  Json.mkObj [
    ("index", jsonNatValue column.index),
    ("name", jsonStringValue column.name),
    ("role", jsonStringValue column.role.wireName),
    ("type", jsonStringValue "m31"),
    ("width", jsonNatValue 1)
  ]

private def nodeArgs (arguments : Array NodeId) : Json :=
  Json.arr (arguments.map jsonNatValue)

private def ExprNode.toJson : ExprNode → Json
  | .const value => Json.mkObj [
      ("op", jsonStringValue "const"),
      ("value", jsonNatValue value.toNat)
    ]
  | .column columnIndex => Json.mkObj [
      ("op", jsonStringValue "col"),
      ("column", jsonNatValue columnIndex)
    ]
  | .add left right => Json.mkObj [
      ("op", jsonStringValue "add"),
      ("args", nodeArgs #[left, right])
    ]
  | .sub left right => Json.mkObj [
      ("op", jsonStringValue "sub"),
      ("args", nodeArgs #[left, right])
    ]
  | .mul left right => Json.mkObj [
      ("op", jsonStringValue "mul"),
      ("args", nodeArgs #[left, right])
    ]
  | .neg value => Json.mkObj [
      ("op", jsonStringValue "neg"),
      ("args", nodeArgs #[value])
    ]

private def FieldIdentity.toJson (field : FieldIdentity) : Json :=
  Json.mkObj [
    ("name", jsonStringValue field.name),
    ("modulus", jsonNatValue field.modulus)
  ]

private def OpcodeSelector.toJson (selector : OpcodeSelector) : Json :=
  Json.mkObj [
    ("manifest_id", jsonNatValue selector.manifestId),
    ("mnemonic", jsonStringValue selector.mnemonic),
    ("expression", jsonNatValue selector.expression)
  ]

private def FixedTableIdentity.toJson (table : FixedTableIdentity) : Json :=
  Json.mkObj [
    ("id", jsonStringValue table.id.wireName),
    ("domain", jsonStringValue table.domain.wireName),
    ("arity", jsonNatValue table.arity),
    ("log_size", jsonNatValue table.logSize),
    ("schema_sha256", jsonStringValue table.schemaSha256)
  ]

private def optionalTableIdToJson : Option FixedTableId → Json
  | none => .null
  | some table => jsonStringValue table.wireName

private def optionalNatToJson : Option Nat → Json
  | none => .null
  | some value => jsonNatValue value

private def Event.toJson : Event → Json
  | .constraint event => Json.mkObj [
      ("ordinal", jsonNatValue event.ordinal),
      ("kind", jsonStringValue "constraint"),
      ("root", jsonNatValue event.root)
    ]
  | .lookup event => Json.mkObj [
      ("ordinal", jsonNatValue event.ordinal),
      ("kind", jsonStringValue "lookup"),
      ("domain", jsonStringValue event.domain.wireName),
      ("numerator", jsonNatValue event.numerator),
      ("tuple", Json.arr (event.tuple.map jsonNatValue)),
      ("role", jsonStringValue event.role.wireName),
      ("table_id", optionalTableIdToJson event.tableId),
      ("liveness", jsonStringValue "nonzero_numerator"),
      ("access_ordinal", optionalNatToJson event.accessOrdinal)
    ]

private def Projection.toJson (projection : Projection) : Json :=
  Json.mkObj [
    ("program_event", jsonNatValue projection.programEvent),
    ("state_events", Json.arr (projection.stateEvents.map jsonNatValue)),
    ("source_events", Json.arr (projection.sourceEvents.map jsonNatValue)),
    ("destination_events", Json.arr (projection.destinationEvents.map jsonNatValue)),
    ("next_pc", jsonNatValue projection.nextPc)
  ]

private def SourceFileIdentity.toJson (file : SourceFileIdentity) : Json :=
  Json.mkObj [
    ("path", jsonStringValue file.path),
    ("sha256", jsonStringValue file.sha256)
  ]

private def SourceIdentity.toJson (source : SourceIdentity) : Json :=
  Json.mkObj [
    ("builder", jsonStringValue source.builder),
    ("source_closure_sha256", jsonStringValue source.sourceClosureSha256),
    ("files", Json.arr (source.files.map SourceFileIdentity.toJson))
  ]

def ConstraintProgram.toJson (program : ConstraintProgram) : Json :=
  Json.mkObj [
    ("schema_version", jsonNatValue program.schemaVersion),
    ("kind", jsonStringValue program.kind),
    ("field", program.field.toJson),
    ("family", jsonStringValue program.family.wireName),
    ("columns", Json.arr (program.columns.map Column.toJson)),
    ("nodes", Json.arr (program.nodes.map ExprNode.toJson)),
    ("active_row", jsonNatValue program.activeRow),
    ("opcode_selector", program.opcodeSelector.toJson),
    ("fixed_tables", Json.arr (program.fixedTables.map FixedTableIdentity.toJson)),
    ("events", Json.arr (program.events.map Event.toJson)),
    ("projection", program.projection.toJson),
    ("source_identity", program.sourceIdentity.toJson),
    ("content_digest", jsonStringValue program.contentDigest)
  ]

def ConstraintProgram.canonicalJson (program : ConstraintProgram) : String :=
  Json.compress program.toJson

/--
Parse AIR IR v2 from its one canonical byte spelling.

The parse → typed decode → canonical reserialization comparison rejects
whitespace variants, reordered keys, alternate number/string spellings, and
duplicate keys (Lean's JSON parser overwrites duplicates, so the bytes cannot
round-trip).

`content_digest` is format-checked here.  Its SHA-256 is checked by the
artifact generation/receipt gate until a reviewed SHA-256 implementation is
part of the Lean trusted input path.
-/
def ConstraintProgram.decodeCanonical (input : String) : Except String ConstraintProgram := do
  let json ←
    match Json.parse input with
    | .ok value => .ok value
    | .error message => decodeFailure "constraint_program" s!"invalid JSON: {message}"
  let program ← ConstraintProgram.fromJson? json
  if program.canonicalJson != input then
    decodeFailure "constraint_program"
      "noncanonical JSON (including duplicate/reordered keys or whitespace)"
  return program

/-- Boolean certificate target used by generated AIR modules. -/
def ConstraintProgram.canonicalDecodes (input : String) : Bool :=
  match ConstraintProgram.decodeCanonical input with
  | .ok _ => true
  | .error _ => false

/--
Extract the typed program from a kernel-checked successful-decode certificate.

A caller that can supply the Boolean premise receives the decoded value with
no panic, unsafe escape, default program, or unchecked fallback.
-/
def ConstraintProgram.ofCanonicalJson
    (input : String)
    (success : ConstraintProgram.canonicalDecodes input = true) :
    ConstraintProgram :=
  match decoded : ConstraintProgram.decodeCanonical input with
  | .ok program => program
  | .error _ =>
      False.elim (by
        simp [ConstraintProgram.canonicalDecodes, decoded] at success)

end RiscvRefinement.Air
