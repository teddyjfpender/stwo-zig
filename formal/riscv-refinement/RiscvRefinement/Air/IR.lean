import RiscvRefinement.Tables.Fixed

namespace RiscvRefinement.Air

open RiscvRefinement

abbrev NodeId := Nat
abbrev EventOrdinal := Nat

inductive Family where
  | baseAluReg
  | baseAluImm
  | shiftsReg
  | shiftsImm
  | ltReg
  | ltImm
  | branchEq
  | branchLt
  | lui
  | auipc
  | jalr
  | jal
  | loadStore
  | mul
  | mulh
  | div
  | fence
deriving DecidableEq, Repr

namespace Family

def wireName : Family → String
  | .baseAluReg => "base_alu_reg"
  | .baseAluImm => "base_alu_imm"
  | .shiftsReg => "shifts_reg"
  | .shiftsImm => "shifts_imm"
  | .ltReg => "lt_reg"
  | .ltImm => "lt_imm"
  | .branchEq => "branch_eq"
  | .branchLt => "branch_lt"
  | .lui => "lui"
  | .auipc => "auipc"
  | .jalr => "jalr"
  | .jal => "jal"
  | .loadStore => "load_store"
  | .mul => "mul"
  | .mulh => "mulh"
  | .div => "div"
  | .fence => "fence"

def ofWireName? : String → Option Family
  | "base_alu_reg" => some .baseAluReg
  | "base_alu_imm" => some .baseAluImm
  | "shifts_reg" => some .shiftsReg
  | "shifts_imm" => some .shiftsImm
  | "lt_reg" => some .ltReg
  | "lt_imm" => some .ltImm
  | "branch_eq" => some .branchEq
  | "branch_lt" => some .branchLt
  | "lui" => some .lui
  | "auipc" => some .auipc
  | "jalr" => some .jalr
  | "jal" => some .jal
  | "load_store" => some .loadStore
  | "mul" => some .mul
  | "mulh" => some .mulh
  | "div" => some .div
  | "fence" => some .fence
  | _ => none

def validOpcode (family : Family) (manifestId : Nat) (mnemonic : String) : Bool :=
  match family with
  | .baseAluReg =>
      [(0, "add"), (1, "sub"), (5, "xor"), (8, "or"), (9, "and")].contains
        (manifestId, mnemonic)
  | .baseAluImm =>
      [(10, "addi"), (13, "xori"), (14, "ori"), (15, "andi")].contains
        (manifestId, mnemonic)
  | .shiftsReg =>
      [(2, "sll"), (6, "srl"), (7, "sra")].contains (manifestId, mnemonic)
  | .shiftsImm =>
      [(16, "slli"), (17, "srli"), (18, "srai")].contains (manifestId, mnemonic)
  | .ltReg =>
      [(3, "slt"), (4, "sltu")].contains (manifestId, mnemonic)
  | .ltImm =>
      [(11, "slti"), (12, "sltiu")].contains (manifestId, mnemonic)
  | .branchEq =>
      [(27, "beq"), (28, "bne")].contains (manifestId, mnemonic)
  | .branchLt =>
      [(29, "blt"), (30, "bge"), (31, "bltu"), (32, "bgeu")].contains
        (manifestId, mnemonic)
  | .lui => manifestId == 35 && mnemonic == "lui"
  | .auipc => manifestId == 36 && mnemonic == "auipc"
  | .jalr => manifestId == 34 && mnemonic == "jalr"
  | .jal => manifestId == 33 && mnemonic == "jal"
  | .loadStore =>
      [(19, "lb"), (20, "lh"), (21, "lw"), (22, "lbu"), (23, "lhu"),
       (24, "sb"), (25, "sh"), (26, "sw")].contains (manifestId, mnemonic)
  | .mul => manifestId == 37 && mnemonic == "mul"
  | .mulh =>
      [(38, "mulh"), (39, "mulhsu"), (40, "mulhu")].contains (manifestId, mnemonic)
  | .div =>
      [(41, "div"), (42, "divu"), (43, "rem"), (44, "remu")].contains
        (manifestId, mnemonic)
  | .fence => manifestId == 45 && mnemonic == "fence"

end Family

inductive ColumnRole where
  | input
  | output
  | witness
deriving DecidableEq, Repr

namespace ColumnRole

def wireName : ColumnRole → String
  | .input => "input"
  | .output => "output"
  | .witness => "witness"

def ofWireName? : String → Option ColumnRole
  | "input" => some .input
  | "output" => some .output
  | "witness" => some .witness
  | _ => none

end ColumnRole

structure Column where
  index : Nat
  name : String
  role : ColumnRole
deriving DecidableEq, Repr

/--
Typed expression nodes.  Node IDs live in the enclosing topologically ordered
array; the strict decoder checks that every argument is smaller than the
node's array index.
-/
inductive ExprNode where
  | const (value : M31)
  | column (column : Nat)
  | add (left right : NodeId)
  | sub (left right : NodeId)
  | mul (left right : NodeId)
  | neg (value : NodeId)
deriving DecidableEq, Repr

/-- All relation domains accepted by the production RISC-V lookup builder. -/
inductive Domain where
  | registersState
  | memoryAccess
  | programAccess
  | merkle
  | poseidon2
  | poseidon2Io
  | bitwise
  | rangeCheck20
  | rangeCheck811
  | rangeCheck884
  | rangeCheck88
  | rangeCheckM31
deriving DecidableEq, Repr

namespace Domain

def wireName : Domain → String
  | .registersState => "registers_state"
  | .memoryAccess => "memory_access"
  | .programAccess => "program_access"
  | .merkle => "merkle"
  | .poseidon2 => "poseidon2"
  | .poseidon2Io => "poseidon2_io"
  | .bitwise => "bitwise"
  | .rangeCheck20 => "range_check_20"
  | .rangeCheck811 => "range_check_8_11"
  | .rangeCheck884 => "range_check_8_8_4"
  | .rangeCheck88 => "range_check_8_8"
  | .rangeCheckM31 => "range_check_m31"

def ofWireName? : String → Option Domain
  | "registers_state" => some .registersState
  | "memory_access" => some .memoryAccess
  | "program_access" => some .programAccess
  | "merkle" => some .merkle
  | "poseidon2" => some .poseidon2
  | "poseidon2_io" => some .poseidon2Io
  | "bitwise" => some .bitwise
  | "range_check_20" => some .rangeCheck20
  | "range_check_8_11" => some .rangeCheck811
  | "range_check_8_8_4" => some .rangeCheck884
  | "range_check_8_8" => some .rangeCheck88
  | "range_check_m31" => some .rangeCheckM31
  | _ => none

def arity : Domain → Nat
  | .registersState => 2
  | .memoryAccess => 7
  | .programAccess => 5
  | .merkle => 4
  | .poseidon2 => 16
  | .poseidon2Io => 32
  | .bitwise => 4
  | .rangeCheck20 => 1
  | .rangeCheck811 => 2
  | .rangeCheck884 => 3
  | .rangeCheck88 => 2
  | .rangeCheckM31 => 2

def fixedTable? : Domain → Option FixedTableId
  | .bitwise => some .bitwise
  | .rangeCheck20 => some .rangeCheck20
  | .rangeCheck811 => some .rangeCheck811
  | .rangeCheck884 => some .rangeCheck884
  | .rangeCheck88 => some .rangeCheck88
  | .rangeCheckM31 => some .rangeCheckM31
  | _ => none

def ofFixedTable : FixedTableId → Domain
  | .bitwise => .bitwise
  | .rangeCheck20 => .rangeCheck20
  | .rangeCheck811 => .rangeCheck811
  | .rangeCheck884 => .rangeCheck884
  | .rangeCheck88 => .rangeCheck88
  | .rangeCheckM31 => .rangeCheckM31

end Domain

structure FieldIdentity where
  name : String
  modulus : Nat
deriving DecidableEq, Repr

structure OpcodeSelector where
  manifestId : Nat
  mnemonic : String
  expression : NodeId
deriving DecidableEq, Repr

structure FixedTableIdentity where
  id : FixedTableId
  domain : Domain
  arity : Nat
  logSize : Nat
  schemaSha256 : String
deriving DecidableEq, Repr

namespace FixedTableIdentity

/-- SHA-256 of compact sorted-key JSON `{arity,domain,id,log_size}`. -/
def expectedSchemaSha256 : FixedTableId → String
  | .bitwise =>
      "7de3a5c8de009b1f2d9da74ce88f02b3705c26da488d0005d0c67b07b9a6daab"
  | .rangeCheck20 =>
      "618f993093152e26cd08fc37b4ddc942a7a7e998444ee2e34d433d42667613e0"
  | .rangeCheck811 =>
      "1fa99606e17949d62271f75ad3ecfdb68bc016dadaa1995579d8831417ab8976"
  | .rangeCheck884 =>
      "c5894ccdf667ad77987691500806fbdb7f93b91fa40672785465e41fb393e1df"
  | .rangeCheck88 =>
      "74691adaef966cf81ce717e97fc298c8272958c614327b87aee9dafea79c5102"
  | .rangeCheckM31 =>
      "bf4f031af4d434f3d9ad028c3b8976822499b3f3cdfe81be0933e45baafd674d"

def expected (id : FixedTableId) : FixedTableIdentity where
  id := id
  domain := Domain.ofFixedTable id
  arity := id.arity
  logSize := id.logSize
  schemaSha256 := expectedSchemaSha256 id

end FixedTableIdentity

inductive LookupLiveness where
  | nonzeroNumerator
deriving DecidableEq, Repr

inductive LookupRole where
  | request
  | consume
  | emit
deriving DecidableEq, Repr

namespace LookupRole

def wireName : LookupRole → String
  | .request => "request"
  | .consume => "consume"
  | .emit => "emit"

def ofWireName? : String → Option LookupRole
  | "request" => some .request
  | "consume" => some .consume
  | "emit" => some .emit
  | _ => none

end LookupRole

structure ConstraintEvent where
  ordinal : EventOrdinal
  root : NodeId
deriving DecidableEq, Repr

structure LookupEvent where
  ordinal : EventOrdinal
  domain : Domain
  numerator : NodeId
  tuple : Array NodeId
  role : LookupRole
  tableId : Option FixedTableId
  liveness : LookupLiveness
  accessOrdinal : Option Nat
deriving DecidableEq, Repr

inductive Event where
  | constraint (event : ConstraintEvent)
  | lookup (event : LookupEvent)
deriving DecidableEq, Repr

namespace Event

def ordinal : Event → EventOrdinal
  | .constraint event => event.ordinal
  | .lookup event => event.ordinal

def lookup? : Event → Option LookupEvent
  | .constraint _ => none
  | .lookup event => some event

end Event

structure Projection where
  programEvent : EventOrdinal
  stateEvents : Array EventOrdinal
  sourceEvents : Array EventOrdinal
  destinationEvents : Array EventOrdinal
  nextPc : NodeId
deriving DecidableEq, Repr

structure SourceFileIdentity where
  path : String
  sha256 : String
deriving DecidableEq, Repr

structure SourceIdentity where
  builder : String
  sourceClosureSha256 : String
  files : Array SourceFileIdentity
deriving DecidableEq, Repr

/-- AIR IR v2 after fail-closed wire validation. -/
structure ConstraintProgram where
  schemaVersion : Nat
  kind : String
  field : FieldIdentity
  family : Family
  columns : Array Column
  nodes : Array ExprNode
  activeRow : NodeId
  opcodeSelector : OpcodeSelector
  fixedTables : Array FixedTableIdentity
  events : Array Event
  projection : Projection
  sourceIdentity : SourceIdentity
  contentDigest : String
deriving DecidableEq, Repr

end RiscvRefinement.Air
