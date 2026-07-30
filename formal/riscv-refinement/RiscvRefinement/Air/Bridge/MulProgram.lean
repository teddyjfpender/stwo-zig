-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts scratch `gen_mul_program.py` (O1 spike for issue #137).
-- Data source: /tmp/tb-ir/mul.json, sha256
--   20036f269882cc1ca77d9a83f9b8863763e3b4b9e4fd3d28c6b1d78bfb931146
-- which is the same export `RiscvRefinement/Air/Family/Multiply.lean` pins as
-- `mulIrDigest`.
--
-- This file is a stand-in for Team A's `Air/IR.lean` + `Air/Eval.lean` +
-- `Air/Generated/*Program.lean` (PR #141, branch feat/issue-136-air-ir-v2),
-- which are not on this branch and therefore cannot be imported yet. The node
-- algebra (`const`/`col`/`add`/`sub`/`mul`/`neg` over a topologically ordered
-- node array, constraint roots as node indices, lookups as a numerator node
-- plus a tuple of nodes), the field, and the evaluation semantics are the
-- shapes A ships; the differences are deliberate and listed here:
--
--   * `List` replaces A's `Array` everywhere. Kernel reduction of `Array`
--     literals goes through `List.toArray` anyway, and the proofs in
--     `MulBridge.lean` need the node table to reduce under a symbolic row.
--   * evaluation is total (`Program.value` returns `0` off the end of the
--     table) instead of A's `Except EvalError`. `Program.wellFormed` is the
--     fail-closed check that makes the two agree: it is exactly A's decoder
--     side condition (every argument index is smaller than the node's own
--     index, every column index is in range, every constant is canonical).
--   * `M31.neg` is `reduce (modulus - value)`; A writes the same function as a
--     dependent `if value = 0`. The two agree pointwise.
--   * only the five relation domains the `mul` family uses are modelled.
--
-- When A's modules land, `mulProgram` below should be replaced by A's decoded
-- `ConstraintProgram` and `MulBridge.lean` should keep its statements.

import RiscvRefinement.Common

namespace RiscvRefinement.Air.Bridge

-- The Mersenne prime the production prover works over.
def m31Modulus : Nat := 2147483647

structure M31 where
  val : Nat
  isLt : val < m31Modulus
deriving DecidableEq, Repr

namespace M31

def modulus : Nat := m31Modulus

theorem modulus_pos : 0 < modulus := by decide

def reduce (value : Nat) : M31 :=
  ⟨value % modulus, Nat.mod_lt _ modulus_pos⟩

def toNat (value : M31) : Nat := value.val

def zero : M31 := ⟨0, by decide⟩

def one : M31 := ⟨1, by decide⟩

def add (left right : M31) : M31 := reduce (left.val + right.val)

def sub (left right : M31) : M31 := reduce (left.val + modulus - right.val)

def mul (left right : M31) : M31 := reduce (left.val * right.val)

def neg (value : M31) : M31 := reduce (modulus - value.val)

instance : Zero M31 := ⟨zero⟩
instance : One M31 := ⟨one⟩
instance : Add M31 := ⟨add⟩
instance : Sub M31 := ⟨sub⟩
instance : Mul M31 := ⟨mul⟩
instance : Neg M31 := ⟨neg⟩

end M31

-- Typed expression nodes. Argument indices point into the enclosing
-- topologically ordered node table.
inductive Node where
  | const (value : Nat)
  | col (index : Nat)
  | add (left right : Nat)
  | sub (left right : Nat)
  | mul (left right : Nat)
  | neg (value : Nat)
deriving DecidableEq, Repr

-- The relation domains the `mul` family requests. A models all twelve.
inductive Domain where
  | programAccess
  | registersState
  | memoryAccess
  | rangeCheck20
  | rangeCheck811
deriving DecidableEq, Repr

inductive Role where
  | request
  | consumed
  | emitted
deriving DecidableEq, Repr

structure Lookup where
  domain : Domain
  role : Role
  numerator : Nat
  tuple : List Nat
deriving DecidableEq, Repr

structure Program where
  family : String
  modulus : Nat
  columns : List String
  nodes : List Node
  nodeCount : Nat
  constraints : List Nat
  lookups : List Lookup
deriving DecidableEq, Repr

-- Fail-closed wire validation, mirroring A's decoder: an argument may only
-- name an earlier node, a column index must exist, a constant must be the
-- canonical representative.
def Node.wellFormed (columnCount index : Nat) : Node → Bool
  | .const value => decide (value < m31Modulus)
  | .col column => decide (column < columnCount)
  | .add left right
  | .sub left right
  | .mul left right => decide (left < index) && decide (right < index)
  | .neg value => decide (value < index)

def nodesWellFormed (columnCount index : Nat) : List Node → Bool
  | [] => true
  | node :: rest =>
      node.wellFormed columnCount index && nodesWellFormed columnCount (index + 1) rest

def Program.wellFormed (program : Program) : Bool :=
  let nodeCount := program.nodes.length
  decide (program.modulus = m31Modulus) &&
    decide (program.nodeCount = nodeCount) &&
    nodesWellFormed program.columns.length 0 program.nodes &&
    program.constraints.all (fun root => decide (root < nodeCount)) &&
    program.lookups.all (fun entry =>
      decide (entry.numerator < nodeCount) &&
        entry.tuple.all (fun node => decide (node < nodeCount)))

-- Localisation.
--
-- Evaluation walks the node table once, keeping the values computed so far in
-- a *reversed* accumulator, so extending it is a `cons`. A node argument is
-- then read at a fixed offset from the head of that accumulator, and the
-- offset is `index - 1 - argument`. Rewriting the absolute argument to that
-- offset ahead of evaluation is what keeps the evaluator free of arithmetic:
-- with an index threaded through the loop instead, a single symbolic
-- evaluation of this table does not finish inside 20000 levels of `whnf`,
-- because the index accumulates as an unreduced `0 + 1 + 1 + ...` chain that
-- every memo read re-reduces.
def Node.localise (index : Nat) : Node → Node
  | .const value => .const value
  | .col column => .col column
  | .add left right => .add (index - 1 - left) (index - 1 - right)
  | .sub left right => .sub (index - 1 - left) (index - 1 - right)
  | .mul left right => .mul (index - 1 - left) (index - 1 - right)
  | .neg value => .neg (index - 1 - value)

def localiseNodes (index : Nat) : List Node → List Node
  | [] => []
  | node :: rest => node.localise index :: localiseNodes (index + 1) rest

def Program.localise (program : Program) : Program :=
  { program with nodes := localiseNodes 0 program.nodes }

-- Evaluation of a localised program.
def nth : List M31 → Nat → M31
  | [], _ => 0
  | value :: _, 0 => value
  | _ :: rest, index + 1 => nth rest index

def Node.evalLocal (columns values : List M31) : Node → M31
  | .const value => M31.reduce value
  | .col column => nth columns column
  | .add left right => nth values left + nth values right
  | .sub left right => nth values left - nth values right
  | .mul left right => nth values left * nth values right
  | .neg value => -nth values value

def evalLoop (columns : List M31) : List M31 → List Node → List M31
  | values, [] => values
  | values, node :: rest => evalLoop columns (node.evalLocal columns values :: values) rest

-- The memo table, most recently computed node first.
def Program.nodeValuesRev (program : Program) (columns : List M31) : List M31 :=
  evalLoop columns [] program.nodes

-- The memo table in node order, which is the shape A's `evalNodes` returns.
def Program.nodeValues (program : Program) (columns : List M31) : List M31 :=
  (program.nodeValuesRev columns).reverse

theorem nth_eq_getElem? (values : List M31) (index : Nat) :
    nth values index = (values[index]?).getD 0 := by
  induction values generalizing index with
  | nil => cases index <;> rfl
  | cons value rest ih =>
      cases index with
      | zero => rfl
      | succ smaller => simpa using ih smaller

theorem nth_reverse (values : List M31) (index : Nat) (bound : index < values.length) :
    nth values.reverse index = nth values (values.length - 1 - index) := by
  rw [nth_eq_getElem?, nth_eq_getElem?, List.getElem?_reverse bound]

theorem evalLoop_length (columns : List M31) (nodes : List Node) :
    ∀ values : List M31,
      (evalLoop columns values nodes).length = values.length + nodes.length := by
  induction nodes with
  | nil => intro values; simp [evalLoop]
  | cons node rest ih =>
      intro values
      simp only [evalLoop, ih, List.length_cons]
      omega

def Program.value (program : Program) (columns : List M31) (index : Nat) : M31 :=
  nth (program.nodeValuesRev columns) (program.nodeCount - 1 - index)

-- `value` really is the node-order read, for any index the table covers.
theorem Program.value_eq_nodeValues
    (program : Program)
    (columns : List M31)
    (index : Nat)
    (hcount : program.nodeCount = program.nodes.length)
    (hindex : index < program.nodes.length) :
    program.value columns index = nth (program.nodeValues columns) index := by
  have length : (program.nodeValuesRev columns).length = program.nodes.length := by
    simpa using evalLoop_length columns program.nodes []
  rw [Program.nodeValues, nth_reverse _ index (by omega), length, Program.value, hcount]

def Program.values
    (program : Program) (columns : List M31) (indices : List Nat) : List M31 :=
  indices.map (program.value columns)

def Program.constraintValues (program : Program) (columns : List M31) : List M31 :=
  program.values columns program.constraints

def Program.lookupTuple
    (program : Program) (columns : List M31) (entry : Lookup) : List M31 :=
  program.values columns entry.tuple

def Program.lookupNumerator
    (program : Program) (columns : List M31) (entry : Lookup) : M31 :=
  program.value columns entry.numerator

-- Membership in the two preprocessed tables the `mul` family requests,
-- transcribed from A's `Tables/Fixed.lean` (`FixedTableId.contains`).
def rangeCheck20Contains : List M31 → Bool
  | [value] => decide (value.toNat < 2 ^ 20)
  | _ => false

def rangeCheck811Contains : List M31 → Bool
  | [low, high] => decide (low.toNat < 2 ^ 8) && decide (high.toNat < 2 ^ 11)
  | _ => false

-- A's `EvaluatedProgram.fixedLookupsHold`, restricted to the two preprocessed
-- tables this family requests. Every request must land in its table.
def Program.fixedRequestsHold (program : Program) (columns : List M31) : Bool :=
  program.lookups.all fun entry =>
    match entry.domain with
    | .rangeCheck20 => rangeCheck20Contains (program.lookupTuple columns entry)
    | .rangeCheck811 => rangeCheck811Contains (program.lookupTuple columns entry)
    | _ => true

-- 44 columns, 130 nodes, 22 constraints, 16 lookups.
def mulProgram : Program where
  family := "mul"
  modulus := 2147483647
  columns := [
    "enabler", "clock", "pc", "rd_addr",
    "rd_previous_0", "rd_previous_1", "rd_previous_2", "rd_previous_3",
    "rd_previous_clock", "rd_next_0", "rd_next_1", "rd_next_2",
    "rd_next_3", "rs1_addr", "rs1_previous_0", "rs1_previous_1",
    "rs1_previous_2", "rs1_previous_3", "rs1_previous_clock", "rs1_next_0",
    "rs1_next_1", "rs1_next_2", "rs1_next_3", "rs2_addr",
    "rs2_previous_0", "rs2_previous_1", "rs2_previous_2", "rs2_previous_3",
    "rs2_previous_clock", "rs2_next_0", "rs2_next_1", "rs2_next_2",
    "rs2_next_3", "result_0", "result_1", "result_2",
    "result_3", "destination_nonzero", "destination_inverse", "bus_value_39",
    "bus_value_40", "bus_value_41", "bus_value_42", "bus_value_43"
  ]
  nodes := [
    .col 0, -- 0
    .col 1, -- 1
    .col 2, -- 2
    .col 3, -- 3
    .col 4, -- 4
    .col 5, -- 5
    .col 6, -- 6
    .col 7, -- 7
    .col 8, -- 8
    .col 9, -- 9
    .col 10, -- 10
    .col 11, -- 11
    .col 12, -- 12
    .col 13, -- 13
    .col 14, -- 14
    .col 15, -- 15
    .col 16, -- 16
    .col 17, -- 17
    .col 18, -- 18
    .col 19, -- 19
    .col 20, -- 20
    .col 21, -- 21
    .col 22, -- 22
    .col 23, -- 23
    .col 24, -- 24
    .col 25, -- 25
    .col 26, -- 26
    .col 27, -- 27
    .col 28, -- 28
    .col 29, -- 29
    .col 30, -- 30
    .col 31, -- 31
    .col 32, -- 32
    .col 33, -- 33
    .col 34, -- 34
    .col 35, -- 35
    .col 36, -- 36
    .col 37, -- 37
    .col 38, -- 38
    .const 1, -- 39
    .sub 39 0, -- 40
    .mul 0 40, -- 41
    .sub 37 39, -- 42
    .mul 37 42, -- 43
    .sub 39 37, -- 44
    .mul 3 44, -- 45
    .mul 3 38, -- 46
    .sub 46 37, -- 47
    .mul 37 33, -- 48
    .sub 9 48, -- 49
    .mul 37 34, -- 50
    .sub 10 50, -- 51
    .mul 37 35, -- 52
    .sub 11 52, -- 53
    .mul 37 36, -- 54
    .sub 12 54, -- 55
    .sub 19 14, -- 56
    .mul 0 56, -- 57
    .sub 20 15, -- 58
    .mul 0 58, -- 59
    .sub 21 16, -- 60
    .mul 0 60, -- 61
    .sub 22 17, -- 62
    .mul 0 62, -- 63
    .sub 29 24, -- 64
    .mul 0 64, -- 65
    .sub 30 25, -- 66
    .mul 0 66, -- 67
    .sub 31 26, -- 68
    .mul 0 68, -- 69
    .sub 32 27, -- 70
    .mul 0 70, -- 71
    .sub 0 39, -- 72
    .mul 19 29, -- 73
    .sub 73 33, -- 74
    .const 8388608, -- 75
    .mul 74 75, -- 76
    .mul 20 29, -- 77
    .add 76 77, -- 78
    .mul 19 30, -- 79
    .add 78 79, -- 80
    .sub 80 34, -- 81
    .mul 81 75, -- 82
    .mul 21 29, -- 83
    .add 82 83, -- 84
    .mul 20 30, -- 85
    .add 84 85, -- 86
    .mul 19 31, -- 87
    .add 86 87, -- 88
    .sub 88 35, -- 89
    .mul 89 75, -- 90
    .mul 22 29, -- 91
    .add 90 91, -- 92
    .mul 21 30, -- 93
    .add 92 93, -- 94
    .mul 20 31, -- 95
    .add 94 95, -- 96
    .mul 19 32, -- 97
    .add 96 97, -- 98
    .sub 98 36, -- 99
    .mul 99 75, -- 100
    .neg 0, -- 101
    .const 37, -- 102
    .const 4, -- 103
    .add 2 103, -- 104
    .add 1 39, -- 105
    .sub 1 39, -- 106
    .mul 106 103, -- 107
    .add 107 39, -- 108
    .const 0, -- 109
    .sub 108 18, -- 110
    .sub 110 39, -- 111
    .const 2, -- 112
    .add 107 112, -- 113
    .sub 113 28, -- 114
    .sub 114 39, -- 115
    .const 3, -- 116
    .add 107 116, -- 117
    .sub 117 8, -- 118
    .sub 118 39, -- 119
    .col 39, -- 120
    .sub 120 104, -- 121
    .col 40, -- 122
    .sub 122 105, -- 123
    .col 41, -- 124
    .sub 124 108, -- 125
    .col 42, -- 126
    .sub 126 113, -- 127
    .col 43, -- 128
    .sub 128 117 -- 129
  ]
  nodeCount := 130
  constraints := [
    41, 43, 45, 47, 49, 51, 53, 55,
    57, 59, 61, 63, 65, 67, 69, 71,
    72, 121, 123, 125, 127, 129
  ]
  lookups := [
    { domain := .programAccess, role := .request,
      numerator := 101, tuple := [2, 102, 3, 13, 23] }, -- lookup 0
    { domain := .registersState, role := .consumed,
      numerator := 101, tuple := [2, 1] }, -- lookup 1
    { domain := .registersState, role := .emitted,
      numerator := 0, tuple := [104, 105] }, -- lookup 2
    { domain := .memoryAccess, role := .consumed,
      numerator := 101, tuple := [109, 13, 18, 14, 15, 16, 17] }, -- lookup 3
    { domain := .memoryAccess, role := .emitted,
      numerator := 0, tuple := [109, 13, 108, 19, 20, 21, 22] }, -- lookup 4
    { domain := .rangeCheck20, role := .request,
      numerator := 101, tuple := [111] }, -- lookup 5
    { domain := .memoryAccess, role := .consumed,
      numerator := 101, tuple := [109, 23, 28, 24, 25, 26, 27] }, -- lookup 6
    { domain := .memoryAccess, role := .emitted,
      numerator := 0, tuple := [109, 23, 113, 29, 30, 31, 32] }, -- lookup 7
    { domain := .rangeCheck20, role := .request,
      numerator := 101, tuple := [115] }, -- lookup 8
    { domain := .rangeCheck811, role := .request,
      numerator := 101, tuple := [33, 76] }, -- lookup 9
    { domain := .rangeCheck811, role := .request,
      numerator := 101, tuple := [34, 82] }, -- lookup 10
    { domain := .rangeCheck811, role := .request,
      numerator := 101, tuple := [35, 90] }, -- lookup 11
    { domain := .rangeCheck811, role := .request,
      numerator := 101, tuple := [36, 100] }, -- lookup 12
    { domain := .memoryAccess, role := .consumed,
      numerator := 101, tuple := [109, 3, 8, 4, 5, 6, 7] }, -- lookup 13
    { domain := .memoryAccess, role := .emitted,
      numerator := 0, tuple := [109, 3, 117, 9, 10, 11, 12] }, -- lookup 14
    { domain := .rangeCheck20, role := .request,
      numerator := 101, tuple := [119] } -- lookup 15
  ]

-- The same program with every node argument rewritten to its offset
-- from the head of the reversed memo table. This is the table the
-- proofs in MulBridge.lean evaluate; the `#guard` below is what ties it
-- to the verbatim export above.
def mulProgramCompiled : Program where
  family := "mul"
  modulus := 2147483647
  columns := mulProgram.columns
  nodes := [
    .col 0, -- 0
    .col 1, -- 1
    .col 2, -- 2
    .col 3, -- 3
    .col 4, -- 4
    .col 5, -- 5
    .col 6, -- 6
    .col 7, -- 7
    .col 8, -- 8
    .col 9, -- 9
    .col 10, -- 10
    .col 11, -- 11
    .col 12, -- 12
    .col 13, -- 13
    .col 14, -- 14
    .col 15, -- 15
    .col 16, -- 16
    .col 17, -- 17
    .col 18, -- 18
    .col 19, -- 19
    .col 20, -- 20
    .col 21, -- 21
    .col 22, -- 22
    .col 23, -- 23
    .col 24, -- 24
    .col 25, -- 25
    .col 26, -- 26
    .col 27, -- 27
    .col 28, -- 28
    .col 29, -- 29
    .col 30, -- 30
    .col 31, -- 31
    .col 32, -- 32
    .col 33, -- 33
    .col 34, -- 34
    .col 35, -- 35
    .col 36, -- 36
    .col 37, -- 37
    .col 38, -- 38
    .const 1, -- 39
    .sub 0 39, -- 40
    .mul 40 0, -- 41
    .sub 4 2, -- 42
    .mul 5 0, -- 43
    .sub 4 6, -- 44
    .mul 41 0, -- 45
    .mul 42 7, -- 46
    .sub 0 9, -- 47
    .mul 10 14, -- 48
    .sub 39 0, -- 49
    .mul 12 15, -- 50
    .sub 40 0, -- 51
    .mul 14 16, -- 52
    .sub 41 0, -- 53
    .mul 16 17, -- 54
    .sub 42 0, -- 55
    .sub 36 41, -- 56
    .mul 56 0, -- 57
    .sub 37 42, -- 58
    .mul 58 0, -- 59
    .sub 38 43, -- 60
    .mul 60 0, -- 61
    .sub 39 44, -- 62
    .mul 62 0, -- 63
    .sub 34 39, -- 64
    .mul 64 0, -- 65
    .sub 35 40, -- 66
    .mul 66 0, -- 67
    .sub 36 41, -- 68
    .mul 68 0, -- 69
    .sub 37 42, -- 70
    .mul 70 0, -- 71
    .sub 71 32, -- 72
    .mul 53 43, -- 73
    .sub 0 40, -- 74
    .const 8388608, -- 75
    .mul 1 0, -- 76
    .mul 56 47, -- 77
    .add 1 0, -- 78
    .mul 59 48, -- 79
    .add 1 0, -- 80
    .sub 0 46, -- 81
    .mul 0 6, -- 82
    .mul 61 53, -- 83
    .add 1 0, -- 84
    .mul 64 54, -- 85
    .add 1 0, -- 86
    .mul 67 55, -- 87
    .add 1 0, -- 88
    .sub 0 53, -- 89
    .mul 0 14, -- 90
    .mul 68 61, -- 91
    .add 1 0, -- 92
    .mul 71 62, -- 93
    .add 1 0, -- 94
    .mul 74 63, -- 95
    .add 1 0, -- 96
    .mul 77 64, -- 97
    .add 1 0, -- 98
    .sub 0 62, -- 99
    .mul 0 24, -- 100
    .neg 100, -- 101
    .const 37, -- 102
    .const 4, -- 103
    .add 101 0, -- 104
    .add 103 65, -- 105
    .sub 104 66, -- 106
    .mul 0 3, -- 107
    .add 0 68, -- 108
    .const 0, -- 109
    .sub 1 91, -- 110
    .sub 0 71, -- 111
    .const 2, -- 112
    .add 5 0, -- 113
    .sub 0 85, -- 114
    .sub 0 75, -- 115
    .const 3, -- 116
    .add 9 0, -- 117
    .sub 0 109, -- 118
    .sub 0 79, -- 119
    .col 39, -- 120
    .sub 0 16, -- 121
    .col 40, -- 122
    .sub 0 17, -- 123
    .col 41, -- 124
    .sub 0 16, -- 125
    .col 42, -- 126
    .sub 0 13, -- 127
    .col 43, -- 128
    .sub 0 11 -- 129
  ]
  nodeCount := 130
  constraints := mulProgram.constraints
  lookups := mulProgram.lookups

-- The localisation really is the mechanical rewrite of the export.
#guard mulProgramCompiled == mulProgram.localise

-- The wire validation A's decoder performs, run on this table.
#guard mulProgram.wellFormed

-- Sanity: the table is the size the export reports.
#guard mulProgram.columns.length == 44
#guard mulProgram.nodes.length == 130
#guard mulProgram.constraints.length == 22
#guard mulProgram.lookups.length == 16

-- A concrete satisfying row, and the values an independent evaluator
-- (the generator, walking the same JSON) computes for it. This is the
-- differential test between this interpreter and that one.
def mulWitnessColumns : List M31 := [
    M31.reduce 1, M31.reduce 5, M31.reduce 100, M31.reduce 7,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 3, M31.reduce 20, M31.reduce 15, M31.reduce 10,
    M31.reduce 5, M31.reduce 1, M31.reduce 4, M31.reduce 3,
    M31.reduce 2, M31.reduce 1, M31.reduce 3, M31.reduce 4,
    M31.reduce 3, M31.reduce 2, M31.reduce 1, M31.reduce 2,
    M31.reduce 5, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 3, M31.reduce 5, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 20, M31.reduce 15, M31.reduce 10,
    M31.reduce 5, M31.reduce 1, M31.reduce 1840700269, M31.reduce 104,
    M31.reduce 6, M31.reduce 17, M31.reduce 18, M31.reduce 19
  ]

#guard mulProgramCompiled.constraintValues mulWitnessColumns ==
  List.replicate 22 0

#guard mulProgramCompiled.fixedRequestsHold mulWitnessColumns

#guard (mulProgramCompiled.lookups.map fun entry =>
    (mulProgramCompiled.lookupTuple mulWitnessColumns entry).map M31.toNat) ==
  [
    [100, 37, 7, 1, 2],
    [100, 5],
    [104, 6],
    [0, 1, 3, 4, 3, 2, 1],
    [0, 1, 17, 4, 3, 2, 1],
    [13],
    [0, 2, 3, 5, 0, 0, 0],
    [0, 2, 18, 5, 0, 0, 0],
    [14],
    [20, 0],
    [15, 0],
    [10, 0],
    [5, 0],
    [0, 7, 3, 0, 0, 0, 0],
    [0, 7, 19, 20, 15, 10, 5],
    [15]
  ]

#guard (mulProgramCompiled.lookups.map fun entry =>
    (mulProgramCompiled.lookupNumerator mulWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646]

end RiscvRefinement.Air.Bridge
