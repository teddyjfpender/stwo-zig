-- GENERATED FILE. DO NOT EDIT.
-- Generator: scratch `gen_mulh_program.py` (O2 for issue #137), adapted from
-- the O1 generator that emitted `MulProgram.lean`.
-- Data source: /tmp/tb-ir/mulh.json, sha256
--   461461c9adcf8b65f3c5a8d14f9336ddb65b3fea28c1ca9bbe530156ad88f28b
-- which is the export `RiscvRefinement/Air/Family/Multiply.lean` pins as
-- `mulhIrDigest`.
--
-- The node algebra, the field, the localisation and the evaluator all come
-- from `MulProgram.lean` unchanged; this file only adds what the `mulh`
-- family needs on top of them, and that is exactly two things.
--
-- 1. A sixth relation domain, `range_check_m31`. `MulProgram.Domain` is an
--    inductive with five constructors and cannot be extended after the fact,
--    so the lookup/program records are re-declared here as `MulhLookup` /
--    `MulhCircuit`. The `Node`, `M31`, `nth`, `evalLoop`, `Node.evalLocal`,
--    `Node.localise`, `nodesWellFormed`, `rangeCheck20Contains` and
--    `rangeCheck811Contains` definitions are imported, not copied, so the two
--    families are interpreted by literally the same evaluator.
--
-- 2. Numerator gating on fixed-table membership. `mul` has a committed
--    `enabler` column pinned to one, so every one of its requests is live on
--    every active row and `Program.fixedRequestsHold` can check them all
--    unconditionally. `mulh` does not: lookups 17 and 18 carry numerators
--    `-(is_mulh + is_mulhsu)` and `-is_mulh`, which are zero on `mulhu` and
--    (for 18) on `mulhsu` rows. A LogUp term with a zero numerator contributes
--    nothing to the bus sum, so the production system does not require its
--    tuple to be in the table -- and indeed on an unsigned row
--    `rs1_next_3 - 128 * rs1_sign` is just `rs1_next_3`, which routinely
--    exceeds the table's 7-bit second coordinate. `MulhCircuit.fixedRequestsHold`
--    below therefore reads "every request with a non-zero numerator lands in
--    its table". `fixedRequestsHoldUnconditional` is the ungated reading, kept
--    only so that the `#guard` at the bottom of this file can exhibit a
--    satisfying `mulhu` row on which it is false.
--
-- Membership itself is transcribed from the production table generator
-- `src/frontends/riscv/air/lookups/tables/schema.zig` (`checkedIndex`):
-- `range_check_m31` accepts `(lo, hi)` with `lo < 256`, `hi < 128` and
-- `(lo, hi) != (255, 127)` -- the last row of that table is reserved and holds
-- the zero tuple instead.

import RiscvRefinement.Air.Bridge.MulProgram

namespace RiscvRefinement.Air.Bridge

/-- The relation domains the `mulh` family requests. `mul` uses the first five;
`range_check_m31` is the one this family adds. A models all twelve. -/
inductive MulhDomain where
  | programAccess
  | registersState
  | memoryAccess
  | rangeCheck20
  | rangeCheck811
  | rangeCheckM31
deriving DecidableEq, Repr

structure MulhLookup where
  domain : MulhDomain
  role : Role
  numerator : Nat
  tuple : List Nat
deriving DecidableEq, Repr

structure MulhCircuit where
  family : String
  modulus : Nat
  columns : List String
  nodes : List Node
  nodeCount : Nat
  constraints : List Nat
  lookups : List MulhLookup
deriving DecidableEq, Repr

/-- A's decoder side condition, verbatim from `Program.wellFormed`. -/
def MulhCircuit.wellFormed (circuit : MulhCircuit) : Bool :=
  let nodeCount := circuit.nodes.length
  decide (circuit.modulus = m31Modulus) &&
    decide (circuit.nodeCount = nodeCount) &&
    nodesWellFormed circuit.columns.length 0 circuit.nodes &&
    circuit.constraints.all (fun root => decide (root < nodeCount)) &&
    circuit.lookups.all (fun entry =>
      decide (entry.numerator < nodeCount) &&
        entry.tuple.all (fun node => decide (node < nodeCount)))

def MulhCircuit.localise (circuit : MulhCircuit) : MulhCircuit :=
  { circuit with nodes := localiseNodes 0 circuit.nodes }

def MulhCircuit.nodeValuesRev (circuit : MulhCircuit) (columns : List M31) : List M31 :=
  evalLoop columns [] circuit.nodes

def MulhCircuit.value (circuit : MulhCircuit) (columns : List M31) (index : Nat) : M31 :=
  nth (circuit.nodeValuesRev columns) (circuit.nodeCount - 1 - index)

def MulhCircuit.values
    (circuit : MulhCircuit) (columns : List M31) (indices : List Nat) : List M31 :=
  indices.map (circuit.value columns)

def MulhCircuit.constraintValues (circuit : MulhCircuit) (columns : List M31) : List M31 :=
  circuit.values columns circuit.constraints

def MulhCircuit.lookupTuple
    (circuit : MulhCircuit) (columns : List M31) (entry : MulhLookup) : List M31 :=
  circuit.values columns entry.tuple

def MulhCircuit.lookupNumerator
    (circuit : MulhCircuit) (columns : List M31) (entry : MulhLookup) : M31 :=
  circuit.value columns entry.numerator

/-- Membership in the `range_check_m31` preprocessed table, transcribed from
`checkedIndex` in `air/lookups/tables/schema.zig`. -/
def rangeCheckM31Contains : List M31 → Bool
  | [low, high] =>
      decide (low.toNat < 256) && decide (high.toNat < 128) &&
        !(decide (low.toNat = 255) && decide (high.toNat = 127))
  | _ => false

/-- One request lands inside the fixed table it names. Requests against the
three bus relations are not fixed-table requests and impose nothing here. -/
def MulhCircuit.fixedRequestHolds
    (circuit : MulhCircuit) (columns : List M31) (entry : MulhLookup) : Bool :=
  match entry.domain with
  | .rangeCheck20 => rangeCheck20Contains (circuit.lookupTuple columns entry)
  | .rangeCheck811 => rangeCheck811Contains (circuit.lookupTuple columns entry)
  | .rangeCheckM31 => rangeCheckM31Contains (circuit.lookupTuple columns entry)
  | _ => true

/-- Every *live* fixed-table request lands inside its table. A LogUp term whose
numerator evaluates to zero contributes nothing to the bus sum, so it is not a
request; see the header. -/
def MulhCircuit.fixedRequestsHold (circuit : MulhCircuit) (columns : List M31) : Bool :=
  circuit.lookups.all fun entry =>
    decide (circuit.lookupNumerator columns entry = 0) ||
      circuit.fixedRequestHolds columns entry

/-- The ungated reading, which `mul` can afford and `mulh` cannot. Present only
so that the counterexample `#guard` below can be stated. -/
def MulhCircuit.fixedRequestsHoldUnconditional
    (circuit : MulhCircuit) (columns : List M31) : Bool :=
  circuit.lookups.all fun entry => circuit.fixedRequestHolds columns entry

/-- sha256 of the export this file was generated from. `MulhBridge.lean`
`#guard`s it equal to `Air.Family.mulhIrDigest`, so the node table below
and the hand transcription in `Air/Family/Multiply.lean` are pinned to the
same bytes mechanically, not by comment. -/
def mulhProgramIrDigest : String :=
  "461461c9adcf8b65f3c5a8d14f9336ddb65b3fea28c1ca9bbe530156ad88f28b"

-- 53 columns, 221 nodes, 30 constraints, 22 lookups.
def mulhProgram : MulhCircuit where
  family := "mulh"
  modulus := 2147483647
  columns := [
    "clock", "pc", "rd_addr", "rd_previous_0",
    "rd_previous_1", "rd_previous_2", "rd_previous_3", "rd_previous_clock",
    "rd_next_0", "rd_next_1", "rd_next_2", "rd_next_3",
    "rs1_addr", "rs1_previous_0", "rs1_previous_1", "rs1_previous_2",
    "rs1_previous_3", "rs1_previous_clock", "rs1_next_0", "rs1_next_1",
    "rs1_next_2", "rs1_next_3", "rs2_addr", "rs2_previous_0",
    "rs2_previous_1", "rs2_previous_2", "rs2_previous_3", "rs2_previous_clock",
    "rs2_next_0", "rs2_next_1", "rs2_next_2", "rs2_next_3",
    "rd_high_0", "rd_high_1", "rd_high_2", "rd_high_3",
    "rs1_sign", "rs2_sign", "is_mulh", "is_mulhsu",
    "is_mulhu", "result_0", "result_1", "result_2",
    "result_3", "destination_nonzero", "destination_inverse", "bus_value_47",
    "bus_value_48", "bus_value_49", "bus_value_50", "bus_value_51",
    "bus_value_52"
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
    .col 39, -- 39
    .col 40, -- 40
    .col 41, -- 41
    .col 42, -- 42
    .col 43, -- 43
    .col 44, -- 44
    .col 45, -- 45
    .col 46, -- 46
    .const 1, -- 47
    .add 38 39, -- 48
    .add 48 40, -- 49
    .sub 47 49, -- 50
    .mul 49 50, -- 51
    .sub 47 38, -- 52
    .mul 38 52, -- 53
    .sub 47 39, -- 54
    .mul 39 54, -- 55
    .sub 47 40, -- 56
    .mul 40 56, -- 57
    .sub 47 36, -- 58
    .mul 36 58, -- 59
    .sub 47 37, -- 60
    .mul 37 60, -- 61
    .sub 52 39, -- 62
    .mul 62 36, -- 63
    .mul 52 37, -- 64
    .sub 45 47, -- 65
    .mul 45 65, -- 66
    .sub 47 45, -- 67
    .mul 2 67, -- 68
    .mul 2 46, -- 69
    .sub 69 45, -- 70
    .mul 45 41, -- 71
    .sub 8 71, -- 72
    .mul 45 42, -- 73
    .sub 9 73, -- 74
    .mul 45 43, -- 75
    .sub 10 75, -- 76
    .mul 45 44, -- 77
    .sub 11 77, -- 78
    .sub 18 13, -- 79
    .mul 49 79, -- 80
    .sub 19 14, -- 81
    .mul 49 81, -- 82
    .sub 20 15, -- 83
    .mul 49 83, -- 84
    .sub 21 16, -- 85
    .mul 49 85, -- 86
    .sub 28 23, -- 87
    .mul 49 87, -- 88
    .sub 29 24, -- 89
    .mul 49 89, -- 90
    .sub 30 25, -- 91
    .mul 49 91, -- 92
    .sub 31 26, -- 93
    .mul 49 93, -- 94
    .sub 49 47, -- 95
    .const 255, -- 96
    .mul 36 96, -- 97
    .mul 37 96, -- 98
    .const 0, -- 99
    .mul 18 28, -- 100
    .add 99 100, -- 101
    .sub 101 32, -- 102
    .const 8388608, -- 103
    .mul 102 103, -- 104
    .mul 18 29, -- 105
    .add 104 105, -- 106
    .mul 19 28, -- 107
    .add 106 107, -- 108
    .sub 108 33, -- 109
    .mul 109 103, -- 110
    .mul 18 30, -- 111
    .add 110 111, -- 112
    .mul 19 29, -- 113
    .add 112 113, -- 114
    .mul 20 28, -- 115
    .add 114 115, -- 116
    .sub 116 34, -- 117
    .mul 117 103, -- 118
    .mul 18 31, -- 119
    .add 118 119, -- 120
    .mul 19 30, -- 121
    .add 120 121, -- 122
    .mul 20 29, -- 123
    .add 122 123, -- 124
    .mul 21 28, -- 125
    .add 124 125, -- 126
    .sub 126 35, -- 127
    .mul 127 103, -- 128
    .mul 18 98, -- 129
    .add 128 129, -- 130
    .mul 19 31, -- 131
    .add 130 131, -- 132
    .mul 20 30, -- 133
    .add 132 133, -- 134
    .mul 21 29, -- 135
    .add 134 135, -- 136
    .mul 97 28, -- 137
    .add 136 137, -- 138
    .sub 138 41, -- 139
    .mul 139 103, -- 140
    .add 140 129, -- 141
    .mul 19 98, -- 142
    .add 141 142, -- 143
    .mul 20 31, -- 144
    .add 143 144, -- 145
    .mul 21 30, -- 146
    .add 145 146, -- 147
    .mul 97 29, -- 148
    .add 147 148, -- 149
    .add 149 137, -- 150
    .sub 150 42, -- 151
    .mul 151 103, -- 152
    .add 152 129, -- 153
    .add 153 142, -- 154
    .mul 20 98, -- 155
    .add 154 155, -- 156
    .mul 21 31, -- 157
    .add 156 157, -- 158
    .mul 97 30, -- 159
    .add 158 159, -- 160
    .add 160 148, -- 161
    .add 161 137, -- 162
    .sub 162 43, -- 163
    .mul 163 103, -- 164
    .add 164 129, -- 165
    .add 165 142, -- 166
    .add 166 155, -- 167
    .mul 21 98, -- 168
    .add 167 168, -- 169
    .mul 97 31, -- 170
    .add 169 170, -- 171
    .add 171 159, -- 172
    .add 172 148, -- 173
    .add 173 137, -- 174
    .sub 174 44, -- 175
    .mul 175 103, -- 176
    .neg 49, -- 177
    .const 38, -- 178
    .mul 38 178, -- 179
    .const 39, -- 180
    .mul 39 180, -- 181
    .add 179 181, -- 182
    .const 40, -- 183
    .mul 40 183, -- 184
    .add 182 184, -- 185
    .const 4, -- 186
    .add 1 186, -- 187
    .add 0 47, -- 188
    .sub 0 47, -- 189
    .mul 189 186, -- 190
    .add 190 47, -- 191
    .sub 191 17, -- 192
    .sub 192 47, -- 193
    .const 2, -- 194
    .add 190 194, -- 195
    .sub 195 27, -- 196
    .sub 196 47, -- 197
    .const 128, -- 198
    .mul 36 198, -- 199
    .sub 21 199, -- 200
    .neg 48, -- 201
    .mul 37 198, -- 202
    .sub 31 202, -- 203
    .neg 38, -- 204
    .const 3, -- 205
    .add 190 205, -- 206
    .sub 206 7, -- 207
    .sub 207 47, -- 208
    .col 47, -- 209
    .sub 209 185, -- 210
    .col 48, -- 211
    .sub 211 187, -- 212
    .col 49, -- 213
    .sub 213 188, -- 214
    .col 50, -- 215
    .sub 215 191, -- 216
    .col 51, -- 217
    .sub 217 195, -- 218
    .col 52, -- 219
    .sub 219 206 -- 220
  ]
  nodeCount := 221
  constraints := [
    51, 53, 55, 57, 59, 61, 63, 64,
    66, 68, 70, 72, 74, 76, 78, 80,
    82, 84, 86, 88, 90, 92, 94, 95,
    210, 212, 214, 216, 218, 220
  ]
  lookups := [
    { domain := .programAccess, role := .request,
      numerator := 177, tuple := [1, 185, 2, 12, 22] }, -- lookup 0
    { domain := .registersState, role := .consumed,
      numerator := 177, tuple := [1, 0] }, -- lookup 1
    { domain := .registersState, role := .emitted,
      numerator := 49, tuple := [187, 188] }, -- lookup 2
    { domain := .memoryAccess, role := .consumed,
      numerator := 177, tuple := [99, 12, 17, 13, 14, 15, 16] }, -- lookup 3
    { domain := .memoryAccess, role := .emitted,
      numerator := 49, tuple := [99, 12, 191, 18, 19, 20, 21] }, -- lookup 4
    { domain := .rangeCheck20, role := .request,
      numerator := 177, tuple := [193] }, -- lookup 5
    { domain := .memoryAccess, role := .consumed,
      numerator := 177, tuple := [99, 22, 27, 23, 24, 25, 26] }, -- lookup 6
    { domain := .memoryAccess, role := .emitted,
      numerator := 49, tuple := [99, 22, 195, 28, 29, 30, 31] }, -- lookup 7
    { domain := .rangeCheck20, role := .request,
      numerator := 177, tuple := [197] }, -- lookup 8
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [32, 104] }, -- lookup 9
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [33, 110] }, -- lookup 10
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [34, 118] }, -- lookup 11
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [35, 128] }, -- lookup 12
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [41, 140] }, -- lookup 13
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [42, 152] }, -- lookup 14
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [43, 164] }, -- lookup 15
    { domain := .rangeCheck811, role := .request,
      numerator := 177, tuple := [44, 176] }, -- lookup 16
    { domain := .rangeCheckM31, role := .request,
      numerator := 201, tuple := [99, 200] }, -- lookup 17
    { domain := .rangeCheckM31, role := .request,
      numerator := 204, tuple := [99, 203] }, -- lookup 18
    { domain := .memoryAccess, role := .consumed,
      numerator := 177, tuple := [99, 2, 7, 3, 4, 5, 6] }, -- lookup 19
    { domain := .memoryAccess, role := .emitted,
      numerator := 49, tuple := [99, 2, 206, 8, 9, 10, 11] }, -- lookup 20
    { domain := .rangeCheck20, role := .request,
      numerator := 177, tuple := [208] } -- lookup 21
  ]

-- The same program with every node argument rewritten to its offset
-- from the head of the reversed memo table. This is the table the
-- proofs in MulhBridge.lean evaluate; the `#guard` below is what ties
-- it to the verbatim export above.
def mulhProgramCompiled : MulhCircuit where
  family := "mulh"
  modulus := 2147483647
  columns := mulhProgram.columns
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
    .col 39, -- 39
    .col 40, -- 40
    .col 41, -- 41
    .col 42, -- 42
    .col 43, -- 43
    .col 44, -- 44
    .col 45, -- 45
    .col 46, -- 46
    .const 1, -- 47
    .add 9 8, -- 48
    .add 0 8, -- 49
    .sub 2 0, -- 50
    .mul 1 0, -- 51
    .sub 4 13, -- 52
    .mul 14 0, -- 53
    .sub 6 14, -- 54
    .mul 15 0, -- 55
    .sub 8 15, -- 56
    .mul 16 0, -- 57
    .sub 10 21, -- 58
    .mul 22 0, -- 59
    .sub 12 22, -- 60
    .mul 23 0, -- 61
    .sub 9 22, -- 62
    .mul 0 26, -- 63
    .mul 11 26, -- 64
    .sub 19 17, -- 65
    .mul 20 0, -- 66
    .sub 19 21, -- 67
    .mul 65 0, -- 68
    .mul 66 22, -- 69
    .sub 0 24, -- 70
    .mul 25 29, -- 71
    .sub 63 0, -- 72
    .mul 27 30, -- 73
    .sub 64 0, -- 74
    .mul 29 31, -- 75
    .sub 65 0, -- 76
    .mul 31 32, -- 77
    .sub 66 0, -- 78
    .sub 60 65, -- 79
    .mul 30 0, -- 80
    .sub 61 66, -- 81
    .mul 32 0, -- 82
    .sub 62 67, -- 83
    .mul 34 0, -- 84
    .sub 63 68, -- 85
    .mul 36 0, -- 86
    .sub 58 63, -- 87
    .mul 38 0, -- 88
    .sub 59 64, -- 89
    .mul 40 0, -- 90
    .sub 60 65, -- 91
    .mul 42 0, -- 92
    .sub 61 66, -- 93
    .mul 44 0, -- 94
    .sub 45 47, -- 95
    .const 255, -- 96
    .mul 60 0, -- 97
    .mul 60 1, -- 98
    .const 0, -- 99
    .mul 81 71, -- 100
    .add 1 0, -- 101
    .sub 0 69, -- 102
    .const 8388608, -- 103
    .mul 1 0, -- 104
    .mul 86 75, -- 105
    .add 1 0, -- 106
    .mul 87 78, -- 107
    .add 1 0, -- 108
    .sub 0 75, -- 109
    .mul 0 6, -- 110
    .mul 92 80, -- 111
    .add 1 0, -- 112
    .mul 93 83, -- 113
    .add 1 0, -- 114
    .mul 94 86, -- 115
    .add 1 0, -- 116
    .sub 0 82, -- 117
    .mul 0 14, -- 118
    .mul 100 87, -- 119
    .add 1 0, -- 120
    .mul 101 90, -- 121
    .add 1 0, -- 122
    .mul 102 93, -- 123
    .add 1 0, -- 124
    .mul 103 96, -- 125
    .add 1 0, -- 126
    .sub 0 91, -- 127
    .mul 0 24, -- 128
    .mul 110 30, -- 129
    .add 1 0, -- 130
    .mul 111 99, -- 131
    .add 1 0, -- 132
    .mul 112 102, -- 133
    .add 1 0, -- 134
    .mul 113 105, -- 135
    .add 1 0, -- 136
    .mul 39 108, -- 137
    .add 1 0, -- 138
    .sub 0 97, -- 139
    .mul 0 36, -- 140
    .add 0 11, -- 141
    .mul 122 43, -- 142
    .add 1 0, -- 143
    .mul 123 112, -- 144
    .add 1 0, -- 145
    .mul 124 115, -- 146
    .add 1 0, -- 147
    .mul 50 118, -- 148
    .add 1 0, -- 149
    .add 0 12, -- 150
    .sub 0 108, -- 151
    .mul 0 48, -- 152
    .add 0 23, -- 153
    .add 0 11, -- 154
    .mul 134 56, -- 155
    .add 1 0, -- 156
    .mul 135 125, -- 157
    .add 1 0, -- 158
    .mul 61 128, -- 159
    .add 1 0, -- 160
    .add 0 12, -- 161
    .add 0 24, -- 162
    .sub 0 119, -- 163
    .mul 0 60, -- 164
    .add 0 35, -- 165
    .add 0 23, -- 166
    .add 0 11, -- 167
    .mul 146 69, -- 168
    .add 1 0, -- 169
    .mul 72 138, -- 170
    .add 1 0, -- 171
    .add 0 12, -- 172
    .add 0 24, -- 173
    .add 0 36, -- 174
    .sub 0 130, -- 175
    .mul 0 72, -- 176
    .neg 127, -- 177
    .const 38, -- 178
    .mul 140 0, -- 179
    .const 39, -- 180
    .mul 141 0, -- 181
    .add 2 0, -- 182
    .const 40, -- 183
    .mul 143 0, -- 184
    .add 2 0, -- 185
    .const 4, -- 186
    .add 185 0, -- 187
    .add 187 140, -- 188
    .sub 188 141, -- 189
    .mul 0 3, -- 190
    .add 0 143, -- 191
    .sub 0 174, -- 192
    .sub 0 145, -- 193
    .const 2, -- 194
    .add 4 0, -- 195
    .sub 0 168, -- 196
    .sub 0 149, -- 197
    .const 128, -- 198
    .mul 162 0, -- 199
    .sub 178 0, -- 200
    .neg 152, -- 201
    .mul 164 3, -- 202
    .sub 171 0, -- 203
    .neg 165, -- 204
    .const 3, -- 205
    .add 15 0, -- 206
    .sub 0 199, -- 207
    .sub 0 160, -- 208
    .col 47, -- 209
    .sub 0 24, -- 210
    .col 48, -- 211
    .sub 0 24, -- 212
    .col 49, -- 213
    .sub 0 25, -- 214
    .col 50, -- 215
    .sub 0 24, -- 216
    .col 51, -- 217
    .sub 0 22, -- 218
    .col 52, -- 219
    .sub 0 13 -- 220
  ]
  nodeCount := 221
  constraints := mulhProgram.constraints
  lookups := mulhProgram.lookups

-- The localisation really is the mechanical rewrite of the export.
#guard mulhProgramCompiled == mulhProgram.localise

-- The wire validation A's decoder performs, run on this table.
#guard mulhProgram.wellFormed

-- Sanity: the table is the size the export reports.
#guard mulhProgram.columns.length == 53
#guard mulhProgram.nodes.length == 221
#guard mulhProgram.constraints.length == 30
#guard mulhProgram.lookups.length == 22

-- A concrete satisfying MULH row (-1 * 2, so both sign witnesses are
-- exercised: rs1_sign = 1, rs2_sign = 0), and the values an
-- independent evaluator -- the generator, walking the same JSON --
-- computes for it. This is the differential test between this
-- interpreter and that one.
def mulhWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 100, M31.reduce 7, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 255, M31.reduce 255, M31.reduce 255, M31.reduce 255,
    M31.reduce 1, M31.reduce 255, M31.reduce 255, M31.reduce 255,
    M31.reduce 255, M31.reduce 3, M31.reduce 255, M31.reduce 255,
    M31.reduce 255, M31.reduce 255, M31.reduce 2, M31.reduce 2,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 2, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 254, M31.reduce 255, M31.reduce 255, M31.reduce 255,
    M31.reduce 1, M31.reduce 0, M31.reduce 1, M31.reduce 0,
    M31.reduce 0, M31.reduce 255, M31.reduce 255, M31.reduce 255,
    M31.reduce 255, M31.reduce 1, M31.reduce 1840700269, M31.reduce 38,
    M31.reduce 104, M31.reduce 6, M31.reduce 17, M31.reduce 18,
    M31.reduce 19
  ]

#guard mulhProgramCompiled.constraintValues mulhWitnessColumns ==
  List.replicate 30 0

#guard mulhProgramCompiled.fixedRequestsHold mulhWitnessColumns

-- On a MULH row every request is live, so the ungated reading holds too.
#guard mulhProgramCompiled.fixedRequestsHoldUnconditional mulhWitnessColumns

#guard (mulhProgramCompiled.lookups.map fun entry =>
    (mulhProgramCompiled.lookupTuple mulhWitnessColumns entry).map M31.toNat) ==
  [
    [100, 38, 7, 1, 2],
    [100, 5],
    [104, 6],
    [0, 1, 3, 255, 255, 255, 255],
    [0, 1, 17, 255, 255, 255, 255],
    [13],
    [0, 2, 3, 2, 0, 0, 0],
    [0, 2, 18, 2, 0, 0, 0],
    [14],
    [254, 1],
    [255, 1],
    [255, 1],
    [255, 1],
    [255, 1],
    [255, 1],
    [255, 1],
    [255, 1],
    [0, 127],
    [0, 0],
    [0, 7, 3, 0, 0, 0, 0],
    [0, 7, 19, 255, 255, 255, 255],
    [15]
  ]

#guard (mulhProgramCompiled.lookups.map fun entry =>
    (mulhProgramCompiled.lookupNumerator mulhWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646]

-- A concrete satisfying MULHU row, 0xff000000 * 2. Its top source
-- byte is 255, so lookup 17's tuple is (0, 255): outside the
-- `range_check_m31` table, which only holds second coordinates below
-- 128. The row is nevertheless accepted by the production AIR,
-- because lookup 17's numerator -(is_mulh + is_mulhsu) is zero here.
def mulhUnsignedWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 100, M31.reduce 7, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 1, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 1, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 255, M31.reduce 3, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 255, M31.reduce 2, M31.reduce 2,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 2, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 254,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 1, M31.reduce 1, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 1, M31.reduce 1840700269, M31.reduce 40,
    M31.reduce 104, M31.reduce 6, M31.reduce 17, M31.reduce 18,
    M31.reduce 19
  ]

#guard mulhProgramCompiled.constraintValues mulhUnsignedWitnessColumns ==
  List.replicate 30 0

-- This is the fact that forces the numerator gate: the ungated reading
-- of `fixedRequestsHold` is FALSE on a row the AIR accepts.
#guard mulhProgramCompiled.fixedRequestsHoldUnconditional
  mulhUnsignedWitnessColumns == false

-- The gated reading, which is what the bridge proves, holds.
#guard mulhProgramCompiled.fixedRequestsHold mulhUnsignedWitnessColumns

-- Lookups 17 and 18 are exactly the two dead requests on this row.
#guard (mulhProgramCompiled.lookups.map fun entry =>
    (mulhProgramCompiled.lookupNumerator mulhUnsignedWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 2147483646, 0, 0, 2147483646, 1, 2147483646]

#guard (mulhProgramCompiled.lookups.map fun entry =>
    (mulhProgramCompiled.lookupTuple mulhUnsignedWitnessColumns entry).map M31.toNat) ==
  [
    [100, 40, 7, 1, 2],
    [100, 5],
    [104, 6],
    [0, 1, 3, 0, 0, 0, 255],
    [0, 1, 17, 0, 0, 0, 255],
    [13],
    [0, 2, 3, 2, 0, 0, 0],
    [0, 2, 18, 2, 0, 0, 0],
    [14],
    [0, 0],
    [0, 0],
    [0, 0],
    [254, 1],
    [1, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 255],
    [0, 0],
    [0, 7, 3, 0, 0, 0, 0],
    [0, 7, 19, 1, 0, 0, 0],
    [15]
  ]

end RiscvRefinement.Air.Bridge
