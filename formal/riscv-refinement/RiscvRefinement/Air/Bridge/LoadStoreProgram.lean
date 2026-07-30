-- GENERATED FILE. DO NOT EDIT.
-- Generator: scratch `gen_load_store_program.py` (O4 for issue #137), adapted
-- from the O1/O2 generators that emitted `MulProgram.lean` and
-- `MulhProgram.lean`.
-- Data source: /tmp/tb-ir/load_store.json, sha256
--   cadb1b662ec30864615aa84541c1bcd863e921f306446ea1c7a328c650180b20
-- which is the export `RiscvRefinement/Air/Family/LoadStore.lean` pins as
-- `loadStoreIrDigest`; `LoadStoreBridge.lean` `#guard`s the two strings equal.
--
-- This file adds no interpreter. The five relation domains `load_store` uses
-- -- `program_access`, `registers_state`, `memory_access`, `range_check_20`
-- and `range_check_m31` -- are a subset of the six `MulhDomain` already
-- models, so the encoded circuit below *is* a `MulhCircuit` and is evaluated by
-- literally the same `evalLoop` / `Node.evalLocal` / `nth` that `mul` and
-- `mulh` are evaluated by. The record's name is historical (it is the first one
-- that had to carry `range_check_m31`); nothing in it is `mulh`-specific.
--
-- Two `load_store` facts that shape what is emitted here:
--
--   * columns 2 (`dst_addr`) and 22 (`src_addr`) are dead -- no node reads
--     them -- and so is node 85 (`is_lw + is_sw`, the unused `opcode_w`). They
--     are kept in the table because this file is a verbatim encoding of the
--     export, not a pruned one; `LoadStoreBridge.lean` assigns the two dead
--     columns zero and says so.
--   * lookups 14 and 15 carry numerators `-is_lb` and `-is_lh`, so they are
--     dead on the other six opcodes. The `#guard` at the bottom exhibits a
--     satisfying `LW` row on which the *ungated* reading of
--     `fixedRequestsHold` is false, which is why the bridge proves the gated
--     one. Lookup 7 (`range_check_m31` on the base address) carries `-active`
--     and so is live on every row.

import RiscvRefinement.Air.Bridge.MulhProgram

namespace RiscvRefinement.Air.Bridge

/-- SHA-256 of the export this file encodes. -/
def loadStoreProgramIrDigest : String :=
  "cadb1b662ec30864615aa84541c1bcd863e921f306446ea1c7a328c650180b20"

-- 64 columns, 342 nodes, 79 constraint roots, 16 lookups.
def loadStoreCircuit : MulhCircuit where
  family := "load_store"
  modulus := 2147483647
  columns := [
    "clk", "pc", "dst_addr", "dst_previous_0",
    "dst_previous_1", "dst_previous_2", "dst_previous_3", "dst_previous_clock",
    "dst_next_0", "dst_next_1", "dst_next_2", "dst_next_3",
    "rs1_addr", "rs1_previous_0", "rs1_previous_1", "rs1_previous_2",
    "rs1_previous_3", "rs1_previous_clock", "rs1_next_0", "rs1_next_1",
    "rs1_next_2", "rs1_next_3", "src_addr", "src_previous_0",
    "src_previous_1", "src_previous_2", "src_previous_3", "src_previous_clock",
    "src_next_0", "src_next_1", "src_next_2", "src_next_3",
    "r2_idx", "imm_felt", "src_msb", "shift_amount",
    "src_addr_selector", "dst_addr_selector", "markers_0", "markers_1",
    "markers_2", "markers_3", "is_lb", "is_lh",
    "is_lbu", "is_lhu", "is_lw", "is_sb",
    "is_sh", "is_sw", "result_0", "result_1",
    "result_2", "result_3", "destination_nonzero", "destination_inverse",
    "bus_value_56", "bus_value_57", "bus_value_58", "bus_value_59",
    "bus_value_60", "bus_value_61", "bus_value_62", "bus_value_63"
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
    .col 47, -- 47
    .col 48, -- 48
    .col 49, -- 49
    .col 50, -- 50
    .col 51, -- 51
    .col 52, -- 52
    .col 53, -- 53
    .col 54, -- 54
    .col 55, -- 55
    .const 1, -- 56
    .add 42 43, -- 57
    .add 57 44, -- 58
    .add 58 45, -- 59
    .add 59 46, -- 60
    .add 60 47, -- 61
    .add 61 48, -- 62
    .add 62 49, -- 63
    .add 44 42, -- 64
    .add 64 47, -- 65
    .add 45 43, -- 66
    .add 66 48, -- 67
    .add 47 48, -- 68
    .add 68 49, -- 69
    .const 0, -- 70
    .add 70 38, -- 71
    .mul 38 70, -- 72
    .add 70 72, -- 73
    .add 71 39, -- 74
    .mul 39 56, -- 75
    .add 73 75, -- 76
    .add 74 40, -- 77
    .const 2, -- 78
    .mul 40 78, -- 79
    .add 76 79, -- 80
    .add 77 41, -- 81
    .const 3, -- 82
    .mul 41 82, -- 83
    .add 80 83, -- 84
    .add 46 49, -- 85
    .add 42 44, -- 86
    .add 43 45, -- 87
    .sub 63 69, -- 88
    .const 256, -- 89
    .mul 21 89, -- 90
    .add 90 20, -- 91
    .mul 91 89, -- 92
    .add 92 19, -- 93
    .mul 93 89, -- 94
    .add 94 18, -- 95
    .add 95 33, -- 96
    .mul 57 34, -- 97
    .const 255, -- 98
    .mul 97 98, -- 99
    .add 36 37, -- 100
    .sub 100 32, -- 101
    .const 536870912, -- 102
    .mul 101 102, -- 103
    .sub 63 56, -- 104
    .mul 63 104, -- 105
    .sub 42 56, -- 106
    .mul 42 106, -- 107
    .sub 43 56, -- 108
    .mul 43 108, -- 109
    .sub 44 56, -- 110
    .mul 44 110, -- 111
    .sub 45 56, -- 112
    .mul 45 112, -- 113
    .sub 46 56, -- 114
    .mul 46 114, -- 115
    .sub 47 56, -- 116
    .mul 47 116, -- 117
    .sub 48 56, -- 118
    .mul 48 118, -- 119
    .sub 49 56, -- 120
    .mul 49 120, -- 121
    .sub 34 56, -- 122
    .mul 34 122, -- 123
    .sub 56 57, -- 124
    .mul 124 34, -- 125
    .sub 38 56, -- 126
    .mul 38 126, -- 127
    .sub 39 56, -- 128
    .mul 39 128, -- 129
    .sub 40 56, -- 130
    .mul 40 130, -- 131
    .sub 41 56, -- 132
    .mul 41 132, -- 133
    .mul 65 84, -- 134
    .sub 84 56, -- 135
    .mul 67 135, -- 136
    .const 1073741824, -- 137
    .mul 136 137, -- 138
    .add 134 138, -- 139
    .sub 35 139, -- 140
    .sub 96 35, -- 141
    .mul 88 141, -- 142
    .mul 69 32, -- 143
    .add 142 143, -- 144
    .sub 36 144, -- 145
    .mul 88 32, -- 146
    .mul 69 141, -- 147
    .add 146 147, -- 148
    .sub 37 148, -- 149
    .sub 56 81, -- 150
    .mul 65 150, -- 151
    .sub 78 81, -- 152
    .mul 67 152, -- 153
    .sub 56 84, -- 154
    .mul 67 154, -- 155
    .const 5, -- 156
    .sub 156 84, -- 157
    .mul 155 157, -- 158
    .sub 99 51, -- 159
    .mul 86 159, -- 160
    .sub 99 52, -- 161
    .mul 86 161, -- 162
    .sub 99 53, -- 163
    .mul 86 163, -- 164
    .sub 50 28, -- 165
    .mul 86 165, -- 166
    .mul 166 38, -- 167
    .sub 8 28, -- 168
    .mul 47 168, -- 169
    .mul 169 38, -- 170
    .sub 50 29, -- 171
    .mul 86 171, -- 172
    .mul 172 39, -- 173
    .sub 9 28, -- 174
    .mul 47 174, -- 175
    .mul 175 39, -- 176
    .sub 50 30, -- 177
    .mul 86 177, -- 178
    .mul 178 40, -- 179
    .sub 10 28, -- 180
    .mul 47 180, -- 181
    .mul 181 40, -- 182
    .sub 50 31, -- 183
    .mul 86 183, -- 184
    .mul 184 41, -- 185
    .sub 11 28, -- 186
    .mul 47 186, -- 187
    .mul 187 41, -- 188
    .mul 87 161, -- 189
    .mul 87 163, -- 190
    .mul 157 102, -- 191
    .mul 135 102, -- 192
    .mul 87 191, -- 193
    .mul 193 165, -- 194
    .sub 51 29, -- 195
    .mul 193 195, -- 196
    .mul 87 192, -- 197
    .mul 197 177, -- 198
    .sub 51 31, -- 199
    .mul 197 199, -- 200
    .mul 48 191, -- 201
    .mul 201 168, -- 202
    .sub 9 29, -- 203
    .mul 201 203, -- 204
    .mul 48 192, -- 205
    .mul 205 180, -- 206
    .sub 11 29, -- 207
    .mul 205 207, -- 208
    .mul 46 165, -- 209
    .mul 49 168, -- 210
    .add 209 210, -- 211
    .mul 46 195, -- 212
    .mul 49 203, -- 213
    .add 212 213, -- 214
    .sub 52 30, -- 215
    .mul 46 215, -- 216
    .sub 10 30, -- 217
    .mul 49 217, -- 218
    .add 216 218, -- 219
    .sub 53 31, -- 220
    .mul 46 220, -- 221
    .sub 11 31, -- 222
    .mul 49 222, -- 223
    .add 221 223, -- 224
    .sub 18 13, -- 225
    .mul 63 225, -- 226
    .sub 19 14, -- 227
    .mul 63 227, -- 228
    .sub 20 15, -- 229
    .mul 63 229, -- 230
    .sub 21 16, -- 231
    .mul 63 231, -- 232
    .sub 28 23, -- 233
    .mul 63 233, -- 234
    .sub 29 24, -- 235
    .mul 63 235, -- 236
    .sub 30 25, -- 237
    .mul 63 237, -- 238
    .sub 31 26, -- 239
    .mul 63 239, -- 240
    .sub 56 38, -- 241
    .mul 68 241, -- 242
    .sub 8 3, -- 243
    .mul 242 243, -- 244
    .sub 56 39, -- 245
    .mul 68 245, -- 246
    .sub 9 4, -- 247
    .mul 246 247, -- 248
    .sub 56 40, -- 249
    .mul 68 249, -- 250
    .sub 10 5, -- 251
    .mul 250 251, -- 252
    .sub 56 41, -- 253
    .mul 68 253, -- 254
    .sub 11 6, -- 255
    .mul 254 255, -- 256
    .sub 54 56, -- 257
    .mul 54 257, -- 258
    .sub 56 54, -- 259
    .mul 32 259, -- 260
    .mul 32 55, -- 261
    .sub 261 54, -- 262
    .mul 54 50, -- 263
    .sub 8 263, -- 264
    .mul 54 51, -- 265
    .sub 9 265, -- 266
    .mul 54 52, -- 267
    .sub 10 267, -- 268
    .mul 54 53, -- 269
    .sub 11 269, -- 270
    .mul 88 264, -- 271
    .mul 88 266, -- 272
    .mul 88 268, -- 273
    .mul 88 270, -- 274
    .sub 56 88, -- 275
    .mul 275 50, -- 276
    .mul 275 51, -- 277
    .mul 275 52, -- 278
    .mul 275 53, -- 279
    .mul 63 21, -- 280
    .sub 0 56, -- 281
    .const 4, -- 282
    .mul 281 282, -- 283
    .add 283 78, -- 284
    .add 283 56, -- 285
    .sub 285 17, -- 286
    .sub 286 56, -- 287
    .add 284 88, -- 288
    .sub 288 27, -- 289
    .sub 289 56, -- 290
    .add 284 69, -- 291
    .sub 291 7, -- 292
    .sub 292 56, -- 293
    .neg 63, -- 294
    .const 19, -- 295
    .mul 42 295, -- 296
    .const 20, -- 297
    .mul 43 297, -- 298
    .add 296 298, -- 299
    .const 21, -- 300
    .mul 46 300, -- 301
    .add 299 301, -- 302
    .const 22, -- 303
    .mul 44 303, -- 304
    .add 302 304, -- 305
    .const 23, -- 306
    .mul 45 306, -- 307
    .add 305 307, -- 308
    .const 24, -- 309
    .mul 47 309, -- 310
    .add 308 310, -- 311
    .const 25, -- 312
    .mul 48 312, -- 313
    .add 311 313, -- 314
    .const 26, -- 315
    .mul 49 315, -- 316
    .add 314 316, -- 317
    .add 1 282, -- 318
    .add 0 56, -- 319
    .const 128, -- 320
    .mul 34 320, -- 321
    .sub 50 321, -- 322
    .sub 51 321, -- 323
    .neg 42, -- 324
    .neg 43, -- 325
    .col 56, -- 326
    .sub 326 317, -- 327
    .col 57, -- 328
    .sub 328 318, -- 329
    .col 58, -- 330
    .sub 330 319, -- 331
    .col 59, -- 332
    .sub 332 285, -- 333
    .col 60, -- 334
    .sub 334 88, -- 335
    .col 61, -- 336
    .sub 336 288, -- 337
    .col 62, -- 338
    .sub 338 69, -- 339
    .col 63, -- 340
    .sub 340 291 -- 341
  ]
  nodeCount := 342
  constraints := [
    105, 107, 109, 111, 113, 115, 117, 119,
    121, 123, 125, 127, 129, 131, 133, 140,
    145, 149, 151, 153, 158, 160, 162, 164,
    167, 170, 173, 176, 179, 182, 185, 188,
    189, 190, 194, 196, 198, 200, 202, 204,
    206, 208, 211, 214, 219, 224, 226, 228,
    230, 232, 234, 236, 238, 240, 244, 248,
    252, 256, 258, 260, 262, 271, 272, 273,
    274, 276, 277, 278, 279, 280, 104, 327,
    329, 331, 333, 335, 337, 339, 341
  ]
  lookups := [
    { domain := .programAccess, role := .request,
      numerator := 294, tuple := [1, 317, 12, 32, 33] }, -- lookup 0
    { domain := .registersState, role := .consumed,
      numerator := 294, tuple := [1, 0] }, -- lookup 1
    { domain := .registersState, role := .emitted,
      numerator := 63, tuple := [318, 319] }, -- lookup 2
    { domain := .memoryAccess, role := .consumed,
      numerator := 294, tuple := [70, 12, 17, 13, 14, 15, 16] }, -- lookup 3
    { domain := .memoryAccess, role := .emitted,
      numerator := 63, tuple := [70, 12, 285, 18, 19, 20, 21] }, -- lookup 4
    { domain := .rangeCheck20, role := .request,
      numerator := 294, tuple := [287] }, -- lookup 5
    { domain := .rangeCheck20, role := .request,
      numerator := 294, tuple := [103] }, -- lookup 6
    { domain := .rangeCheckM31, role := .request,
      numerator := 294, tuple := [18, 21] }, -- lookup 7
    { domain := .memoryAccess, role := .consumed,
      numerator := 294, tuple := [88, 36, 27, 23, 24, 25, 26] }, -- lookup 8
    { domain := .memoryAccess, role := .emitted,
      numerator := 63, tuple := [88, 36, 288, 28, 29, 30, 31] }, -- lookup 9
    { domain := .rangeCheck20, role := .request,
      numerator := 294, tuple := [290] }, -- lookup 10
    { domain := .memoryAccess, role := .consumed,
      numerator := 294, tuple := [69, 37, 7, 3, 4, 5, 6] }, -- lookup 11
    { domain := .memoryAccess, role := .emitted,
      numerator := 63, tuple := [69, 37, 291, 8, 9, 10, 11] }, -- lookup 12
    { domain := .rangeCheck20, role := .request,
      numerator := 294, tuple := [293] }, -- lookup 13
    { domain := .rangeCheckM31, role := .request,
      numerator := 324, tuple := [70, 322] }, -- lookup 14
    { domain := .rangeCheckM31, role := .request,
      numerator := 325, tuple := [70, 323] } -- lookup 15
  ]

-- The same circuit with every node argument rewritten to its offset
-- from the head of the reversed memo table. This is the table the
-- proofs in LoadStoreBridge.lean evaluate; the `#guard` below is what
-- ties it to the verbatim export above.
def loadStoreCircuitCompiled : MulhCircuit where
  family := "load_store"
  modulus := 2147483647
  columns := loadStoreCircuit.columns
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
    .col 47, -- 47
    .col 48, -- 48
    .col 49, -- 49
    .col 50, -- 50
    .col 51, -- 51
    .col 52, -- 52
    .col 53, -- 53
    .col 54, -- 54
    .col 55, -- 55
    .const 1, -- 56
    .add 14 13, -- 57
    .add 0 13, -- 58
    .add 0 13, -- 59
    .add 0 13, -- 60
    .add 0 13, -- 61
    .add 0 13, -- 62
    .add 0 13, -- 63
    .add 19 21, -- 64
    .add 0 17, -- 65
    .add 20 22, -- 66
    .add 0 18, -- 67
    .add 20 19, -- 68
    .add 0 19, -- 69
    .const 0, -- 70
    .add 0 32, -- 71
    .mul 33 1, -- 72
    .add 2 0, -- 73
    .add 2 34, -- 74
    .mul 35 18, -- 75
    .add 2 0, -- 76
    .add 2 36, -- 77
    .const 2, -- 78
    .mul 38 0, -- 79
    .add 3 0, -- 80
    .add 3 39, -- 81
    .const 3, -- 82
    .mul 41 0, -- 83
    .add 3 0, -- 84
    .add 38 35, -- 85
    .add 43 41, -- 86
    .add 43 41, -- 87
    .sub 24 18, -- 88
    .const 256, -- 89
    .mul 68 0, -- 90
    .add 0 70, -- 91
    .mul 0 2, -- 92
    .add 0 73, -- 93
    .mul 0 4, -- 94
    .add 0 76, -- 95
    .add 0 62, -- 96
    .mul 39 62, -- 97
    .const 255, -- 98
    .mul 1 0, -- 99
    .add 63 62, -- 100
    .sub 0 68, -- 101
    .const 536870912, -- 102
    .mul 1 0, -- 103
    .sub 40 47, -- 104
    .mul 41 0, -- 105
    .sub 63 49, -- 106
    .mul 64 0, -- 107
    .sub 64 51, -- 108
    .mul 65 0, -- 109
    .sub 65 53, -- 110
    .mul 66 0, -- 111
    .sub 66 55, -- 112
    .mul 67 0, -- 113
    .sub 67 57, -- 114
    .mul 68 0, -- 115
    .sub 68 59, -- 116
    .mul 69 0, -- 117
    .sub 69 61, -- 118
    .mul 70 0, -- 119
    .sub 70 63, -- 120
    .mul 71 0, -- 121
    .sub 87 65, -- 122
    .mul 88 0, -- 123
    .sub 67 66, -- 124
    .mul 0 90, -- 125
    .sub 87 69, -- 126
    .mul 88 0, -- 127
    .sub 88 71, -- 128
    .mul 89 0, -- 129
    .sub 89 73, -- 130
    .mul 90 0, -- 131
    .sub 90 75, -- 132
    .mul 91 0, -- 133
    .mul 68 49, -- 134
    .sub 50 78, -- 135
    .mul 68 0, -- 136
    .const 1073741824, -- 137
    .mul 1 0, -- 138
    .add 4 0, -- 139
    .sub 104 0, -- 140
    .sub 44 105, -- 141
    .mul 53 0, -- 142
    .mul 73 110, -- 143
    .add 1 0, -- 144
    .sub 108 0, -- 145
    .mul 57 113, -- 146
    .mul 77 5, -- 147
    .add 1 0, -- 148
    .sub 111 0, -- 149
    .sub 93 68, -- 150
    .mul 85 0, -- 151
    .sub 73 70, -- 152
    .mul 85 0, -- 153
    .sub 97 69, -- 154
    .mul 87 0, -- 155
    .const 5, -- 156
    .sub 0 72, -- 157
    .mul 2 0, -- 158
    .sub 59 107, -- 159
    .mul 73 0, -- 160
    .sub 61 108, -- 161
    .mul 75 0, -- 162
    .sub 63 109, -- 163
    .mul 77 0, -- 164
    .sub 114 136, -- 165
    .mul 79 0, -- 166
    .mul 0 128, -- 167
    .sub 159 139, -- 168
    .mul 121 0, -- 169
    .mul 0 131, -- 170
    .sub 120 141, -- 171
    .mul 85 0, -- 172
    .mul 0 133, -- 173
    .sub 164 145, -- 174
    .mul 127 0, -- 175
    .mul 0 136, -- 176
    .sub 126 146, -- 177
    .mul 91 0, -- 178
    .mul 0 138, -- 179
    .sub 169 151, -- 180
    .mul 133 0, -- 181
    .mul 0 141, -- 182
    .sub 132 151, -- 183
    .mul 97 0, -- 184
    .mul 0 143, -- 185
    .sub 174 157, -- 186
    .mul 139 0, -- 187
    .mul 0 146, -- 188
    .mul 101 27, -- 189
    .mul 102 26, -- 190
    .mul 33 88, -- 191
    .mul 56 89, -- 192
    .mul 105 1, -- 193
    .mul 0 28, -- 194
    .sub 143 165, -- 195
    .mul 2 0, -- 196
    .mul 109 4, -- 197
    .mul 0 20, -- 198
    .sub 147 167, -- 199
    .mul 2 0, -- 200
    .mul 152 9, -- 201
    .mul 0 33, -- 202
    .sub 193 173, -- 203
    .mul 2 0, -- 204
    .mul 156 12, -- 205
    .mul 0 25, -- 206
    .sub 195 177, -- 207
    .mul 2 0, -- 208
    .mul 162 43, -- 209
    .mul 160 41, -- 210
    .add 1 0, -- 211
    .mul 165 16, -- 212
    .mul 163 9, -- 213
    .add 1 0, -- 214
    .sub 162 184, -- 215
    .mul 169 0, -- 216
    .sub 206 186, -- 217
    .mul 168 0, -- 218
    .add 2 0, -- 219
    .sub 166 188, -- 220
    .mul 174 0, -- 221
    .sub 210 190, -- 222
    .mul 173 0, -- 223
    .add 2 0, -- 224
    .sub 206 211, -- 225
    .mul 162 0, -- 226
    .sub 207 212, -- 227
    .mul 164 0, -- 228
    .sub 208 213, -- 229
    .mul 166 0, -- 230
    .sub 209 214, -- 231
    .mul 168 0, -- 232
    .sub 204 209, -- 233
    .mul 170 0, -- 234
    .sub 205 210, -- 235
    .mul 172 0, -- 236
    .sub 206 211, -- 237
    .mul 174 0, -- 238
    .sub 207 212, -- 239
    .mul 176 0, -- 240
    .sub 184 202, -- 241
    .mul 173 0, -- 242
    .sub 234 239, -- 243
    .mul 1 0, -- 244
    .sub 188 205, -- 245
    .mul 177 0, -- 246
    .sub 237 242, -- 247
    .mul 1 0, -- 248
    .sub 192 208, -- 249
    .mul 181 0, -- 250
    .sub 240 245, -- 251
    .mul 1 0, -- 252
    .sub 196 211, -- 253
    .mul 185 0, -- 254
    .sub 243 248, -- 255
    .mul 1 0, -- 256
    .sub 202 200, -- 257
    .mul 203 0, -- 258
    .sub 202 204, -- 259
    .mul 227 0, -- 260
    .mul 228 205, -- 261
    .sub 0 207, -- 262
    .mul 208 212, -- 263
    .sub 255 0, -- 264
    .mul 210 213, -- 265
    .sub 256 0, -- 266
    .mul 212 214, -- 267
    .sub 257 0, -- 268
    .mul 214 215, -- 269
    .sub 258 0, -- 270
    .mul 182 6, -- 271
    .mul 183 5, -- 272
    .mul 184 4, -- 273
    .mul 185 3, -- 274
    .sub 218 186, -- 275
    .mul 0 225, -- 276
    .mul 1 225, -- 277
    .mul 2 225, -- 278
    .mul 3 225, -- 279
    .mul 216 258, -- 280
    .sub 280 224, -- 281
    .const 4, -- 282
    .mul 1 0, -- 283
    .add 0 205, -- 284
    .add 1 228, -- 285
    .sub 0 268, -- 286
    .sub 0 230, -- 287
    .add 3 199, -- 288
    .sub 0 261, -- 289
    .sub 0 233, -- 290
    .add 6 221, -- 291
    .sub 0 284, -- 292
    .sub 0 236, -- 293
    .neg 230, -- 294
    .const 19, -- 295
    .mul 253 0, -- 296
    .const 20, -- 297
    .mul 254 0, -- 298
    .add 2 0, -- 299
    .const 21, -- 300
    .mul 254 0, -- 301
    .add 2 0, -- 302
    .const 22, -- 303
    .mul 259 0, -- 304
    .add 2 0, -- 305
    .const 23, -- 306
    .mul 261 0, -- 307
    .add 2 0, -- 308
    .const 24, -- 309
    .mul 262 0, -- 310
    .add 2 0, -- 311
    .const 25, -- 312
    .mul 264 0, -- 313
    .add 2 0, -- 314
    .const 26, -- 315
    .mul 266 0, -- 316
    .add 2 0, -- 317
    .add 316 35, -- 318
    .add 318 262, -- 319
    .const 128, -- 320
    .mul 286 0, -- 321
    .sub 271 0, -- 322
    .sub 271 1, -- 323
    .neg 281, -- 324
    .neg 281, -- 325
    .col 56, -- 326
    .sub 0 9, -- 327
    .col 57, -- 328
    .sub 0 10, -- 329
    .col 58, -- 330
    .sub 0 11, -- 331
    .col 59, -- 332
    .sub 0 47, -- 333
    .col 60, -- 334
    .sub 0 246, -- 335
    .col 61, -- 336
    .sub 0 48, -- 337
    .col 62, -- 338
    .sub 0 269, -- 339
    .col 63, -- 340
    .sub 0 49 -- 341
  ]
  nodeCount := 342
  constraints := loadStoreCircuit.constraints
  lookups := loadStoreCircuit.lookups

-- The localisation really is the mechanical rewrite of the export.
#guard loadStoreCircuitCompiled == loadStoreCircuit.localise

-- The wire validation A's decoder performs, run on this table.
#guard loadStoreCircuit.wellFormed

-- Sanity: the table is the size the export reports.
#guard loadStoreCircuit.columns.length == 64
#guard loadStoreCircuit.nodes.length == 342
#guard loadStoreCircuit.constraints.length == 79
#guard loadStoreCircuit.lookups.length == 16

-- A concrete satisfying row -- `LW x7, 0(x1)` with `x1 = 64` and `0x44332291` in memory at 64 -- and the values an independent
-- evaluator (this generator, walking the same JSON) computes for it.
-- This is the differential test between the two interpreters.
def loadStoreLoadWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 100, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 145, M31.reduce 34, M31.reduce 51, M31.reduce 68,
    M31.reduce 1, M31.reduce 64, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 3, M31.reduce 64, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 145,
    M31.reduce 34, M31.reduce 51, M31.reduce 68, M31.reduce 3,
    M31.reduce 145, M31.reduce 34, M31.reduce 51, M31.reduce 68,
    M31.reduce 7, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 64, M31.reduce 7, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 145, M31.reduce 34,
    M31.reduce 51, M31.reduce 68, M31.reduce 1, M31.reduce 1840700269,
    M31.reduce 21, M31.reduce 104, M31.reduce 6, M31.reduce 17,
    M31.reduce 1, M31.reduce 19, M31.reduce 0, M31.reduce 18
  ]

#guard loadStoreCircuitCompiled.constraintValues loadStoreLoadWitnessColumns ==
  List.replicate 79 0

#guard loadStoreCircuitCompiled.fixedRequestsHold loadStoreLoadWitnessColumns

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupTuple loadStoreLoadWitnessColumns entry).map M31.toNat) ==
  [
    [100, 21, 1, 7, 0],
    [100, 5],
    [104, 6],
    [0, 1, 3, 64, 0, 0, 0],
    [0, 1, 17, 64, 0, 0, 0],
    [13],
    [16],
    [64, 0],
    [1, 64, 3, 145, 34, 51, 68],
    [1, 64, 19, 145, 34, 51, 68],
    [15],
    [0, 7, 3, 0, 0, 0, 0],
    [0, 7, 18, 145, 34, 51, 68],
    [14],
    [0, 145],
    [0, 34]
  ]

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupNumerator loadStoreLoadWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 0, 0]

-- A concrete satisfying row -- `SB x2, 1(x1)` with `x1 = 65`, `x2 = 0xab` and `0x44332211` in memory at 64 -- and the values an independent
-- evaluator (this generator, walking the same JSON) computes for it.
-- This is the differential test between the two interpreters.
def loadStoreStoreWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 200, M31.reduce 0, M31.reduce 17,
    M31.reduce 34, M31.reduce 51, M31.reduce 68, M31.reduce 3,
    M31.reduce 17, M31.reduce 171, M31.reduce 51, M31.reduce 68,
    M31.reduce 1, M31.reduce 65, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 3, M31.reduce 65, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 171,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 171, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 2, M31.reduce 0, M31.reduce 0, M31.reduce 1,
    M31.reduce 2, M31.reduce 64, M31.reduce 0, M31.reduce 1,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 1,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 1073741824,
    M31.reduce 24, M31.reduce 204, M31.reduce 6, M31.reduce 17,
    M31.reduce 0, M31.reduce 18, M31.reduce 1, M31.reduce 19
  ]

#guard loadStoreCircuitCompiled.constraintValues loadStoreStoreWitnessColumns ==
  List.replicate 79 0

#guard loadStoreCircuitCompiled.fixedRequestsHold loadStoreStoreWitnessColumns

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupTuple loadStoreStoreWitnessColumns entry).map M31.toNat) ==
  [
    [200, 24, 1, 2, 0],
    [200, 5],
    [204, 6],
    [0, 1, 3, 65, 0, 0, 0],
    [0, 1, 17, 65, 0, 0, 0],
    [13],
    [16],
    [65, 0],
    [0, 2, 3, 171, 0, 0, 0],
    [0, 2, 18, 171, 0, 0, 0],
    [14],
    [1, 64, 3, 17, 34, 51, 68],
    [1, 64, 19, 17, 171, 51, 68],
    [15],
    [0, 0],
    [0, 0]
  ]

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupNumerator loadStoreStoreWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 0, 0]

-- The gate on `fixedRequestsHold` is load-bearing, not cosmetic. On the
-- `LW` row above, lookup 14's tuple is `(0, 145)` and `145` is not a
-- seven-bit value, so the request is outside `range_check_m31`. Its
-- numerator `-is_lb` is zero, so the production LogUp sum never asks
-- for it. Widening the bridge's theorem to the ungated reading would
-- make it false; this `#guard` is what stops that happening silently.
#guard !loadStoreCircuitCompiled.fixedRequestsHoldUnconditional
    loadStoreLoadWitnessColumns

end RiscvRefinement.Air.Bridge
