-- GENERATED FILE. DO NOT EDIT.
-- Source: generated/air/lb.air-ir-v2.json
-- Content digest: 8c63862acc341a4dca936e7fc5ae98a46bd38ed87a616b8e070d38bff91d5fab
-- This exact circuit is interpreted by the shared MulhCircuit evaluator.

import RiscvRefinement.Air.Bridge.MulhProgram

namespace RiscvRefinement.Air.Bridge

/-- Content digest of the canonical production AIR export encoded below. -/
def loadStoreProgramIrDigest : String :=
  "8c63862acc341a4dca936e7fc5ae98a46bd38ed87a616b8e070d38bff91d5fab"

-- 48 columns, 301 nodes, 63 constraints, 16 lookups.
def loadStoreCircuit : MulhCircuit where
  family := "load_store"
  modulus := 2147483647
  columns := [
    "clk", "pc", "dst_addr", "dst_previous_0",
    "dst_previous_1", "dst_previous_2", "dst_previous_3", "dst_previous_clock",
    "dst_next_0", "dst_next_1", "dst_next_2", "dst_next_3",
    "rs1_addr", "rs1_value_0", "rs1_value_1", "rs1_value_2",
    "rs1_value_3", "rs1_previous_clock", "src_addr", "src_value_0",
    "src_value_1", "src_value_2", "src_value_3", "src_previous_clock",
    "r2_idx", "imm_felt", "src_msb", "shift_amount",
    "src_addr_selector", "dst_addr_selector", "markers_0", "markers_1",
    "markers_2", "markers_3", "is_lb", "is_lh",
    "is_lbu", "is_lhu", "is_lw", "is_sb",
    "is_sh", "is_sw", "result_0", "result_1",
    "result_2", "result_3", "destination_nonzero", "destination_inverse"
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
    .const 1, -- 48
    .add 34 35, -- 49
    .add 49 36, -- 50
    .add 50 37, -- 51
    .add 51 38, -- 52
    .add 52 39, -- 53
    .add 53 40, -- 54
    .add 54 41, -- 55
    .add 36 34, -- 56
    .add 56 39, -- 57
    .add 37 35, -- 58
    .add 58 40, -- 59
    .add 39 40, -- 60
    .add 60 41, -- 61
    .const 0, -- 62
    .add 62 30, -- 63
    .mul 30 62, -- 64
    .add 62 64, -- 65
    .add 63 31, -- 66
    .mul 31 48, -- 67
    .add 65 67, -- 68
    .add 66 32, -- 69
    .const 2, -- 70
    .mul 32 70, -- 71
    .add 68 71, -- 72
    .add 69 33, -- 73
    .const 3, -- 74
    .mul 33 74, -- 75
    .add 72 75, -- 76
    .add 34 36, -- 77
    .add 35 37, -- 78
    .sub 55 61, -- 79
    .const 256, -- 80
    .mul 16 80, -- 81
    .add 81 15, -- 82
    .mul 82 80, -- 83
    .add 83 14, -- 84
    .mul 84 80, -- 85
    .add 85 13, -- 86
    .add 86 25, -- 87
    .mul 49 26, -- 88
    .const 255, -- 89
    .mul 88 89, -- 90
    .add 28 29, -- 91
    .sub 91 24, -- 92
    .const 536870912, -- 93
    .mul 92 93, -- 94
    .sub 55 48, -- 95
    .mul 55 95, -- 96
    .sub 34 48, -- 97
    .mul 34 97, -- 98
    .sub 35 48, -- 99
    .mul 35 99, -- 100
    .sub 36 48, -- 101
    .mul 36 101, -- 102
    .sub 37 48, -- 103
    .mul 37 103, -- 104
    .sub 38 48, -- 105
    .mul 38 105, -- 106
    .sub 39 48, -- 107
    .mul 39 107, -- 108
    .sub 40 48, -- 109
    .mul 40 109, -- 110
    .sub 41 48, -- 111
    .mul 41 111, -- 112
    .sub 26 48, -- 113
    .mul 26 113, -- 114
    .sub 48 49, -- 115
    .mul 115 26, -- 116
    .sub 30 48, -- 117
    .mul 30 117, -- 118
    .sub 31 48, -- 119
    .mul 31 119, -- 120
    .sub 32 48, -- 121
    .mul 32 121, -- 122
    .sub 33 48, -- 123
    .mul 33 123, -- 124
    .mul 57 76, -- 125
    .sub 76 48, -- 126
    .mul 59 126, -- 127
    .const 1073741824, -- 128
    .mul 127 128, -- 129
    .add 125 129, -- 130
    .sub 27 130, -- 131
    .sub 87 27, -- 132
    .mul 79 132, -- 133
    .mul 61 24, -- 134
    .add 133 134, -- 135
    .sub 28 135, -- 136
    .mul 79 24, -- 137
    .mul 61 132, -- 138
    .add 137 138, -- 139
    .sub 29 139, -- 140
    .sub 48 73, -- 141
    .mul 57 141, -- 142
    .sub 70 73, -- 143
    .mul 59 143, -- 144
    .sub 48 76, -- 145
    .mul 59 145, -- 146
    .const 5, -- 147
    .sub 147 76, -- 148
    .mul 146 148, -- 149
    .sub 90 43, -- 150
    .mul 77 150, -- 151
    .sub 90 44, -- 152
    .mul 77 152, -- 153
    .sub 90 45, -- 154
    .mul 77 154, -- 155
    .sub 42 19, -- 156
    .mul 77 156, -- 157
    .mul 157 30, -- 158
    .sub 8 19, -- 159
    .mul 39 159, -- 160
    .mul 160 30, -- 161
    .sub 42 20, -- 162
    .mul 77 162, -- 163
    .mul 163 31, -- 164
    .sub 9 19, -- 165
    .mul 39 165, -- 166
    .mul 166 31, -- 167
    .sub 42 21, -- 168
    .mul 77 168, -- 169
    .mul 169 32, -- 170
    .sub 10 19, -- 171
    .mul 39 171, -- 172
    .mul 172 32, -- 173
    .sub 42 22, -- 174
    .mul 77 174, -- 175
    .mul 175 33, -- 176
    .sub 11 19, -- 177
    .mul 39 177, -- 178
    .mul 178 33, -- 179
    .mul 78 152, -- 180
    .mul 78 154, -- 181
    .mul 148 93, -- 182
    .mul 126 93, -- 183
    .mul 78 182, -- 184
    .mul 184 156, -- 185
    .sub 43 20, -- 186
    .mul 184 186, -- 187
    .mul 78 183, -- 188
    .mul 188 168, -- 189
    .sub 43 22, -- 190
    .mul 188 190, -- 191
    .mul 40 182, -- 192
    .mul 192 159, -- 193
    .sub 9 20, -- 194
    .mul 192 194, -- 195
    .mul 40 183, -- 196
    .mul 196 171, -- 197
    .sub 11 20, -- 198
    .mul 196 198, -- 199
    .mul 38 156, -- 200
    .mul 41 159, -- 201
    .add 200 201, -- 202
    .mul 38 186, -- 203
    .mul 41 194, -- 204
    .add 203 204, -- 205
    .sub 44 21, -- 206
    .mul 38 206, -- 207
    .sub 10 21, -- 208
    .mul 41 208, -- 209
    .add 207 209, -- 210
    .sub 45 22, -- 211
    .mul 38 211, -- 212
    .sub 11 22, -- 213
    .mul 41 213, -- 214
    .add 212 214, -- 215
    .sub 48 30, -- 216
    .mul 60 216, -- 217
    .sub 8 3, -- 218
    .mul 217 218, -- 219
    .sub 48 31, -- 220
    .mul 60 220, -- 221
    .sub 9 4, -- 222
    .mul 221 222, -- 223
    .sub 48 32, -- 224
    .mul 60 224, -- 225
    .sub 10 5, -- 226
    .mul 225 226, -- 227
    .sub 48 33, -- 228
    .mul 60 228, -- 229
    .sub 11 6, -- 230
    .mul 229 230, -- 231
    .sub 46 48, -- 232
    .mul 46 232, -- 233
    .sub 48 46, -- 234
    .mul 24 234, -- 235
    .mul 24 47, -- 236
    .sub 236 46, -- 237
    .mul 46 42, -- 238
    .sub 8 238, -- 239
    .mul 46 43, -- 240
    .sub 9 240, -- 241
    .mul 46 44, -- 242
    .sub 10 242, -- 243
    .mul 46 45, -- 244
    .sub 11 244, -- 245
    .mul 79 239, -- 246
    .mul 79 241, -- 247
    .mul 79 243, -- 248
    .mul 79 245, -- 249
    .sub 48 79, -- 250
    .mul 250 42, -- 251
    .mul 250 43, -- 252
    .mul 250 44, -- 253
    .mul 250 45, -- 254
    .mul 55 16, -- 255
    .sub 0 48, -- 256
    .const 4, -- 257
    .mul 256 257, -- 258
    .add 258 70, -- 259
    .add 258 48, -- 260
    .sub 260 17, -- 261
    .sub 261 48, -- 262
    .add 259 79, -- 263
    .sub 263 23, -- 264
    .sub 264 48, -- 265
    .add 259 61, -- 266
    .sub 266 7, -- 267
    .sub 267 48, -- 268
    .neg 55, -- 269
    .const 19, -- 270
    .mul 34 270, -- 271
    .const 20, -- 272
    .mul 35 272, -- 273
    .add 271 273, -- 274
    .const 21, -- 275
    .mul 38 275, -- 276
    .add 274 276, -- 277
    .const 22, -- 278
    .mul 36 278, -- 279
    .add 277 279, -- 280
    .const 23, -- 281
    .mul 37 281, -- 282
    .add 280 282, -- 283
    .const 24, -- 284
    .mul 39 284, -- 285
    .add 283 285, -- 286
    .const 25, -- 287
    .mul 40 287, -- 288
    .add 286 288, -- 289
    .const 26, -- 290
    .mul 41 290, -- 291
    .add 289 291, -- 292
    .add 1 257, -- 293
    .add 0 48, -- 294
    .const 128, -- 295
    .mul 26 295, -- 296
    .sub 42 296, -- 297
    .sub 43 296, -- 298
    .neg 34, -- 299
    .neg 35 -- 300
  ]
  nodeCount := 301
  constraints := [
    96, 98, 100, 102, 104, 106, 108, 110,
    112, 114, 116, 118, 120, 122, 124, 131,
    136, 140, 142, 144, 149, 151, 153, 155,
    158, 161, 164, 167, 170, 173, 176, 179,
    180, 181, 185, 187, 189, 191, 193, 195,
    197, 199, 202, 205, 210, 215, 219, 223,
    227, 231, 233, 235, 237, 246, 247, 248,
    249, 251, 252, 253, 254, 255, 95
  ]
  lookups := [
    { domain := .programAccess, role := .request,
      numerator := 269, tuple := [1, 292, 12, 24, 25] }, -- lookup 0
    { domain := .registersState, role := .consumed,
      numerator := 269, tuple := [1, 0] }, -- lookup 1
    { domain := .registersState, role := .emitted,
      numerator := 55, tuple := [293, 294] }, -- lookup 2
    { domain := .memoryAccess, role := .consumed,
      numerator := 269, tuple := [62, 12, 17, 13, 14, 15, 16] }, -- lookup 3
    { domain := .memoryAccess, role := .emitted,
      numerator := 55, tuple := [62, 12, 260, 13, 14, 15, 16] }, -- lookup 4
    { domain := .rangeCheck20, role := .request,
      numerator := 269, tuple := [262] }, -- lookup 5
    { domain := .rangeCheck20, role := .request,
      numerator := 269, tuple := [94] }, -- lookup 6
    { domain := .rangeCheckM31, role := .request,
      numerator := 269, tuple := [13, 16] }, -- lookup 7
    { domain := .memoryAccess, role := .consumed,
      numerator := 269, tuple := [79, 28, 23, 19, 20, 21, 22] }, -- lookup 8
    { domain := .memoryAccess, role := .emitted,
      numerator := 55, tuple := [79, 28, 263, 19, 20, 21, 22] }, -- lookup 9
    { domain := .rangeCheck20, role := .request,
      numerator := 269, tuple := [265] }, -- lookup 10
    { domain := .memoryAccess, role := .consumed,
      numerator := 269, tuple := [61, 29, 7, 3, 4, 5, 6] }, -- lookup 11
    { domain := .memoryAccess, role := .emitted,
      numerator := 55, tuple := [61, 29, 266, 8, 9, 10, 11] }, -- lookup 12
    { domain := .rangeCheck20, role := .request,
      numerator := 269, tuple := [268] }, -- lookup 13
    { domain := .rangeCheckM31, role := .request,
      numerator := 299, tuple := [62, 297] }, -- lookup 14
    { domain := .rangeCheckM31, role := .request,
      numerator := 300, tuple := [62, 298] } -- lookup 15
  ]

/-- The circuit localised for the reverse memo-table evaluator. -/
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
    .const 1, -- 48
    .add 14 13, -- 49
    .add 0 13, -- 50
    .add 0 13, -- 51
    .add 0 13, -- 52
    .add 0 13, -- 53
    .add 0 13, -- 54
    .add 0 13, -- 55
    .add 19 21, -- 56
    .add 0 17, -- 57
    .add 20 22, -- 58
    .add 0 18, -- 59
    .add 20 19, -- 60
    .add 0 19, -- 61
    .const 0, -- 62
    .add 0 32, -- 63
    .mul 33 1, -- 64
    .add 2 0, -- 65
    .add 2 34, -- 66
    .mul 35 18, -- 67
    .add 2 0, -- 68
    .add 2 36, -- 69
    .const 2, -- 70
    .mul 38 0, -- 71
    .add 3 0, -- 72
    .add 3 39, -- 73
    .const 3, -- 74
    .mul 41 0, -- 75
    .add 3 0, -- 76
    .add 42 40, -- 77
    .add 42 40, -- 78
    .sub 23 17, -- 79
    .const 256, -- 80
    .mul 64 0, -- 81
    .add 0 66, -- 82
    .mul 0 2, -- 83
    .add 0 69, -- 84
    .mul 0 4, -- 85
    .add 0 72, -- 86
    .add 0 61, -- 87
    .mul 38 61, -- 88
    .const 255, -- 89
    .mul 1 0, -- 90
    .add 62 61, -- 91
    .sub 0 67, -- 92
    .const 536870912, -- 93
    .mul 1 0, -- 94
    .sub 39 46, -- 95
    .mul 40 0, -- 96
    .sub 62 48, -- 97
    .mul 63 0, -- 98
    .sub 63 50, -- 99
    .mul 64 0, -- 100
    .sub 64 52, -- 101
    .mul 65 0, -- 102
    .sub 65 54, -- 103
    .mul 66 0, -- 104
    .sub 66 56, -- 105
    .mul 67 0, -- 106
    .sub 67 58, -- 107
    .mul 68 0, -- 108
    .sub 68 60, -- 109
    .mul 69 0, -- 110
    .sub 69 62, -- 111
    .mul 70 0, -- 112
    .sub 86 64, -- 113
    .mul 87 0, -- 114
    .sub 66 65, -- 115
    .mul 0 89, -- 116
    .sub 86 68, -- 117
    .mul 87 0, -- 118
    .sub 87 70, -- 119
    .mul 88 0, -- 120
    .sub 88 72, -- 121
    .mul 89 0, -- 122
    .sub 89 74, -- 123
    .mul 90 0, -- 124
    .mul 67 48, -- 125
    .sub 49 77, -- 126
    .mul 67 0, -- 127
    .const 1073741824, -- 128
    .mul 1 0, -- 129
    .add 4 0, -- 130
    .sub 103 0, -- 131
    .sub 44 104, -- 132
    .mul 53 0, -- 133
    .mul 72 109, -- 134
    .add 1 0, -- 135
    .sub 107 0, -- 136
    .mul 57 112, -- 137
    .mul 76 5, -- 138
    .add 1 0, -- 139
    .sub 110 0, -- 140
    .sub 92 67, -- 141
    .mul 84 0, -- 142
    .sub 72 69, -- 143
    .mul 84 0, -- 144
    .sub 96 68, -- 145
    .mul 86 0, -- 146
    .const 5, -- 147
    .sub 0 71, -- 148
    .mul 2 0, -- 149
    .sub 59 106, -- 150
    .mul 73 0, -- 151
    .sub 61 107, -- 152
    .mul 75 0, -- 153
    .sub 63 108, -- 154
    .mul 77 0, -- 155
    .sub 113 136, -- 156
    .mul 79 0, -- 157
    .mul 0 127, -- 158
    .sub 150 139, -- 159
    .mul 120 0, -- 160
    .mul 0 130, -- 161
    .sub 119 141, -- 162
    .mul 85 0, -- 163
    .mul 0 132, -- 164
    .sub 155 145, -- 165
    .mul 126 0, -- 166
    .mul 0 135, -- 167
    .sub 125 146, -- 168
    .mul 91 0, -- 169
    .mul 0 137, -- 170
    .sub 160 151, -- 171
    .mul 132 0, -- 172
    .mul 0 140, -- 173
    .sub 131 151, -- 174
    .mul 97 0, -- 175
    .mul 0 142, -- 176
    .sub 165 157, -- 177
    .mul 138 0, -- 178
    .mul 0 145, -- 179
    .mul 101 27, -- 180
    .mul 102 26, -- 181
    .mul 33 88, -- 182
    .mul 56 89, -- 183
    .mul 105 1, -- 184
    .mul 0 28, -- 185
    .sub 142 165, -- 186
    .mul 2 0, -- 187
    .mul 109 4, -- 188
    .mul 0 20, -- 189
    .sub 146 167, -- 190
    .mul 2 0, -- 191
    .mul 151 9, -- 192
    .mul 0 33, -- 193
    .sub 184 173, -- 194
    .mul 2 0, -- 195
    .mul 155 12, -- 196
    .mul 0 25, -- 197
    .sub 186 177, -- 198
    .mul 2 0, -- 199
    .mul 161 43, -- 200
    .mul 159 41, -- 201
    .add 1 0, -- 202
    .mul 164 16, -- 203
    .mul 162 9, -- 204
    .add 1 0, -- 205
    .sub 161 184, -- 206
    .mul 168 0, -- 207
    .sub 197 186, -- 208
    .mul 167 0, -- 209
    .add 2 0, -- 210
    .sub 165 188, -- 211
    .mul 173 0, -- 212
    .sub 201 190, -- 213
    .mul 172 0, -- 214
    .add 2 0, -- 215
    .sub 167 185, -- 216
    .mul 156 0, -- 217
    .sub 209 214, -- 218
    .mul 1 0, -- 219
    .sub 171 188, -- 220
    .mul 160 0, -- 221
    .sub 212 217, -- 222
    .mul 1 0, -- 223
    .sub 175 191, -- 224
    .mul 164 0, -- 225
    .sub 215 220, -- 226
    .mul 1 0, -- 227
    .sub 179 194, -- 228
    .mul 168 0, -- 229
    .sub 218 223, -- 230
    .mul 1 0, -- 231
    .sub 185 183, -- 232
    .mul 186 0, -- 233
    .sub 185 187, -- 234
    .mul 210 0, -- 235
    .mul 211 188, -- 236
    .sub 0 190, -- 237
    .mul 191 195, -- 238
    .sub 230 0, -- 239
    .mul 193 196, -- 240
    .sub 231 0, -- 241
    .mul 195 197, -- 242
    .sub 232 0, -- 243
    .mul 197 198, -- 244
    .sub 233 0, -- 245
    .mul 166 6, -- 246
    .mul 167 5, -- 247
    .mul 168 4, -- 248
    .mul 169 3, -- 249
    .sub 201 170, -- 250
    .mul 0 208, -- 251
    .mul 1 208, -- 252
    .mul 2 208, -- 253
    .mul 3 208, -- 254
    .mul 199 238, -- 255
    .sub 255 207, -- 256
    .const 4, -- 257
    .mul 1 0, -- 258
    .add 0 188, -- 259
    .add 1 211, -- 260
    .sub 0 243, -- 261
    .sub 0 213, -- 262
    .add 3 183, -- 263
    .sub 0 240, -- 264
    .sub 0 216, -- 265
    .add 6 204, -- 266
    .sub 0 259, -- 267
    .sub 0 219, -- 268
    .neg 213, -- 269
    .const 19, -- 270
    .mul 236 0, -- 271
    .const 20, -- 272
    .mul 237 0, -- 273
    .add 2 0, -- 274
    .const 21, -- 275
    .mul 237 0, -- 276
    .add 2 0, -- 277
    .const 22, -- 278
    .mul 242 0, -- 279
    .add 2 0, -- 280
    .const 23, -- 281
    .mul 244 0, -- 282
    .add 2 0, -- 283
    .const 24, -- 284
    .mul 245 0, -- 285
    .add 2 0, -- 286
    .const 25, -- 287
    .mul 247 0, -- 288
    .add 2 0, -- 289
    .const 26, -- 290
    .mul 249 0, -- 291
    .add 2 0, -- 292
    .add 291 35, -- 293
    .add 293 245, -- 294
    .const 128, -- 295
    .mul 269 0, -- 296
    .sub 254 0, -- 297
    .sub 254 1, -- 298
    .neg 264, -- 299
    .neg 264 -- 300
  ]
  nodeCount := 301
  constraints := loadStoreCircuit.constraints
  lookups := loadStoreCircuit.lookups

#guard loadStoreCircuitCompiled == loadStoreCircuit.localise
#guard loadStoreCircuit.wellFormed
#guard loadStoreCircuit.columns.length == 48
#guard loadStoreCircuit.nodes.length == 301
#guard loadStoreCircuit.constraints.length == 63
#guard loadStoreCircuit.lookups.length == 16

-- Independent concrete LW and SB witnesses retained as evaluator differential tests.
def loadStoreLoadWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 100, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 145, M31.reduce 34, M31.reduce 51, M31.reduce 68,
    M31.reduce 1, M31.reduce 64, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 3, M31.reduce 0, M31.reduce 145,
    M31.reduce 34, M31.reduce 51, M31.reduce 68, M31.reduce 3,
    M31.reduce 7, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 64, M31.reduce 7, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 145, M31.reduce 34,
    M31.reduce 51, M31.reduce 68, M31.reduce 1, M31.reduce 1840700269
  ]

#guard loadStoreCircuitCompiled.constraintValues loadStoreLoadWitnessColumns ==
  List.replicate 63 0

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

def loadStoreStoreWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 200, M31.reduce 0, M31.reduce 17,
    M31.reduce 34, M31.reduce 51, M31.reduce 68, M31.reduce 3,
    M31.reduce 17, M31.reduce 171, M31.reduce 51, M31.reduce 68,
    M31.reduce 1, M31.reduce 65, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 3, M31.reduce 0, M31.reduce 171,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 2, M31.reduce 0, M31.reduce 0, M31.reduce 1,
    M31.reduce 2, M31.reduce 64, M31.reduce 0, M31.reduce 1,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 1,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 1073741824
  ]

#guard loadStoreCircuitCompiled.constraintValues loadStoreStoreWitnessColumns ==
  List.replicate 63 0

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

-- Gating is load-bearing: inactive range_check_m31 requests need not be members.
#guard !loadStoreCircuitCompiled.fixedRequestsHoldUnconditional
    loadStoreLoadWitnessColumns

end RiscvRefinement.Air.Bridge
