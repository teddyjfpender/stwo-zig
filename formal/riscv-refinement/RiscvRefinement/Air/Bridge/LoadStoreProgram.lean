-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Source: generated/air/lb.air-ir-v2.json
import RiscvRefinement.Air.Bridge.MulhProgram
namespace RiscvRefinement.Air.Bridge
def loadStoreProgramIrDigest : String := "dc7a7abc306d0bd0473b115f4cf674efb660caf9dc90c3e900f64e5542b14876"
def loadStoreCircuit : MulhCircuit where
  family := "load_store"
  modulus := 2147483647
  columns := ["clk", "pc", "dst_addr", "dst_previous_0", "dst_previous_1", "dst_previous_2", "dst_previous_3", "dst_previous_clock", "dst_next_0", "dst_next_1", "dst_next_2", "dst_next_3", "rs1_addr", "rs1_value_0", "rs1_value_1", "rs1_value_2", "rs1_value_3", "rs1_previous_clock", "src_addr", "src_value_0", "src_value_1", "src_value_2", "src_value_3", "src_previous_clock", "r2_idx", "imm_felt", "src_msb", "shift_amount", "src_addr_selector", "dst_addr_selector", "markers_0", "markers_1", "markers_2", "markers_3", "is_lb", "is_lh", "is_lbu", "is_lhu", "is_lw", "is_sb", "is_sh", "is_sw", "result_0", "result_1", "result_2", "result_3", "destination_nonzero", "destination_inverse", "aligned_addr_quarter", "aligned_addr_low20"]
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
    .const 1, -- 50
    .add 34 35, -- 51
    .add 51 36, -- 52
    .add 52 37, -- 53
    .add 53 38, -- 54
    .add 54 39, -- 55
    .add 55 40, -- 56
    .add 56 41, -- 57
    .add 36 34, -- 58
    .add 58 39, -- 59
    .add 37 35, -- 60
    .add 60 40, -- 61
    .add 39 40, -- 62
    .add 62 41, -- 63
    .const 0, -- 64
    .add 64 30, -- 65
    .mul 30 64, -- 66
    .add 64 66, -- 67
    .add 65 31, -- 68
    .mul 31 50, -- 69
    .add 67 69, -- 70
    .add 68 32, -- 71
    .const 2, -- 72
    .mul 32 72, -- 73
    .add 70 73, -- 74
    .add 71 33, -- 75
    .const 3, -- 76
    .mul 33 76, -- 77
    .add 74 77, -- 78
    .add 28 29, -- 79
    .sub 79 24, -- 80
    .const 536870912, -- 81
    .mul 80 81, -- 82
    .add 34 36, -- 83
    .add 35 37, -- 84
    .sub 57 63, -- 85
    .const 256, -- 86
    .mul 16 86, -- 87
    .add 87 15, -- 88
    .mul 88 86, -- 89
    .add 89 14, -- 90
    .mul 90 86, -- 91
    .add 91 13, -- 92
    .add 92 25, -- 93
    .mul 51 26, -- 94
    .const 255, -- 95
    .mul 94 95, -- 96
    .sub 48 49, -- 97
    .const 2048, -- 98
    .mul 97 98, -- 99
    .sub 57 50, -- 100
    .mul 57 100, -- 101
    .sub 34 50, -- 102
    .mul 34 102, -- 103
    .sub 35 50, -- 104
    .mul 35 104, -- 105
    .sub 36 50, -- 106
    .mul 36 106, -- 107
    .sub 37 50, -- 108
    .mul 37 108, -- 109
    .sub 38 50, -- 110
    .mul 38 110, -- 111
    .sub 39 50, -- 112
    .mul 39 112, -- 113
    .sub 40 50, -- 114
    .mul 40 114, -- 115
    .sub 41 50, -- 116
    .mul 41 116, -- 117
    .sub 26 50, -- 118
    .mul 26 118, -- 119
    .sub 50 51, -- 120
    .mul 120 26, -- 121
    .sub 30 50, -- 122
    .mul 30 122, -- 123
    .sub 31 50, -- 124
    .mul 31 124, -- 125
    .sub 32 50, -- 126
    .mul 32 126, -- 127
    .sub 33 50, -- 128
    .mul 33 128, -- 129
    .mul 59 78, -- 130
    .sub 78 50, -- 131
    .mul 61 131, -- 132
    .const 1073741824, -- 133
    .mul 132 133, -- 134
    .add 130 134, -- 135
    .sub 27 135, -- 136
    .sub 93 27, -- 137
    .mul 85 137, -- 138
    .mul 63 24, -- 139
    .add 138 139, -- 140
    .sub 28 140, -- 141
    .mul 85 24, -- 142
    .mul 63 137, -- 143
    .add 142 143, -- 144
    .sub 29 144, -- 145
    .sub 50 75, -- 146
    .mul 59 146, -- 147
    .sub 72 75, -- 148
    .mul 61 148, -- 149
    .sub 50 78, -- 150
    .mul 61 150, -- 151
    .const 5, -- 152
    .sub 152 78, -- 153
    .mul 151 153, -- 154
    .sub 96 43, -- 155
    .mul 83 155, -- 156
    .sub 96 44, -- 157
    .mul 83 157, -- 158
    .sub 96 45, -- 159
    .mul 83 159, -- 160
    .sub 42 19, -- 161
    .mul 83 161, -- 162
    .mul 162 30, -- 163
    .sub 8 19, -- 164
    .mul 39 164, -- 165
    .mul 165 30, -- 166
    .sub 42 20, -- 167
    .mul 83 167, -- 168
    .mul 168 31, -- 169
    .sub 9 19, -- 170
    .mul 39 170, -- 171
    .mul 171 31, -- 172
    .sub 42 21, -- 173
    .mul 83 173, -- 174
    .mul 174 32, -- 175
    .sub 10 19, -- 176
    .mul 39 176, -- 177
    .mul 177 32, -- 178
    .sub 42 22, -- 179
    .mul 83 179, -- 180
    .mul 180 33, -- 181
    .sub 11 19, -- 182
    .mul 39 182, -- 183
    .mul 183 33, -- 184
    .mul 84 157, -- 185
    .mul 84 159, -- 186
    .mul 153 81, -- 187
    .mul 131 81, -- 188
    .mul 84 187, -- 189
    .mul 189 161, -- 190
    .sub 43 20, -- 191
    .mul 189 191, -- 192
    .mul 84 188, -- 193
    .mul 193 173, -- 194
    .sub 43 22, -- 195
    .mul 193 195, -- 196
    .mul 40 187, -- 197
    .mul 197 164, -- 198
    .sub 9 20, -- 199
    .mul 197 199, -- 200
    .mul 40 188, -- 201
    .mul 201 176, -- 202
    .sub 11 20, -- 203
    .mul 201 203, -- 204
    .mul 38 161, -- 205
    .mul 41 164, -- 206
    .add 205 206, -- 207
    .mul 38 191, -- 208
    .mul 41 199, -- 209
    .add 208 209, -- 210
    .sub 44 21, -- 211
    .mul 38 211, -- 212
    .sub 10 21, -- 213
    .mul 41 213, -- 214
    .add 212 214, -- 215
    .sub 45 22, -- 216
    .mul 38 216, -- 217
    .sub 11 22, -- 218
    .mul 41 218, -- 219
    .add 217 219, -- 220
    .sub 50 30, -- 221
    .mul 62 221, -- 222
    .sub 8 3, -- 223
    .mul 222 223, -- 224
    .sub 50 31, -- 225
    .mul 62 225, -- 226
    .sub 9 4, -- 227
    .mul 226 227, -- 228
    .sub 50 32, -- 229
    .mul 62 229, -- 230
    .sub 10 5, -- 231
    .mul 230 231, -- 232
    .sub 50 33, -- 233
    .mul 62 233, -- 234
    .sub 11 6, -- 235
    .mul 234 235, -- 236
    .sub 46 50, -- 237
    .mul 46 237, -- 238
    .sub 50 46, -- 239
    .mul 24 239, -- 240
    .mul 24 47, -- 241
    .sub 241 46, -- 242
    .mul 46 42, -- 243
    .sub 8 243, -- 244
    .mul 46 43, -- 245
    .sub 9 245, -- 246
    .mul 46 44, -- 247
    .sub 10 247, -- 248
    .mul 46 45, -- 249
    .sub 11 249, -- 250
    .mul 85 244, -- 251
    .mul 85 246, -- 252
    .mul 85 248, -- 253
    .mul 85 250, -- 254
    .sub 50 85, -- 255
    .mul 255 42, -- 256
    .mul 255 43, -- 257
    .mul 255 44, -- 258
    .mul 255 45, -- 259
    .sub 48 82, -- 260
    .mul 57 260, -- 261
    .sub 0 50, -- 262
    .const 4, -- 263
    .mul 262 263, -- 264
    .add 264 72, -- 265
    .add 264 50, -- 266
    .sub 266 17, -- 267
    .sub 267 50, -- 268
    .add 265 85, -- 269
    .sub 269 23, -- 270
    .sub 270 50, -- 271
    .add 265 63, -- 272
    .sub 272 7, -- 273
    .sub 273 50, -- 274
    .const 128, -- 275
    .mul 26 275, -- 276
    .sub 42 276, -- 277
    .sub 43 276, -- 278
    .neg 57, -- 279
    .const 19, -- 280
    .mul 34 280, -- 281
    .const 20, -- 282
    .mul 35 282, -- 283
    .add 281 283, -- 284
    .const 21, -- 285
    .mul 38 285, -- 286
    .add 284 286, -- 287
    .const 22, -- 288
    .mul 36 288, -- 289
    .add 287 289, -- 290
    .const 23, -- 291
    .mul 37 291, -- 292
    .add 290 292, -- 293
    .const 24, -- 294
    .mul 39 294, -- 295
    .add 293 295, -- 296
    .const 25, -- 297
    .mul 40 297, -- 298
    .add 296 298, -- 299
    .const 26, -- 300
    .mul 41 300, -- 301
    .add 299 301, -- 302
    .add 1 263, -- 303
    .add 0 50, -- 304
    .mul 16 72, -- 305
    .neg 34, -- 306
    .neg 35 -- 307
  ]
  nodeCount := 308
  constraints := [101, 103, 105, 107, 109, 111, 113, 115, 117, 119, 121, 123, 125, 127, 129, 136, 141, 145, 147, 149, 154, 156, 158, 160, 163, 166, 169, 172, 175, 178, 181, 184, 185, 186, 190, 192, 194, 196, 198, 200, 202, 204, 207, 210, 215, 220, 224, 228, 232, 236, 238, 240, 242, 251, 252, 253, 254, 256, 257, 258, 259, 261, 100]
  lookups := [
    { domain := .programAccess, role := .request,
      numerator := 279, tuple := [1, 302, 12, 24, 25] },
    { domain := .registersState, role := .consumed,
      numerator := 279, tuple := [1, 0] },
    { domain := .registersState, role := .emitted,
      numerator := 57, tuple := [303, 304] },
    { domain := .memoryAccess, role := .consumed,
      numerator := 279, tuple := [64, 12, 17, 13, 14, 15, 16] },
    { domain := .memoryAccess, role := .emitted,
      numerator := 57, tuple := [64, 12, 266, 13, 14, 15, 16] },
    { domain := .rangeCheck20, role := .request,
      numerator := 279, tuple := [268] },
    { domain := .rangeCheck20, role := .request,
      numerator := 279, tuple := [49] },
    { domain := .rangeCheckM31, role := .request,
      numerator := 279, tuple := [13, 305] },
    { domain := .memoryAccess, role := .consumed,
      numerator := 279, tuple := [85, 28, 23, 19, 20, 21, 22] },
    { domain := .memoryAccess, role := .emitted,
      numerator := 57, tuple := [85, 28, 269, 19, 20, 21, 22] },
    { domain := .rangeCheck20, role := .request,
      numerator := 279, tuple := [271] },
    { domain := .memoryAccess, role := .consumed,
      numerator := 279, tuple := [63, 29, 7, 3, 4, 5, 6] },
    { domain := .memoryAccess, role := .emitted,
      numerator := 57, tuple := [63, 29, 272, 8, 9, 10, 11] },
    { domain := .rangeCheck20, role := .request,
      numerator := 279, tuple := [274] },
    { domain := .rangeCheckM31, role := .request,
      numerator := 306, tuple := [64, 277] },
    { domain := .rangeCheckM31, role := .request,
      numerator := 307, tuple := [64, 278] },
    { domain := .rangeCheck88, role := .request,
      numerator := 279, tuple := [99, 64] }
  ]
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
    .const 1, -- 50
    .add 16 15, -- 51
    .add 0 15, -- 52
    .add 0 15, -- 53
    .add 0 15, -- 54
    .add 0 15, -- 55
    .add 0 15, -- 56
    .add 0 15, -- 57
    .add 21 23, -- 58
    .add 0 19, -- 59
    .add 22 24, -- 60
    .add 0 20, -- 61
    .add 22 21, -- 62
    .add 0 21, -- 63
    .const 0, -- 64
    .add 0 34, -- 65
    .mul 35 1, -- 66
    .add 2 0, -- 67
    .add 2 36, -- 68
    .mul 37 18, -- 69
    .add 2 0, -- 70
    .add 2 38, -- 71
    .const 2, -- 72
    .mul 40 0, -- 73
    .add 3 0, -- 74
    .add 3 41, -- 75
    .const 3, -- 76
    .mul 43 0, -- 77
    .add 3 0, -- 78
    .add 50 49, -- 79
    .sub 0 55, -- 80
    .const 536870912, -- 81
    .mul 1 0, -- 82
    .add 48 46, -- 83
    .add 48 46, -- 84
    .sub 27 21, -- 85
    .const 256, -- 86
    .mul 70 0, -- 87
    .add 0 72, -- 88
    .mul 0 2, -- 89
    .add 0 75, -- 90
    .mul 0 4, -- 91
    .add 0 78, -- 92
    .add 0 67, -- 93
    .mul 42 67, -- 94
    .const 255, -- 95
    .mul 1 0, -- 96
    .sub 48 47, -- 97
    .const 2048, -- 98
    .mul 1 0, -- 99
    .sub 42 49, -- 100
    .mul 43 0, -- 101
    .sub 67 51, -- 102
    .mul 68 0, -- 103
    .sub 68 53, -- 104
    .mul 69 0, -- 105
    .sub 69 55, -- 106
    .mul 70 0, -- 107
    .sub 70 57, -- 108
    .mul 71 0, -- 109
    .sub 71 59, -- 110
    .mul 72 0, -- 111
    .sub 72 61, -- 112
    .mul 73 0, -- 113
    .sub 73 63, -- 114
    .mul 74 0, -- 115
    .sub 74 65, -- 116
    .mul 75 0, -- 117
    .sub 91 67, -- 118
    .mul 92 0, -- 119
    .sub 69 68, -- 120
    .mul 0 94, -- 121
    .sub 91 71, -- 122
    .mul 92 0, -- 123
    .sub 92 73, -- 124
    .mul 93 0, -- 125
    .sub 93 75, -- 126
    .mul 94 0, -- 127
    .sub 94 77, -- 128
    .mul 95 0, -- 129
    .mul 70 51, -- 130
    .sub 52 80, -- 131
    .mul 70 0, -- 132
    .const 1073741824, -- 133
    .mul 1 0, -- 134
    .add 4 0, -- 135
    .sub 108 0, -- 136
    .sub 43 109, -- 137
    .mul 52 0, -- 138
    .mul 75 114, -- 139
    .add 1 0, -- 140
    .sub 112 0, -- 141
    .mul 56 117, -- 142
    .mul 79 5, -- 143
    .add 1 0, -- 144
    .sub 115 0, -- 145
    .sub 95 70, -- 146
    .mul 87 0, -- 147
    .sub 75 72, -- 148
    .mul 87 0, -- 149
    .sub 99 71, -- 150
    .mul 89 0, -- 151
    .const 5, -- 152
    .sub 0 74, -- 153
    .mul 2 0, -- 154
    .sub 58 111, -- 155
    .mul 72 0, -- 156
    .sub 60 112, -- 157
    .mul 74 0, -- 158
    .sub 62 113, -- 159
    .mul 76 0, -- 160
    .sub 118 141, -- 161
    .mul 78 0, -- 162
    .mul 0 132, -- 163
    .sub 155 144, -- 164
    .mul 125 0, -- 165
    .mul 0 135, -- 166
    .sub 124 146, -- 167
    .mul 84 0, -- 168
    .mul 0 137, -- 169
    .sub 160 150, -- 170
    .mul 131 0, -- 171
    .mul 0 140, -- 172
    .sub 130 151, -- 173
    .mul 90 0, -- 174
    .mul 0 142, -- 175
    .sub 165 156, -- 176
    .mul 137 0, -- 177
    .mul 0 145, -- 178
    .sub 136 156, -- 179
    .mul 96 0, -- 180
    .mul 0 147, -- 181
    .sub 170 162, -- 182
    .mul 143 0, -- 183
    .mul 0 150, -- 184
    .mul 100 27, -- 185
    .mul 101 26, -- 186
    .mul 33 105, -- 187
    .mul 56 106, -- 188
    .mul 104 1, -- 189
    .mul 0 28, -- 190
    .sub 147 170, -- 191
    .mul 2 0, -- 192
    .mul 108 4, -- 193
    .mul 0 20, -- 194
    .sub 151 172, -- 195
    .mul 2 0, -- 196
    .mul 156 9, -- 197
    .mul 0 33, -- 198
    .sub 189 178, -- 199
    .mul 2 0, -- 200
    .mul 160 12, -- 201
    .mul 0 25, -- 202
    .sub 191 182, -- 203
    .mul 2 0, -- 204
    .mul 166 43, -- 205
    .mul 164 41, -- 206
    .add 1 0, -- 207
    .mul 169 16, -- 208
    .mul 167 9, -- 209
    .add 1 0, -- 210
    .sub 166 189, -- 211
    .mul 173 0, -- 212
    .sub 202 191, -- 213
    .mul 172 0, -- 214
    .add 2 0, -- 215
    .sub 170 193, -- 216
    .mul 178 0, -- 217
    .sub 206 195, -- 218
    .mul 177 0, -- 219
    .add 2 0, -- 220
    .sub 170 190, -- 221
    .mul 159 0, -- 222
    .sub 214 219, -- 223
    .mul 1 0, -- 224
    .sub 174 193, -- 225
    .mul 163 0, -- 226
    .sub 217 222, -- 227
    .mul 1 0, -- 228
    .sub 178 196, -- 229
    .mul 167 0, -- 230
    .sub 220 225, -- 231
    .mul 1 0, -- 232
    .sub 182 199, -- 233
    .mul 171 0, -- 234
    .sub 223 228, -- 235
    .mul 1 0, -- 236
    .sub 190 186, -- 237
    .mul 191 0, -- 238
    .sub 188 192, -- 239
    .mul 215 0, -- 240
    .mul 216 193, -- 241
    .sub 0 195, -- 242
    .mul 196 200, -- 243
    .sub 235 0, -- 244
    .mul 198 201, -- 245
    .sub 236 0, -- 246
    .mul 200 202, -- 247
    .sub 237 0, -- 248
    .mul 202 203, -- 249
    .sub 238 0, -- 250
    .mul 165 6, -- 251
    .mul 166 5, -- 252
    .mul 167 4, -- 253
    .mul 168 3, -- 254
    .sub 204 169, -- 255
    .mul 0 213, -- 256
    .mul 1 213, -- 257
    .mul 2 213, -- 258
    .mul 3 213, -- 259
    .sub 211 177, -- 260
    .mul 203 0, -- 261
    .sub 261 211, -- 262
    .const 4, -- 263
    .mul 1 0, -- 264
    .add 0 192, -- 265
    .add 1 215, -- 266
    .sub 0 249, -- 267
    .sub 0 217, -- 268
    .add 3 183, -- 269
    .sub 0 246, -- 270
    .sub 0 220, -- 271
    .add 6 208, -- 272
    .sub 0 265, -- 273
    .sub 0 223, -- 274
    .const 128, -- 275
    .mul 249 0, -- 276
    .sub 234 0, -- 277
    .sub 234 1, -- 278
    .neg 221, -- 279
    .const 19, -- 280
    .mul 246 0, -- 281
    .const 20, -- 282
    .mul 247 0, -- 283
    .add 2 0, -- 284
    .const 21, -- 285
    .mul 247 0, -- 286
    .add 2 0, -- 287
    .const 22, -- 288
    .mul 252 0, -- 289
    .add 2 0, -- 290
    .const 23, -- 291
    .mul 254 0, -- 292
    .add 2 0, -- 293
    .const 24, -- 294
    .mul 255 0, -- 295
    .add 2 0, -- 296
    .const 25, -- 297
    .mul 257 0, -- 298
    .add 2 0, -- 299
    .const 26, -- 300
    .mul 259 0, -- 301
    .add 2 0, -- 302
    .add 301 39, -- 303
    .add 303 253, -- 304
    .mul 288 232, -- 305
    .neg 271, -- 306
    .neg 271 -- 307
  ]
  nodeCount := 308
  constraints := loadStoreCircuit.constraints
  lookups := loadStoreCircuit.lookups
#guard loadStoreCircuitCompiled == loadStoreCircuit.localise
#guard loadStoreCircuit.wellFormed
#guard loadStoreCircuit.columns.length == 50
#guard loadStoreCircuit.nodes.length == 308
#guard loadStoreCircuit.constraints.length == 63
#guard loadStoreCircuit.lookups.length == 17

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
    M31.reduce 51, M31.reduce 68, M31.reduce 1, M31.reduce 1840700269, M31.reduce 16, M31.reduce 16
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
    [0, 34],
    [0, 0]
  ]

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupNumerator loadStoreLoadWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 0, 0, 2147483646]

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
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 1073741824, M31.reduce 16, M31.reduce 16
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
    [0, 0],
    [0, 0]
  ]

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupNumerator loadStoreStoreWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 0, 0, 2147483646]

-- Gating is load-bearing: inactive range_check_m31 requests need not be members.
#guard !loadStoreCircuitCompiled.fixedRequestsHoldUnconditional
    loadStoreLoadWitnessColumns


end RiscvRefinement.Air.Bridge
