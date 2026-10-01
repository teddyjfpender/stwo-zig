//! Runs the CUDA row function itself on the host and compares every witness
//! column and table count against the circuit frontend's CPU oracle.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cuda = @import("stwo_cuda_backend");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const K = circuit.witness.components;
const base = cuda.runtime.stages.circuit_base;

extern "c" fn stwo_circuit_base_witness_emulate(
    component: u32,
    values: [*]const u32,
    value_count: u32,
    row_count: u32,
    first_permutation_row: u32,
    pp_host: [*]const [*]const u32,
    pp_count: u32,
    out_host: [*]const [*]u32,
    out_count: u32,
    counts_host: [*]const [*]u32,
    count_count: u32,
    error_flag: *u32,
) c_int;

fn encoded(input_word: u32) QM31 {
    return QM31.fromU32Unchecked(input_word & 0xffff, input_word >> 16, 0, 0);
}

fn word(value: QM31) u32 {
    const limbs = value.toM31Array();
    return limbs[0].toU32() | (limbs[1].toU32() << 16);
}

fn rotateRight(x: u32, comptime amount: u5) u32 {
    const left: u5 = @intCast(32 - @as(u6, amount));
    return (x >> amount) | (x << left);
}

fn blakeG(inputs: [6]u32) [10]u32 {
    var a = inputs[0];
    var b = inputs[1];
    var c = inputs[2];
    var d = inputs[3];
    a +%= b +% inputs[4];
    d = rotateRight(d ^ a, 16);
    c +%= d;
    b = rotateRight(b ^ c, 12);
    a +%= b +% inputs[5];
    d = rotateRight(d ^ a, 8);
    c +%= d;
    b = rotateRight(b ^ c, 7);
    return .{ inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5], a, b, c, d };
}

fn writeRow(out: *[52]u32, row: anytype) void {
    for (row, 0..) |felt, index| out[index] = felt.toU32();
}

test "circuit CUDA base row emulation equals CPU witness and complete table counts" {
    const a = std.heap.page_allocator;
    var counts: [base.count_lengths.len][]u32 = undefined;
    var count_ptrs: [base.count_lengths.len][*]u32 = undefined;
    var initialized: usize = 0;
    defer for (counts[0..initialized]) |slice| a.free(slice);
    for (base.count_lengths, 0..) |len, index| {
        counts[index] = try a.alloc(u32, len);
        initialized += 1;
        count_ptrs[index] = counts[index].ptr;
    }
    var expected_counts = try K.TableMultiplicities.init(a);
    defer expected_counts.deinit(a);

    for (0..base.gate_count) |component| {
        for (counts) |slice| @memset(slice, 0);
        const rows: usize = 16;
        var values: [160]QM31 = @splat(QM31.zero());
        var pp: [11][16]u32 = @splat(@splat(0));
        var outputs: [52][16]u32 = @splat(@splat(0));
        var pp_ptrs: [11][*]const u32 = undefined;
        var out_ptrs: [52][*]u32 = undefined;
        for (&pp, &pp_ptrs) |*column, *pointer| pointer.* = column;
        for (&outputs, &out_ptrs) |*column, *pointer| pointer.* = column;
        for (0..rows) |r| {
            switch (component) {
                0 => {
                    values[r] = QM31.fromU32Unchecked(@intCast(17 + r), @intCast(31 + r), @intCast(47 + r), @intCast(61 + r));
                    pp[0][r] = @intCast(r);
                },
                1 => {
                    for (0..3) |i| {
                        const index = 3 * r + i;
                        values[index] = QM31.fromU32Unchecked(@intCast(index + 1), @intCast(index + 2), @intCast(index + 3), @intCast(index + 4));
                        pp[4 + i][r] = @intCast(index);
                    }
                },
                2 => {
                    const x: u32 = @intCast(r);
                    const words = [_]u32{ 0x12345670 + x, 0x89abcdef ^ x, 0x76543210 + x, 0 };
                    const out = words[0] ^ words[1] ^ words[2];
                    for ([_]u32{ words[0], words[1], words[2], out }, 0..) |w, i| {
                        values[4 * r + i] = encoded(w);
                        pp[i][r] = @intCast(4 * r + i);
                    }
                },
                3 => {
                    const x: u32 = @intCast(r * 100003 + 123);
                    values[r] = QM31.fromU32Unchecked(x, 0, 0, 0);
                    pp[0][r] = @intCast(r);
                },
                else => {
                    const x: u32 = @intCast(r);
                    const words = blakeG(.{ 0x12345678 + x, 0x89abcdef ^ x, 0x76543210 + x, 0xfedcba98 - x, 0x11111111 + x, 0x22222222 ^ x });
                    for (words, 0..) |w, i| {
                        values[10 * r + i] = encoded(w);
                        pp[i][r] = @intCast(10 * r + i);
                    }
                },
            }
        }
        var raw: [160 * 4]u32 = undefined;
        for (values, 0..) |value, index| {
            for (value.toM31Array(), 0..) |felt, limb| raw[4 * index + limb] = felt.toU32();
        }
        var error_flag: u32 = 0;
        try std.testing.expectEqual(@as(c_int, 0), stwo_circuit_base_witness_emulate(
            @intCast(component),
            &raw,
            160,
            16,
            8,
            &pp_ptrs,
            @intCast(base.pp_widths[component]),
            &out_ptrs,
            @intCast(base.output_widths[component]),
            &count_ptrs,
            @intCast(base.count_lengths.len),
            &error_flag,
        ));
        try std.testing.expectEqual(@as(u32, 0), error_flag);

        for (0..rows) |r| {
            var expected: [52]u32 = @splat(0);
            switch (component) {
                0 => {
                    var row: [K.eq.n_columns]M31 = undefined;
                    K.eq.row(values[pp[0][r]], &row);
                    writeRow(&expected, row);
                },
                1 => {
                    var row: [K.qm31_ops.n_columns]M31 = undefined;
                    if (r < 8) {
                        K.qm31_ops.row(values[pp[4][r]], values[pp[5][r]], values[pp[6][r]], &row);
                    } else {
                        const pair = r - ((r - 8) % 2);
                        const address = if (r == pair) pp[5][pair] else pp[6][pair + 1];
                        K.qm31_ops.row(QM31.zero(), values[address], values[address], &row);
                    }
                    writeRow(&expected, row);
                },
                2 => {
                    var row: [K.triple_xor.n_columns]M31 = undefined;
                    K.triple_xor.row(word(values[pp[0][r]]), word(values[pp[1][r]]), word(values[pp[2][r]]), word(values[pp[3][r]]), &row);
                    writeRow(&expected, row);
                    try expected_counts.addUses(&K.triple_xor.lookups(&row, .{
                        .in0 = M31.fromCanonical(pp[0][r]),
                        .in1 = M31.fromCanonical(pp[1][r]),
                        .in2 = M31.fromCanonical(pp[2][r]),
                        .out = M31.fromCanonical(pp[3][r]),
                        .mults = M31.one(),
                    }));
                },
                3 => {
                    var row: [K.m31_to_u32.n_columns]M31 = undefined;
                    K.m31_to_u32.row(values[pp[0][r]].toM31Array()[0], &row);
                    writeRow(&expected, row);
                    try expected_counts.addUses(&K.m31_to_u32.lookups(&row, .{
                        .input = M31.fromCanonical(pp[0][r]),
                        .output = M31.one(),
                        .mults = M31.one(),
                    }));
                },
                else => {
                    var words: [10]u32 = undefined;
                    for (&words, 0..) |*w, i| w.* = word(values[pp[i][r]]);
                    var row: [K.blake_g_gate.n_columns]M31 = undefined;
                    K.blake_g_gate.row(words, &row);
                    writeRow(&expected, row);
                    var inputs: [6]M31 = undefined;
                    var outputs_pp: [4]M31 = undefined;
                    for (&inputs, 0..) |*entry, i| entry.* = M31.fromCanonical(pp[i][r]);
                    for (&outputs_pp, 0..) |*entry, i| entry.* = M31.fromCanonical(pp[i + 6][r]);
                    try expected_counts.addUses(&K.blake_g_gate.lookups(&row, .{
                        .inputs = inputs,
                        .outputs = outputs_pp,
                        .mults = M31.one(),
                    }));
                },
            }
            for (expected[0..base.output_widths[component]], 0..) |want, column|
                try std.testing.expectEqual(want, outputs[column][r]);
        }
        const oracle = [_][]const u32{
            expected_counts.xor8[0],   expected_counts.xor8[1],
            expected_counts.xor12[0],  expected_counts.xor12[1],
            expected_counts.xor12[2],  expected_counts.xor12[3],
            expected_counts.xor12[4],  expected_counts.xor12[5],
            expected_counts.xor12[6],  expected_counts.xor12[7],
            expected_counts.xor12[8],  expected_counts.xor12[9],
            expected_counts.xor12[10], expected_counts.xor12[11],
            expected_counts.xor12[12], expected_counts.xor12[13],
            expected_counts.xor12[14], expected_counts.xor12[15],
            expected_counts.xor4,      expected_counts.xor7,
            expected_counts.xor9,      expected_counts.rc16,
        };
        for (counts, oracle) |actual, want| try std.testing.expectEqualSlices(u32, want, actual);
        if (component == 0 or component == 2) {
            if (component == 0) pp[0][0] = 160 else raw[4 * 3] ^= 1;
            error_flag = 0;
            try std.testing.expectEqual(@as(c_int, 0), stwo_circuit_base_witness_emulate(
                @intCast(component), &raw, 160, 16, 8,
                &pp_ptrs, @intCast(base.pp_widths[component]),
                &out_ptrs, @intCast(base.output_widths[component]),
                &count_ptrs, @intCast(base.count_lengths.len), &error_flag,
            ));
            try std.testing.expectEqual(@as(u32, 1), error_flag);
        }
        for (oracle) |slice| @memset(@constCast(slice), 0);
    }
}
