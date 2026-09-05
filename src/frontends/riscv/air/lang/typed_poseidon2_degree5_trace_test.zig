//! Focused tests for the compiled degree-five main-trace writer.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const infra = @import("../../infra_trace.zig");
const row_program = @import("typed_poseidon2_degree5_row_program.zig");
const trace_mod = @import("typed_poseidon2_degree5_trace.zig");
const generateMain = trace_mod.generateMain;

test "degree-five row program block arithmetic matches scalar M31" {
    const a_words = [row_program.LANES]u32{ 0, 1, m31.Modulus - 1, 12345, 2_000_000_000, 7, m31.Modulus - 2, 99 };
    const b_words = [row_program.LANES]u32{ m31.Modulus - 1, 1, m31.Modulus - 1, 54321, 1_999_999_999, 0, 3, 100 };
    const a = row_program.loadBlock(&a_words);
    const b = row_program.loadBlock(&b_words);
    var sum: [row_program.LANES]M31 = undefined;
    var difference: [row_program.LANES]M31 = undefined;
    var product: [row_program.LANES]M31 = undefined;
    var negated: [row_program.LANES]M31 = undefined;
    a.add(b).store(&sum);
    a.sub(b).store(&difference);
    a.mul(b).store(&product);
    a.neg().store(&negated);
    for (a_words, b_words, 0..) |x, y, lane| {
        const lhs = M31.fromCanonical(x);
        const rhs = M31.fromCanonical(y);
        try std.testing.expectEqual(lhs.add(rhs).toU32(), sum[lane].toU32());
        try std.testing.expectEqual(lhs.sub(rhs).toU32(), difference[lane].toU32());
        try std.testing.expectEqual(lhs.mul(rhs).toU32(), product[lane].toU32());
        try std.testing.expectEqual(lhs.neg().toU32(), negated[lane].toU32());
    }
    const raw = [row_program.LANES]u32{ 0, m31.Modulus, m31.Modulus + 5, 0xffff_ffff, 1, 2, 3, m31.Modulus - 1 };
    const reduced = row_program.Block{
        .lo = row_program.reduceWordsVec(row_program.loadBlock(&raw).lo),
        .hi = row_program.reduceWordsVec(row_program.loadBlock(&raw).hi),
    };
    var reduced_words: [row_program.LANES]M31 = undefined;
    reduced.store(&reduced_words);
    for (raw, 0..) |word, lane|
        try std.testing.expectEqual(M31.fromU64(word).toU32(), reduced_words[lane].toU32());
}

test "degree-five main trace matches the candidate row writer in committed order" {
    const allocator = std.testing.allocator;
    var candidate = try candidate_mod.Candidate.init(allocator, .degree5);
    defer candidate.deinit();
    const log_size: u32 = 6;
    const size = @as(usize, 1) << log_size;
    var prng = std.Random.DefaultPrng.init(0x5eed_d5);
    const random = prng.random();
    var calls: [size - 5]production.Call = undefined;
    for (&calls, 0..) |*call, index| {
        for (&call.input) |*word| word.* = random.uintLessThan(u32, m31.Modulus);
        call.wide = index % 7 == 3;
        call.io = index % 11 == 5;
        call.narrow_output = null;
    }
    var generated = try generateMain(allocator, &candidate, &calls, log_size);
    defer generated.deinit(allocator);
    try std.testing.expectEqual(candidate.mainColumnCount(), generated.values.len);

    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    const row = try allocator.alloc(M31, candidate.mainColumnCount());
    defer allocator.free(row);
    for (0..size) |logical| {
        const committed = table.map(logical);
        if (logical < calls.len) {
            try candidate.fillRow(row, calls[logical]);
        } else {
            @memset(row, M31.zero());
        }
        for (generated.values, row) |column, expected| {
            try std.testing.expectEqual(expected.toU32(), column[committed].toU32());
        }
    }
}
