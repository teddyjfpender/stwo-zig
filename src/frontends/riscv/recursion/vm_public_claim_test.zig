//! Conformance and adversarial gates for the canonical recursive VM claim.

const std = @import("std");
const stwo_core = @import("stwo_core");
const public_data_mod = @import("../air/public_data.zig");
const claim = @import("vm_public_claim.zig");
const claim_witness = @import("air/vm_public_claim_input_witness.zig");

const M31 = stwo_core.fields.m31.M31;

test "R-012 VM public claim uses exact fixed V1 geometry and feeds row 12" {
    const data = testPublicData();
    const shape = try claim.Shape.init(3, 3);
    var encoded = try claim.encode(std.testing.allocator, &data, shape);
    defer encoded.deinit();

    try std.testing.expectEqual(@as(usize, 289), encoded.words.len);
    try std.testing.expectEqual(@as(u32, @intFromEnum(claim.Tag.claim)), encoded.words[0].toU32());
    try std.testing.expectEqual(@as(u32, @intFromEnum(claim.Tag.shape)), encoded.words[1].toU32());
    try std.testing.expectEqual(@as(u32, 3), readU32(encoded.words, 2));
    try std.testing.expectEqual(@as(u32, 3), readU32(encoded.words, 4));
    try std.testing.expectEqual(data.initial_pc, readU32(encoded.words, claim.canonical_layout.initial_pc_start));
    try std.testing.expectEqual(data.final_pc, readU32(encoded.words, claim.canonical_layout.final_pc_start));
    try std.testing.expectEqual(data.clock, readU32(encoded.words, claim.canonical_layout.clock_start));

    try expectExpandedRoot(encoded.words, claim.canonical_layout.program_root_present, data.program_root.?);
    try expectExpandedRoot(encoded.words, claim.canonical_layout.initial_rw_root_present, data.initial_rw_root.?);
    try expectExpandedRoot(encoded.words, claim.canonical_layout.final_rw_root_present, data.final_rw_root.?);

    const input_padding = claim.canonical_layout.inputSlotPresent(2);
    try std.testing.expectEqual(@as(u32, 0), encoded.words[input_padding].toU32());
    try std.testing.expectEqual(@as(u32, 0), readU32(encoded.words, input_padding + 1));
    const output_padding = claim.canonical_layout.outputSlotPresent(shape, 2);
    for (encoded.words[output_padding .. output_padding + claim.OUTPUT_SLOT_WORDS]) |word|
        try std.testing.expectEqual(@as(u32, 0), word.toU32());

    var preprocessing = try claim_witness.Preprocessed.init(std.testing.allocator, shape);
    defer preprocessing.deinit();
    var main = try claim_witness.MainWitness.init(
        std.testing.allocator,
        &preprocessing,
        .{ .segment_leaf = encoded.words },
    );
    defer main.deinit();
    try main.validateAgainst(&preprocessing);
    try encoded.validateAgainst(&data);
}

test "R-012 VM public claim digests bind proof fields but output digest excludes clocks" {
    const shape = try claim.Shape.init(3, 3);
    const first_data = testPublicData();
    var first = try claim.encode(std.testing.allocator, &first_data, shape);
    defer first.deinit();

    var changed_clock_data = testPublicData();
    var changed_clock_words = test_output_words;
    changed_clock_words[1].clock = 9;
    changed_clock_data.io_entries.output_words = &changed_clock_words;
    var changed_clock = try claim.encode(std.testing.allocator, &changed_clock_data, shape);
    defer changed_clock.deinit();
    try std.testing.expect(!std.meta.eql(first.digest, changed_clock.digest));
    try std.testing.expectEqual(first.public_output_digest, changed_clock.public_output_digest);

    var changed_input_data = testPublicData();
    var changed_input_words = test_input_words;
    changed_input_words[0] ^= 1;
    changed_input_data.io_entries.input_words = &changed_input_words;
    var changed_input = try claim.encode(std.testing.allocator, &changed_input_data, shape);
    defer changed_input.deinit();
    try std.testing.expect(!std.meta.eql(first.public_input_digest, changed_input.public_input_digest));
    try std.testing.expect(!std.meta.eql(first.digest, changed_input.digest));
}

test "R-012 VM public claim fails closed outside the admitted completion profile" {
    const shape = try claim.Shape.init(3, 3);
    var halt = testPublicData();
    halt.completion = .{
        .kind = .halt_flag,
        .address = 0x20_0000,
        .value = 1,
        .clock = 9,
    };
    try std.testing.expectError(
        error.HaltFlagCompletionRequiresClaimV2,
        claim.encode(std.testing.allocator, &halt, shape),
    );

    var noncanonical_root = testPublicData();
    noncanonical_root.program_root = stwo_core.fields.m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalRoot,
        claim.encode(std.testing.allocator, &noncanonical_root, shape),
    );

    try std.testing.expectError(
        error.VectorExceedsShape,
        claim.encode(std.testing.allocator, &testPublicData(), try claim.Shape.init(1, 3)),
    );
}

test "R-012 VM public claim releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const data = testPublicData();
    var encoded = try claim.encode(allocator, &data, try claim.Shape.init(3, 3));
    defer encoded.deinit();
    try encoded.validateAgainst(&data);
}

fn readU32(words: []const M31, start: usize) u32 {
    return words[start].toU32() | (words[start + 1].toU32() << 16);
}

fn expectExpandedRoot(words: []const M31, present: usize, expected: u32) !void {
    try std.testing.expectEqual(@as(u32, 1), words[present].toU32());
    try std.testing.expectEqual(expected, words[present + 1].toU32());
    for (words[present + 2 .. present + 9]) |word|
        try std.testing.expectEqual(@as(u32, 0), word.toU32());
}

const test_input_words = [_]u32{ 0x4433_2211, 0x55 };
const test_output_words = [_]public_data_mod.OutputWord{
    .{ .addr = 0x10_0004, .value = 4, .clock = 5 },
    .{ .addr = 0x10_0008, .value = 0x8877_6655, .clock = 6 },
};

fn testPublicData() public_data_mod.PublicData {
    var initial_regs = [_]u32{0} ** 32;
    initial_regs[1] = 0x8000_0001;
    var final_regs = initial_regs;
    final_regs[2] = 9;
    var reg_last_clock = [_]u32{0} ** 32;
    reg_last_clock[2] = 7;
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = public_data_mod.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{
            .input_start = 0x20_0000,
            .input_len = 5,
            .input_words = &test_input_words,
            .output_len = 4,
            .output_len_addr = 0x10_0004,
            .output_data_addr = 0x10_0008,
            .output_words = &test_output_words,
        },
    };
}
