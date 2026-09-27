//! End-to-end and hostile mutation gates for rows 10 and 12--14.

const std = @import("std");
const public_data_mod = @import("../air/public_data.zig");
const owner = @import("segment_leaf_authority.zig");
const claim = @import("vm_public_claim.zig");

test "R-012 segment authority derives rows 10 and 12 through 14 once" {
    const data = testPublicData();
    var preprocessing = try owner.Preprocessing.init(
        std.testing.allocator,
        try claim.Shape.init(3, 3),
    );
    defer preprocessing.deinit();
    var prepared = try owner.Prepared.init(
        std.testing.allocator,
        &preprocessing,
        &data,
    );
    defer prepared.deinit();
    try prepared.validateAgainst(&preprocessing, &data);
    try std.testing.expectEqual(
        preprocessing.claim_hash.rows.len + preprocessing.io_hash.rows.len,
        prepared.poseidonCallCount(),
    );
}

test "R-012 segment authority rejects detached claim and statement snapshots" {
    const data = testPublicData();
    var preprocessing = try owner.Preprocessing.init(
        std.testing.allocator,
        try claim.Shape.init(3, 3),
    );
    defer preprocessing.deinit();
    var prepared = try owner.Prepared.init(
        std.testing.allocator,
        &preprocessing,
        &data,
    );
    defer prepared.deinit();

    prepared.claim_hash.output_digest[0] ^= 1;
    try std.testing.expectError(
        error.DigestMismatch,
        prepared.validateAgainst(&preprocessing, &data),
    );
    prepared.claim_hash.output_digest[0] ^= 1;

    const index = @import("span_statement.zig").canonical_layout.public_output_start;
    const saved = prepared.statement.words[index];
    prepared.statement.words[index] = saved.add(@import("stwo_core").fields.m31.M31.one());
    try std.testing.expectError(
        error.DigestMismatch,
        prepared.validateAgainst(&preprocessing, &data),
    );
}

test "R-012 segment authority releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const data = testPublicData();
    var preprocessing = try owner.Preprocessing.init(
        allocator,
        try claim.Shape.init(3, 3),
    );
    defer preprocessing.deinit();
    var prepared = try owner.Prepared.init(allocator, &preprocessing, &data);
    defer prepared.deinit();
    try prepared.validateAgainst(&preprocessing, &data);
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
