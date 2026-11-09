//! Executed admission and lifetime contracts for the three bounded observers.
const std = @import("std");
const Authority = @import("observations/journal.zig").JournalAuthority;
const zero = [_]u8{0} ** 32;
const header = "{\"payload\":{\"schema\":\"stwo.riscv.segmented-execution-header.v3\",\"profile\":\"rv32im-zkvm-ethereum-v1\",\"clock_frame\":\"leaf_local\",\"elf_sha256\":\"" ++ ("0" ** 64) ++ "\",\"input_sha256\":\"" ++ ("0" ** 64) ++ "\",\"segment_step_budget\":8}}\n";
const segment = "{\"payload\":{\"schema\":\"stwo.riscv.segmented-execution-segment.v3\",\"segment_index\":0,\"global_first_cycle\":17,\"cycle_count\":3,\"core_trace_rows\":2}}\n";
const valid = header ++ segment;

test {
    _ = @import("pc_hotspot/options.zig");
    _ = @import("memcpy_hotspot/options.zig");
    _ = @import("function_value/options.zig");
    _ = @import("function_value/input.zig");
    _ = @import("memcpy_admission/options.zig");
    _ = @import("memcpy_admission/classifier.zig");
    _ = @import("analyze_legacy_semantics/main.zig");
}

test "observation journal: selected prefix owns its segments" {
    const backing = try std.testing.allocator.dupe(u8, valid ++ "unselected trailing record\n");
    var parsed = try Authority.parse(std.testing.allocator, backing, zero, zero, 1);
    std.testing.allocator.free(backing);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u64, 17), parsed.first_global_cycle);
    try std.testing.expectEqual(@as(u64, 3), parsed.sampled_cycles);
    try std.testing.expectEqual(@as(u64, 2), parsed.retired_instructions);
    try std.testing.expectEqual(@as(usize, 8), parsed.segment_step_budget);
    try std.testing.expectEqual(@as(u32, 0), parsed.segments[0].segment_index);
}

test "observation journal: identity and header admission reject" {
    try std.testing.expectError(error.InvalidJournal, Authority.parse(std.testing.allocator, "", zero, zero, 1));
    for ([_][2][]const u8{
        .{ "header.v3", "header.v2" },                                          .{ "ethereum-v1", "ethereum-v2" },
        .{ "leaf_local", "global" },                                            .{ "\"segment_step_budget\":8", "\"segment_step_budget\":0" },
        .{ "\"segment_step_budget\":8", "\"segment_step_budget\":4294967296" }, .{ "\"segment_step_budget\":8", "\"segment_step_budget\":-1" },
    }) |mutation| try rejectMutation(mutation[0], mutation[1]);
    const different = [_]u8{1} ** 32;
    try std.testing.expectError(error.JournalInputMismatch, Authority.parse(std.testing.allocator, valid, different, zero, 1));
    try std.testing.expectError(error.JournalInputMismatch, Authority.parse(std.testing.allocator, valid, zero, different, 1));
}

test "observation journal: segment bounds and truncation reject" {
    try std.testing.expectError(error.InvalidJournal, Authority.parse(std.testing.allocator, header, zero, zero, 1));
    try std.testing.expectError(error.InvalidJournal, Authority.parse(std.testing.allocator, valid, zero, zero, 2));
    for ([_][2][]const u8{
        .{ "segment.v3", "segment.v2" },                        .{ "\"segment_index\":0", "\"segment_index\":1" },
        .{ "\"cycle_count\":3", "\"cycle_count\":0" },          .{ "\"core_trace_rows\":2", "\"core_trace_rows\":0" },
        .{ "\"cycle_count\":3", "\"cycle_count\":4294967296" }, .{ "\"global_first_cycle\":17", "\"global_first_cycle\":-1" },
    }) |mutation| try rejectMutation(mutation[0], mutation[1]);
}

fn rejectMutation(before: []const u8, after: []const u8) !void {
    const bytes = try std.mem.replaceOwned(u8, std.testing.allocator, valid, before, after);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectError(error.InvalidJournal, Authority.parse(std.testing.allocator, bytes, zero, zero, 1));
}

fn allocationAttempt(allocator: std.mem.Allocator) !void {
    var parsed = try Authority.parse(allocator, valid, zero, zero, 1);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), parsed.sampled_cycles);
}

test "observation journal: every allocation failure releases partial state" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationAttempt, .{});
}

test "observation contracts: required named discovery" {
    for ([_][]const u8{
        "observation journal: selected prefix owns its segments",
        "observation journal: identity and header admission reject",
        "observation journal: segment bounds and truncation reject",
        "observation journal: every allocation failure releases partial state",
        "pc-hotspot options retain prefix count and radix admission",
        "memcpy-hotspot options retain prefix count and radix admission",
        "options accept exact hex PCs and instruction words",
        "function-value options retain bounded sample admission",
        "function-value input rejects oversized and nonregular files",
        "memcpy-admission options retain prefix count and radix admission",
        "classifier matches aligned-word candidate boundary",
        "memcpy classifier retains every rejection class",
        "options require every exact custody input",
        "input identity borrows digest storage from its owner",
        "call wire borrows digest and opcode storage from retained call",
        "witness code wire borrows its retained hex allocation",
        "canonical sealed identity wire reopens to its unsigned bytes",
        "snapshot reader handles unaligned exact bytes",
        "strict SSZ code inventory classifies legacy, delegation, and empty",
    }) |required| {
        var found = false;
        for (@import("builtin").test_functions) |entry| {
            if (std.mem.endsWith(u8, entry.name, required)) found = true;
        }
        try std.testing.expect(found);
    }
}
