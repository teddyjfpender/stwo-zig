const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const schedule_bindings = @import("../schedule_bindings.zig");
const Error = @import("../resident/errors.zig").Error;

const purpose = schedule_bindings.purpose;
const logicalId = schedule_bindings.logicalId;
const one = schedule_bindings.one;
const oneOrdinal = schedule_bindings.oneOrdinal;

pub const ProofCopy = struct {
    source: arena_plan.Binding,
    destination_word_offset: u32,
    word_count: u32,
};

pub fn collectAssembly(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) ![]arena_plan.Binding {
    var result = std.ArrayList(arena_plan.Binding).empty;
    errdefer result.deinit(allocator);
    for (schedule) |entry| {
        const name = try purpose(entry);
        if (!std.mem.startsWith(u8, name, "Decommit") and
            !std.mem.startsWith(u8, name, "Transcript") and
            !std.mem.startsWith(u8, name, "Pow") and
            !std.mem.eql(u8, name, "ProofBytes")) continue;
        try result.append(allocator, plan.binding(try logicalId(entry)) catch return Error.MissingBinding);
    }
    if (result.items.len == 0) return Error.MissingBinding;
    return result.toOwnedSlice(allocator);
}

pub fn buildProofCopies(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fri_round_count: usize,
) ![]ProofCopy {
    const transcript_ordinals = try proofCopyTranscriptOrdinals(allocator, fri_round_count);
    defer allocator.free(transcript_ordinals);
    var copies = std.ArrayList(ProofCopy).empty;
    errdefer copies.deinit(allocator);
    var cursor: u32 = 0;
    const append = struct {
        fn binding(list: *std.ArrayList(ProofCopy), alloc: std.mem.Allocator, position: *u32, source: arena_plan.Binding) !void {
            if (source.size_bytes % 4 != 0 or source.size_bytes / 4 > std.math.maxInt(u32)) return Error.InvalidBindingSize;
            const words: u32 = @intCast(source.size_bytes / 4);
            try list.append(alloc, .{ .source = source, .destination_word_offset = position.*, .word_count = words });
            position.* = std.math.add(u32, position.*, words) catch return Error.InvalidBindingSize;
        }
    }.binding;
    for (transcript_ordinals) |input| try append(
        &copies,
        allocator,
        &cursor,
        try oneOrdinal(schedule, plan, "TranscriptInput", input),
    );
    try append(&copies, allocator, &cursor, try one(schedule, plan, "DecommitAssembly"));
    return copies.toOwnedSlice(allocator);
}

pub fn proofCopyTranscriptOrdinals(
    allocator: std.mem.Allocator,
    fri_round_count: usize,
) ![]u32 {
    if (fri_round_count == 0 or fri_round_count > 31) return Error.InvalidCardinality;
    const ordinals = try allocator.alloc(u32, fri_round_count + 9);
    const prefix = [_]u32{ 3, 20, 23, 24, 22, 21, 25 };
    @memcpy(ordinals[0..prefix.len], &prefix);
    for (0..fri_round_count) |round| {
        ordinals[prefix.len + round] = 65536 + @as(u32, @intCast(round)) * 4;
    }
    ordinals[ordinals.len - 2] = 30;
    ordinals[ordinals.len - 1] = 31;
    return ordinals;
}
