//! Resident Cairo twiddle-bank layout and materialization.

const std = @import("std");
const arena_plan = @import("stwo_metal_backend").arena_plan;
const schedule_bindings = @import("../schedule_bindings.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const twiddles_mod = @import("stwo_prover_engine").poly.twiddles;
const canonic_circle_mod = @import("stwo_core").poly.circle.canonic;
const circle_mod = @import("stwo_core").circle;

const Error = error{InvalidBindingSize};

pub fn populateProtocolTwiddles(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) !void {
    const forward = try schedule_bindings.one(schedule, plan, "ForwardTwiddles");
    const preprocessed_inverse = try schedule_bindings.one(schedule, plan, "PreprocessedInverseTwiddles");
    if (forward.size_bytes != preprocessed_inverse.size_bytes) return Error.InvalidBindingSize;
    try populateTwiddlePair(allocator, resident_arena, forward, preprocessed_inverse);
    const inverse = try schedule_bindings.one(schedule, plan, "InverseTwiddles");
    try populateInverseTwiddles(allocator, resident_arena, inverse);
    const quotient_inverse = try schedule_bindings.one(schedule, plan, "QuotientInverseTwiddles");
    try populateSplitSubdomainInverseTwiddles(allocator, resident_arena, quotient_inverse);
}

pub fn populateForwardTwiddles(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) !void {
    try populateForwardTwiddleBinding(
        allocator,
        resident_arena,
        try schedule_bindings.one(schedule, plan, "ForwardTwiddles"),
    );
}

pub fn populateForwardTwiddleBinding(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    forward: arena_plan.Binding,
) !void {
    if (forward.size_bytes == 0 or forward.size_bytes % 4 != 0 or
        !std.math.isPowerOfTwo(forward.size_bytes / 4))
        return Error.InvalidBindingSize;
    const log_words: u32 = std.math.log2_int(u64, forward.size_bytes / 4);
    var tree = try twiddles_mod.precomputeM31(allocator, circle_mod.Coset.halfOdds(log_words));
    defer twiddles_mod.deinitM31(allocator, &tree);
    @memcpy(try resident_arena.bytes(forward), std.mem.sliceAsBytes(tree.twiddles));
}

pub fn twiddleBankBinding(storage: arena_plan.Binding, log_size: u32) arena_plan.Binding {
    std.debug.assert(log_size >= 4);
    return storage;
}

pub fn populateNamedInverseTwiddles(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    purpose_name: []const u8,
) !void {
    try populateInverseTwiddles(
        allocator,
        resident_arena,
        try schedule_bindings.one(schedule, plan, purpose_name),
    );
}

pub fn populateQuotientInverseTwiddles(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) !void {
    try populateSplitSubdomainInverseTwiddles(
        allocator,
        resident_arena,
        try schedule_bindings.one(schedule, plan, "QuotientInverseTwiddles"),
    );
}

fn populateTwiddlePair(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    forward: arena_plan.Binding,
    inverse: arena_plan.Binding,
) !void {
    if (forward.size_bytes == 0 or forward.size_bytes % 4 != 0 or
        !std.math.isPowerOfTwo(forward.size_bytes / 4))
        return Error.InvalidBindingSize;
    const log_words: u32 = std.math.log2_int(u64, forward.size_bytes / 4);
    var tree = try twiddles_mod.precomputeM31(allocator, circle_mod.Coset.halfOdds(log_words));
    defer twiddles_mod.deinitM31(allocator, &tree);
    @memcpy(try resident_arena.bytes(forward), std.mem.sliceAsBytes(tree.twiddles));
    @memcpy(try resident_arena.bytes(inverse), std.mem.sliceAsBytes(tree.itwiddles));
}

pub fn populateInverseTwiddles(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    inverse: arena_plan.Binding,
) !void {
    if (inverse.size_bytes == 0 or inverse.size_bytes % 4 != 0 or
        !std.math.isPowerOfTwo(inverse.size_bytes / 4))
        return Error.InvalidBindingSize;
    const log_words: u32 = std.math.log2_int(u64, inverse.size_bytes / 4);
    var tree = try twiddles_mod.precomputeM31(allocator, circle_mod.Coset.halfOdds(log_words));
    defer twiddles_mod.deinitM31(allocator, &tree);
    @memcpy(try resident_arena.bytes(inverse), std.mem.sliceAsBytes(tree.itwiddles));
}

fn populateSplitSubdomainInverseTwiddles(
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    inverse: arena_plan.Binding,
) !void {
    if (inverse.size_bytes == 0 or inverse.size_bytes % 4 != 0 or
        !std.math.isPowerOfTwo(inverse.size_bytes / 4))
        return Error.InvalidBindingSize;
    const half_coset_log: u32 = std.math.log2_int(u64, inverse.size_bytes / 4);
    const subdomain_log = half_coset_log + 1;
    var split = try canonic_circle_mod.CanonicCoset.new(subdomain_log + 1)
        .circleDomain().split(allocator, 1);
    defer split.deinit(allocator);
    var tree = try twiddles_mod.precomputeM31(allocator, split.subdomain.half_coset);
    defer twiddles_mod.deinitM31(allocator, &tree);
    if (tree.itwiddles.len * @sizeOf(M31) != inverse.size_bytes)
        return Error.InvalidBindingSize;
    @memcpy(try resident_arena.bytes(inverse), std.mem.sliceAsBytes(tree.itwiddles));
}

pub fn twiddleBindingForLog(storage: arena_plan.Binding, log_size: u32) !arena_plan.Binding {
    const offset_words = try twiddleOffsetForLog(storage, log_size);
    var result = storage;
    result.offset_bytes = @as(u64, offset_words) * 4;
    result.size_bytes = (@as(u64, 1) << @intCast(log_size - 1)) * 4;
    return result;
}

pub fn twiddleOffsetForLog(binding: arena_plan.Binding, transform_log: u32) !u32 {
    if (transform_log == 0 or binding.offset_bytes % 4 != 0 or binding.size_bytes % 4 != 0)
        return Error.InvalidBindingSize;
    const required_words = @as(u64, 1) << @intCast(transform_log - 1);
    const available_words = binding.size_bytes / 4;
    if (required_words > available_words) return Error.InvalidBindingSize;
    return std.math.cast(u32, binding.offset_bytes / 4 + available_words - required_words) orelse
        Error.InvalidBindingSize;
}

fn testBinding(offset_bytes: u64, size_bytes: u64) arena_plan.Binding {
    return .{
        .logical_id = 7,
        .slot = 3,
        .offset_bytes = offset_bytes,
        .size_bytes = size_bytes,
        .materialization = undefined,
        .occupied = undefined,
    };
}

test "metal: Cairo twiddle log views are tail-aligned within the resident bank" {
    const bank = testBinding(4096, 256);
    const view = try twiddleBindingForLog(bank, 5);

    try std.testing.expectEqual(@as(u64, 4288), view.offset_bytes);
    try std.testing.expectEqual(@as(u64, 64), view.size_bytes);
    try std.testing.expectEqual(@as(u32, 7), view.logical_id);
    try std.testing.expectEqual(@as(u32, 3), view.slot);
}

test "metal: Cairo twiddle log views reject invalid bank extents" {
    try std.testing.expectError(Error.InvalidBindingSize, twiddleOffsetForLog(testBinding(2, 256), 5));
    try std.testing.expectError(Error.InvalidBindingSize, twiddleOffsetForLog(testBinding(0, 258), 5));
    try std.testing.expectError(Error.InvalidBindingSize, twiddleOffsetForLog(testBinding(0, 32), 5));
    try std.testing.expectError(Error.InvalidBindingSize, twiddleOffsetForLog(testBinding(0, 256), 0));
}
