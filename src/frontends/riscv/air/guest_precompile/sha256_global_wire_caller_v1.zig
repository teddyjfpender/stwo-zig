//! Experimental caller recipe with an independently admitted global SHA wire
//! clock. All CPU/register/memory values retain the original local clocks.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("sha256_memory_caller.zig");
const lang = @import("../lang/mod.zig");
const M = core.fields.m31.M31;
pub const Layout = Original.Layout;
pub const PROGRAM_BOUND_PC_INPUTS = Original.PROGRAM_BOUND_PC_INPUTS;
pub const PHYSICAL_MAIN_COLUMN_COUNT = Original.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = Original.PREPROCESSED_COLUMN_COUNT;
pub const LOGICAL_INPUT_COUNT = Original.LOGICAL_INPUT_COUNT + 1;
pub const DIRECT_CONSTRAINT_COUNT = Original.DIRECT_CONSTRAINT_COUNT;
pub const RELATION_EVENT_COUNT = Original.RELATION_EVENT_COUNT;
pub const LOOKUP_BATCH_SIZE = Original.LOOKUP_BATCH_SIZE;
pub const INTERACTION_BATCH_COUNT = Original.INTERACTION_BATCH_COUNT;
pub const INTERACTION_COLUMN_COUNT = Original.INTERACTION_COLUMN_COUNT;
pub const MAXIMUM_CONSTRAINT_DEGREE = Original.MAXIMUM_CONSTRAINT_DEGREE;
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "ef30d9269649ceb006c759533dbd8b315499500fac4ce6164898c8e8d57b68ef") catch unreachable;
    break :blk out;
};
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,
    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const @This()) !void {
        try lang.validate.validate(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or self.arena.effectsView().len != RELATION_EVENT_COUNT) return error.InvalidGlobalShaCallerGeometry;
        const digest = try lang.digest.computeIdentity(&self.arena);
        if (!std.mem.eql(u8, &digest.bytes, &SEMANTIC_DIGEST)) return error.UntrustedGlobalShaCallerRecipe;
    }
};
pub fn build(a: std.mem.Allocator) !Definition {
    const old = try Original.buildGlobalWireClock(a);
    return .{ .arena = old.arena, .events = old.events };
}
/// The original execution scope, not an untrusted witness, selects this frame.
/// This prototype rejects clocks that could alias modulo M31.
pub fn offsetForFrame(frame: @import("../block/memory_event.zig").Frame) !M {
    if (frame.clock_frame != .leaf_local or frame.global_first_cycle == 0 or frame.cycle_count == 0) return error.InvalidGlobalShaWireFrame;
    const offset = frame.global_first_cycle - 1;
    const end = try std.math.add(u64, offset, frame.cycle_count);
    if (end >= 0x7fffffff) return error.GlobalShaWireClockExceedsField;
    return M.fromCanonical(@intCast(offset));
}
pub fn row(call: @import("sha256_memory_record.zig").Record, offset: M) !Row {
    return (try Original.row(call)) ++ .{offset};
}
test "global SHA caller recipe identity" {
    var definition = try build(std.testing.allocator);
    defer definition.deinit();
    const identity = try lang.digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualSlices(u8, &SEMANTIC_DIGEST, &identity.bytes);
    try definition.validate();
    var old = try Original.build(std.testing.allocator);
    defer old.deinit();
    try old.validate();
}

test "global SHA caller offset rejects modular alias and invalid frame" {
    const Frame = @import("../block/memory_event.zig").Frame;
    const valid = Frame{ .clock_frame = .leaf_local, .global_first_cycle = 100, .cycle_count = 20 };
    try std.testing.expectEqual(@as(u32, 99), (try offsetForFrame(valid)).toU32());
    var wrong = valid;
    wrong.global_first_cycle = 0;
    try std.testing.expectError(error.InvalidGlobalShaWireFrame, offsetForFrame(wrong));
    wrong = valid;
    wrong.global_first_cycle = 0x7fffffff - 10;
    try std.testing.expectError(error.GlobalShaWireClockExceedsField, offsetForFrame(wrong));
    wrong.global_first_cycle = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, offsetForFrame(wrong));
}
