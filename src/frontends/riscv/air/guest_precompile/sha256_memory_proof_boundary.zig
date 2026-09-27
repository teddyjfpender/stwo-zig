//! Public CPU/memory tuples for the standalone SHA caller proof gate. These
//! fixtures are replaced by the VM's program, register and memory providers.
const std = @import("std");
const lang = @import("../lang/definition.zig");
const effects = @import("../../recursion/air/relation_effect.zig");
const M = @import("stwo_core").fields.m31.M31;
const Record = @import("sha256_memory_record.zig").Record;
const clock = @import("../../access_clock.zig");
const opcode = @import("../../isa/sha256_compression_v1.zig").proof_opcode_id;
pub const PHYSICAL_MAIN_COLUMN_COUNT = 0;
pub const PREPROCESSED_COLUMN_COUNT = 17;
pub const LOGICAL_INPUT_COUNT = 17;
pub const FIXED_ADDRESS_INPUTS: []const usize = &.{ 0, 6, 10 };
pub const DIRECT_CONSTRAINT_COUNT = 0;
pub const RELATION_EVENT_COUNT = 3;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT = 2;
pub const INTERACTION_COLUMN_COUNT = 8;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 1;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, "c08a15c38e4b85cd4ea29faff61b849c8e5c2375482a6b73a968588ba57511a0") catch unreachable;
    break :blk result;
};
pub const Row = [LOGICAL_INPUT_COUNT]M;
pub const Definition = struct {
    arena: lang.ir.Arena,
    events: [3]lang.types.EffectId,
    pub fn deinit(self: *@This()) void {
        self.arena.deinit();
    }
    pub fn validate(self: *const @This()) !void {
        try lang.validate.validate(&self.arena);
        if (!std.mem.eql(u8, &(try lang.digest.computeIdentity(&self.arena)).bytes, &SEMANTIC_DIGEST)) return error.InvalidShaPublicBoundary;
    }
};
pub fn build(a: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    const span = lang.source.SourceSpan.generated();
    var ids: [LOGICAL_INPUT_COUNT]lang.types.ValueId = undefined;
    for (&ids, 0..) |*id, i| {
        var name: [48]u8 = undefined;
        const ty: lang.types.Type = if (i == 0 or i == 6) .pc else if (i == 10) .address else if (i == 7 or i == 11) .clock else if (i >= 12 and i < 16) .byte else .felt;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "sha.public.value_{d}", .{i}), ty, span);
    }
    const events = try effects.appendGroup(3, &arena, .{
        .{ .domain = .program_access, .role = .request, .values = ids[0..5], .weight = ids[5] },
        .{ .domain = .registers_state, .role = .emit, .values = ids[6..8], .weight = ids[8] },
        .{ .domain = .memory_access, .role = .emit, .values = ids[9..16], .weight = ids[16] },
    }, span);
    try lang.validate.validate(&arena);
    const result = Definition{ .arena = arena, .events = events };
    try result.validate();
    return result;
}
pub fn rows(a: std.mem.Allocator, call: Record) ![]Row {
    // This admits a statement shape, not the SHA result. An incorrect output
    // must fail the proof rather than being excluded by a host SHA oracle.
    if (call.pc >= (1 << 30) - 4 or call.pc & 3 != 0 or call.execution_clock == 0 or clock.maximum(call.execution_clock) >= @import("stwo_core").fields.m31.Modulus) return error.InvalidShaPublicBoundary;
    if (call.state_ptr & 3 != 0 or call.block_ptr & 3 != 0 or @as(u64, call.state_ptr) + 32 > (1 << 30) or @as(u64, call.block_ptr) + 64 > (1 << 30)) return error.InvalidShaPublicBoundary;
    const result = try a.alloc(Row, 64);
    @memset(result, @splat(M.zero()));
    result[0][0..6].* = .{ M.fromCanonical(call.pc), M.fromCanonical(opcode), M.zero(), M.fromCanonical(call.state_register), M.fromCanonical(call.block_register), M.one().neg() };
    result[1][6..9].* = .{ M.fromCanonical(call.pc), M.fromCanonical(call.execution_clock), M.one() };
    result[2][6..9].* = .{ M.fromCanonical(call.pc + 4), M.fromCanonical(call.execution_clock + 1), M.one().neg() };
    for (0..26) |i| for (0..2) |side| {
        const out = &result[3 + 2 * i + side];
        const word = if (i < 2) (if (i == 0) call.state_ptr else call.block_ptr) else (if (side == 0) call.before(i - 2) else call.after(i - 2));
        const address: u32 = if (i < 2) (if (i == 0) call.state_register else call.block_register) else call.address(i - 2);
        const previous = if (i < 2) call.pointer_previous_clocks[i] else call.memory_previous_clocks[i - 2];
        const current = clock.encode(call.execution_clock, if (i < 2) .first else .second);
        if (previous >= current) {
            a.free(result);
            return error.InvalidShaPublicBoundary;
        }
        out[9..12].* = .{ M.fromCanonical(@intFromBool(i >= 2)), M.fromCanonical(address), M.fromCanonical(if (side == 0) previous else current) };
        for (0..4) |byte| out[12 + byte] = M.fromCanonical((word >> @as(u5, @intCast(byte * 8))) & 255);
        out[16] = if (side == 0) M.one() else M.one().neg();
    };
    return result;
}
test "SHA memory proof boundary identity" {
    var d = try build(std.testing.allocator);
    defer d.deinit();
    std.debug.print("SHA_MEMORY_BOUNDARY digest={s}\n", .{std.fmt.bytesToHex((try lang.digest.computeIdentity(&d.arena)).bytes, .lower)});
}
