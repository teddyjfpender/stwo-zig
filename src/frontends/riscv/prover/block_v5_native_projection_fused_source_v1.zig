//! Canonical program + native lookup/state/register projection schedule.
//! All requests read the original native main columns and the B5SS universal
//! challenges. This schedule grants no authority without fresh native admission.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const opcode = @import("../runner/trace.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Program = @import("block_v5_program_request_proof_v1.zig");
const Lookup = @import("block_v5_native_lookup_request_source_v1.zig");
const Universal = @import("../recursion/air/universal_challenges.zig").UniversalRelations;
pub const PARTITION_COUNT = Lookup.PARTITION_COUNT;
pub const Partition = Lookup.Partition;
pub const Pair = Lookup.Pair;
pub const Slot = struct {
    kind: union(enum) { program: opcode.OpcodeFamily, lookup: Lookup.Slot },
    degree: u8,
    log_size: u32,
    n_rows: u32,
    main_offset: usize,
    width: usize,
    register_custody_mode: u32,
};

/// Program slots precede exact typed lookup slots. The receiver derives this
/// complete schedule independently; it never trusts transported slot metadata.
pub fn slotsFromShapeForMode(a: std.mem.Allocator, shape: *const Shape, external: u32, mode: u32) ![]Slot {
    try shape.validateBlake3ExecutionWithExternal(external);
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    const programs = try Program.slotsFromStatement(a, shape);
    defer a.free(programs);
    const lookups = try Lookup.slotsFromShapeForMode(a, shape, external, mode);
    defer a.free(lookups);
    const out = try a.alloc(Slot, try std.math.add(usize, programs.len, lookups.len));
    for (programs, out[0..programs.len]) |slot, *item| item.* = .{
        .kind = .{ .program = slot.family },
        .degree = 3,
        .log_size = slot.log_size,
        .n_rows = slot.n_rows,
        .main_offset = slot.main_offset,
        .width = opcode.nColumnsForFamily(slot.family),
        .register_custody_mode = mode,
    };
    for (lookups, out[programs.len..]) |slot, *item| item.* = .{
        .kind = .{ .lookup = slot },
        .degree = slot.degree,
        .log_size = slot.log_size,
        .n_rows = slot.n_rows,
        .main_offset = slot.main_offset,
        .width = slot.width,
        .register_custody_mode = mode,
    };
    return out;
}
pub fn fromCommittedMain(slot: Slot, main: []const Q, relations: *const Universal) !Pair {
    const pair = try @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).projection(slot, main, relations);
    return .{ .entry_count = pair.entry_count, .numerators = pair.numerators, .denominators = pair.denominators };
}

pub fn mixSlot(channel: *core.proof_suites.Blake3.Channel, slot: Slot) void {
    channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(slot.kind)), slot.degree, slot.log_size, slot.n_rows, @intCast(slot.main_offset), @intCast(slot.width), slot.register_custody_mode });
    switch (slot.kind) {
        .program => |family| channel.mixU32s(&.{@intFromEnum(family)}),
        .lookup => |lookup| {
            const id: u32 = switch (lookup.source) {
                .opcode => |family| @intFromEnum(family),
                .clock => opcode.N_FAMILIES,
            };
            channel.mixU32s(&.{ id, @intFromEnum(lookup.partition), lookup.entries[0], lookup.entries[1], lookup.entry_count });
        },
    }
}
