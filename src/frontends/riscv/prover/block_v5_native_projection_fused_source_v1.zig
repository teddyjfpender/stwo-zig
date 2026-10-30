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

/// Exact base-row specialization of the same typed request algebra. Evaluation
/// domains and committed witness rows contain M31 cells; OODS stays secure.
/// No typed AIR, event ordinal, partition weight or physical claim is changed.
pub fn fromCommittedMainBase(slot: Slot, main: []const core.fields.m31.M31, relations: *const Universal) !Pair {
    const M = core.fields.m31.M31;
    if (main.len != slot.width or main.len > opcode.MAX_FAMILY_COLUMNS) return error.InvalidV5FusedProjectionSlot;
    const Base = @import("../air/semantic_eval.zig").BaseScalar;
    var cells: [opcode.MAX_FAMILY_COLUMNS]Base = undefined;
    for (cells[0..main.len], main) |*cell, value| cell.* = Base.fromBase(value);
    switch (slot.kind) {
        .program => |family| {
            const request = try @import("block_v5_program_request_source_v1.zig").fromCommittedOpcodeMain(Base, family, cells[0..main.len]);
            var tuple: [5]M = undefined;
            for (&tuple, request.tuple) |*out, value| out.* = value.value;
            return .{ .entry_count = 1, .numerators = .{ Q.fromBase(request.numerator.value), Q.zero() }, .denominators = .{ try relations.get(.program_access).combineBase(&tuple), Q.one() } };
        },
        .lookup => |lookup| {
            if (main.len != lookup.width) return error.InvalidV5LookupRequestSlot;
            var list: @import("../air/lookups/entry.zig").Builder(Base).List = undefined;
            switch (lookup.source) {
                .opcode => |family| try @import("../air/lookups/opcode_entries.zig").Entries(Base).fromMainInto(family, cells[0..main.len], &list),
                .clock => {
                    const Clock = @import("../air/clock_update_interaction.zig");
                    list = Clock.orderedEntriesGeneric(Base, try Clock.RowFor(Base).fromMain(cells[0..main.len]));
                },
            }
            const pair = try @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).lookupProjectionFromEntries(lookup, &list, relations);
            return .{ .entry_count = pair.entry_count, .numerators = pair.numerators, .denominators = pair.denominators };
        },
    }
}

pub const BaseEntries = @import("../air/lookups/entry.zig").Builder(@import("../air/semantic_eval.zig").BaseScalar).List;
/// Producer-only row recipe shared by all projections of one native component.
/// The verifier still evaluates the original typed equations at opened points.
pub fn baseEntries(slot: Slot, main: []const core.fields.m31.M31) !BaseEntries {
    if (main.len != slot.width or main.len > opcode.MAX_FAMILY_COLUMNS) return error.InvalidV5FusedProjectionSlot;
    const Base = @import("../air/semantic_eval.zig").BaseScalar;
    var cells: [opcode.MAX_FAMILY_COLUMNS]Base = undefined;
    for (cells[0..main.len], main) |*cell, value| cell.* = Base.fromBase(value);
    var list: BaseEntries = undefined;
    switch (slot.kind) {
        .program => |family| try @import("../air/lookups/opcode_entries.zig").Entries(Base).fromMainInto(family, cells[0..main.len], &list),
        .lookup => |lookup| {
            if (main.len != lookup.width) return error.InvalidV5LookupRequestSlot;
            switch (lookup.source) {
                .opcode => |family| try @import("../air/lookups/opcode_entries.zig").Entries(Base).fromMainInto(family, cells[0..main.len], &list),
                .clock => {
                    const Clock = @import("../air/clock_update_interaction.zig");
                    list = Clock.orderedEntriesGeneric(Base, try Clock.RowFor(Base).fromMain(cells[0..main.len]));
                },
            }
        },
    }
    return list;
}
pub fn fromBaseEntries(slot: Slot, list: *const BaseEntries, relations: *const Universal) !Pair {
    switch (slot.kind) {
        .program => {
            const M = core.fields.m31.M31;
            var result: ?Pair = null;
            for (list.entries[0..list.len]) |entry| {
                if (entry.domain != .program_access) continue;
                if (result != null or entry.role != .request or entry.arity != 5) return error.InvalidProgramRequestRoster;
                var tuple: [5]M = undefined;
                for (&tuple, entry.values[0..5]) |*value, cell| value.* = cell.value;
                result = .{ .entry_count = 1, .numerators = .{ Q.fromBase(entry.numerator.value), Q.zero() }, .denominators = .{ try relations.get(.program_access).combineBase(&tuple), Q.one() } };
            }
            return result orelse error.MissingProgramRequest;
        },
        .lookup => |lookup| {
            const pair = try @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).lookupProjectionFromEntries(lookup, list, relations);
            return .{ .entry_count = pair.entry_count, .numerators = pair.numerators, .denominators = pair.denominators };
        },
    }
}

pub fn mixSlot(channel: anytype, slot: Slot) void {
    channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(slot.kind)), slot.degree, slot.log_size, slot.n_rows, @intCast(slot.main_offset), @intCast(slot.width), slot.register_custody_mode });
    switch (slot.kind) {
        .program => |family| channel.mixU32s(&.{@intFromEnum(family)}),
        .lookup => |lookup| {
            const id: u32 = switch (lookup.source) {
                .opcode => |family| @intFromEnum(family),
                .clock => opcode.N_FAMILIES,
            };
            channel.mixU32s(&.{ id, @intFromEnum(lookup.partition), lookup.entries[0], lookup.entries[1], lookup.entry_count });
            if (lookup.direct_ram_clock_v3) channel.mixU32s(&.{ 0x52434c33, 3 });
        },
    }
}
