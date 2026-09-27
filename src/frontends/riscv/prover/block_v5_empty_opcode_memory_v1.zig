//! Explicit empty packed opcode admission. This creates no STARK or scalar:
//! only a freshly verified zero-slot native shape can authorize the branch.
const std = @import("std");
const core = @import("stwo_core");
const shape_mod = @import("../air/statement.zig");
const frame_mod = @import("../air/block/memory_event.zig");
const source = @import("block_execution_sidecar_batch_v2.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const native = @import("block_v5_native_execution_proof_v3.zig");
const word = @import("block_v5_word_memory_protocol_v1.zig");
const Digest = [32]u8;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x4235454d; // B5EM

pub fn witnessRoot() Digest {
    return witnessRootForMode(0);
}
pub fn witnessRootForMode(mode: u32) Digest {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, 0x454d5054 });
    if (mode != 0) channel.mixU32s(&.{ 2, mode });
    channel.mixRoot(word.abiId());
    return channel.digestBytes();
}

/// First-round producer/planner seam. The caller independently admits native
/// roots and shape; the receiver repeats this derivation after native verify.
pub fn firstRoundEntry(a: std.mem.Allocator, shape: *const shape_mod.Blake3ExecutionStatement, frame: frame_mod.Frame, execution: seal.Entry, expected_events: u64) !seal.Entry {
    return firstRoundEntryForMode(a, shape, frame, execution, expected_events, 0);
}
pub fn firstRoundEntryForMode(a: std.mem.Allocator, shape: *const shape_mod.Blake3ExecutionStatement, frame: frame_mod.Frame, execution: seal.Entry, expected_events: u64, mode: u32) !seal.Entry {
    if (execution.family != .execution or expected_events != 0 or frame.clock_frame != .leaf_local or
        frame.global_first_cycle == 0 or frame.cycle_count != shape.public_data.clock) return error.InvalidV5EmptyOpcodeAdmission;
    const slots = try source.slotsFromStatementForMode(a, shape, frame, mode);
    defer a.free(slots);
    if (slots.len != 0) return error.NonemptyV5OpcodeShape;
    // Every supported ordinary opcode has at least one memory-access slot.
    // Thus all retirements in this shape must be independently proved callers.
    if (mode == 0 and shape.n_components != 0) return error.NonemptyV5OpcodeShape;
    var ordinary_rows: u32 = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| ordinary_rows = try std.math.add(u32, ordinary_rows, desc.n_rows);
    const external_rows = try std.math.sub(u32, shape.total_steps, ordinary_rows);
    try shape.validateBlake3ExecutionWithExternal(external_rows);
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, execution.index });
    if (mode != 0) channel.mixU32s(&.{ 2, mode });
    channel.mixRoot(word.abiId());
    channel.mixRoot(execution.instance_id);
    channel.mixRoot(execution.roots[0]);
    channel.mixRoot(execution.roots[1]);
    channel.mixU64(frame.global_first_cycle);
    channel.mixU64(frame.cycle_count);
    channel.mixRoot(witnessRootForMode(mode));
    return .{ .family = .execution_sidecar, .index = execution.index, .instance_id = channel.digestBytes(), .roots = .{ witnessRootForMode(mode), @splat(0) } };
}

/// Private fresh-native hook seam; never admit an arbitrary empty proof or a
/// caller's zero claim. The base receiver has just verified this native proof.
pub fn admit(a: std.mem.Allocator, shape: *const shape_mod.Blake3ExecutionStatement, frame: frame_mod.Frame, fresh: *const native.OpenReceipt, index: u32, expected_events: u64, sealed: seal.Sealed, pins: seal.Pins, roster: []const seal.Entry) !void {
    try sealed.require(pins, roster);
    if (index >= sealed.execution_instance_count or !std.meta.eql(fresh.sealed_digest, sealed.digest)) return error.UntrustedV5EmptyOpcodeNative;
    var execution: ?seal.Entry = null;
    var present: ?seal.Entry = null;
    for (roster) |entry| {
        if (entry.family == .execution and entry.index == index) execution = entry;
        if (entry.family == .execution_sidecar and entry.index == index) present = entry;
    }
    const base = execution orelse return error.MissingV5EmptyOpcodeNative;
    if (!std.meta.eql(base.instance_id, fresh.instance_id) or !std.meta.eql(base.roots, fresh.first_roots)) return error.UntrustedV5EmptyOpcodeNative;
    const expected = try firstRoundEntryForMode(a, shape, frame, base, expected_events, sealed.register_custody_mode);
    if (present == null or !std.meta.eql(expected, present.?)) return error.UntrustedV5EmptyOpcodeEntry;
}
