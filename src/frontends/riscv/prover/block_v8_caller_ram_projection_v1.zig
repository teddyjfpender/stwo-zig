//! Experimental original caller RAM projection, with the native MemoryAccess
//! sign and clock/address semantics. It has one cyclic secure column per
//! authenticated descriptor and no per-access WORD or byte-copy sidecar.
//! This is algebra and finite planning only: no production prover selects it.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const R = @import("block_v7_memory_relations_v1.zig");
const External = @import("block_execution_external_trace_v2.zig");
const Access = @import("block_execution_access_bridge_v2.zig");
const Bridge = @import("block_execution_external_access_bridge_v2.zig");
const Schedule = @import("block_v7_caller_active_schedule_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const Descriptor = External.Descriptor;
pub const Plan = struct {
    a: std.mem.Allocator,
    descriptors: []Descriptor,
    logical_ram_accesses: u64,
    digest: [32]u8,
    pub fn derive(a: std.mem.Allocator, statement: *const Profile.admission.Statement, steps: u32, frame: @import("../air/block/memory_event.zig").Frame) !Plan {
        if (frame.clock_frame != .leaf_local or frame.global_first_cycle == 0 or frame.cycle_count != steps) return error.InvalidCallerEndpointFrame;
        var schedule = try Schedule.derive(a, statement, steps, frame);
        defer schedule.deinit();
        try External.requireRwDescriptors(schedule.memory, 1);
        const descriptors = try a.dupe(Descriptor, schedule.memory);
        errdefer a.free(descriptors);
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42384352, VERSION, steps, @intCast(descriptors.len) });
        channel.mixU64(schedule.rw_events);
        for (descriptors) |descriptor| mixDescriptor(&channel, descriptor);
        return .{ .a = a, .descriptors = descriptors, .logical_ram_accesses = schedule.rw_events, .digest = channel.digestBytes() };
    }
    pub fn deinit(self: *Plan) void {
        self.a.free(self.descriptors);
        self.* = undefined;
    }
    /// Only after independent original caller admission. Neither a digest nor
    /// a private descriptor array is allowed to choose the admitted inventory.
    pub fn require(self: *const Plan, statement: *const Profile.admission.Statement, steps: u32, frame: @import("../air/block/memory_event.zig").Frame) !void {
        var expected = try derive(self.a, statement, steps, frame);
        defer expected.deinit();
        if (self.logical_ram_accesses != expected.logical_ram_accesses or !std.meta.eql(self.digest, expected.digest) or self.descriptors.len != expected.descriptors.len) return error.UntrustedCallerEndpointPlan;
        for (self.descriptors, expected.descriptors) |got, want| if (!std.meta.eql(got, want)) return error.UntrustedCallerEndpointPlan;
    }
};
fn mixDescriptor(channel: anytype, descriptor: Descriptor) void {
    channel.mixU32s(&.{ @intFromEnum(descriptor.kind), @intCast(descriptor.slot), descriptor.log_size, @intCast(descriptor.fixed_offset), @intCast(descriptor.main_offset), descriptor.x0_local_custody_version, @intFromEnum(descriptor.frame.clock_frame), descriptor.frame.cycle_count });
    channel.mixU64(descriptor.frame.global_first_cycle);
}
pub fn nativeRelation(prefix: *const @import("../recursion/air/universal_challenges.zig").UniversalRelations) !R.Relation(Q, 7) {
    try prefix.validate();
    const relation = prefix.get(.memory_access);
    if (relation.arity != 7) return error.InvalidCallerEndpointRelation;
    return .{ .z = relation.z, .powers = relation.alpha_powers[0..7].* };
}
pub fn Point(comptime S: type) type {
    return struct {
        term: R.Term(S),
        pair_constraints: [3]S,
    };
}
/// Use only with a pair extracted from the authenticated caller's opened
/// columns. Inactive OODS rows must retain this algebraic formula; never
/// branch on the enabler or replace their tuple with a host-side zero pair.
pub fn fromPair(comptime S: type, pair: Access.Pair(S), relation: R.Relation(S, 7)) !Point(S) {
    if (pair.address_unit != .byte_address) return error.UnsupportedCallerEndpointAddressUnit;
    const previous_clock = pair.consume_clock orelse return error.MissingCallerEndpointClock;
    const before = .{ pair.space, pair.source_address, previous_clock } ++ pair.before;
    const after = .{ pair.space, pair.source_address, pair.local_clock } ++ pair.after;
    return .{ .term = .{ .left = relation.combineSecure(before), .right = relation.combineSecure(after), .wl = pair.active.neg(), .wr = pair.active }, .pair_constraints = pair.pair_residuals };
}
pub fn sha(comptime S: type, caller: []const S, active: S, slot: usize, relation: R.Relation(S, 7)) !Point(S) {
    if (slot < 2 or slot >= Bridge.SHA_ACCESS_COUNT) return error.InvalidCallerEndpointSlot;
    return fromPair(S, try Bridge.shaPair(S, caller, active, slot), relation);
}
pub fn signer(comptime S: type, caller: []const S, slot: usize, relation: R.Relation(S, 7)) !Point(S) {
    if (slot == 0 or slot >= Bridge.SIGNER_ACCESS_COUNT) return error.InvalidCallerEndpointSlot;
    return fromPair(S, try Bridge.signerPair(S, caller, slot), relation);
}
/// Keccak's memory values come from its state bit columns at current/+27.
/// Owner.pair's zero-state table helper MUST NOT be used for RAM projections.
pub fn keccak(comptime S: type, caller: []const S, input_word_bits: [32]S, output_word_bits: [32]S, slot: usize, relation: R.Relation(S, 7)) !Point(S) {
    if (slot == 0 or slot >= Bridge.KECCAK_ACCESS_COUNT) return error.InvalidCallerEndpointSlot;
    return fromPair(S, try Bridge.keccakPairFromWordBits(S, caller, input_word_bits, output_word_bits, slot), relation);
}
/// One independent physical claim; absorb it before its interaction commit.
/// Native arithmetic already proves bounds/values. This recurrence binds the
/// projection to precisely those opened tuples, not to producer-built rows.
pub fn equations(comptime S: type, point: Point(S), current: [4]S, previous: [4]S, normalized: S) [4]S {
    return point.pair_constraints ++ R.interactionConstraints(S, 1, .{point.term}, current, previous, .{normalized});
}
