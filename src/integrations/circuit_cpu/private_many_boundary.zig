//! Source-owned, bounded V4 tagged circuit-to-chip boundary geometry.
//!
//! This module does not admit proof bytes. The source compiler supplies its
//! ordered calls, and a sealed verifier must reconstruct the same Plan.
//! Keeping the V4 plan separate preserves every V3 pair proof identity.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const pair = @import("private_pair_boundary.zig");
const repeated = @import("repeated_step_chip.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CircuitView = circuit.common.preprocessed.CircuitView;
const DirectCircuit = circuit.common.direct_arithmetic.Circuit;
const ManyBoundary = circuit.common.direct_arithmetic.ManyBoundary;

pub const max_calls = ManyBoundary.max_calls;
pub const max_components = 1 + 2 * max_calls;
pub const n_calls = max_calls; // V4 AIR call-ID bound, distinct from V3's 2.
pub const n_lanes = pair.n_lanes;
pub const relation_id = pair.relation_id;
pub const bridge_log_size = pair.bridge_log_size;
pub const bridge_main_width = pair.bridge_main_width;
pub const bridge_interaction_width = pair.bridge_interaction_width;
pub const bridge_n_constraints = pair.bridge_n_constraints;
pub const chip_n_constraints = pair.chip_n_constraints;
pub const profile_tag: u64 = 0x5333314d414e5901; // S31MANY\x01.
pub const Call = pair.Call;
pub const States = pair.States;
pub const Elements = pair.Elements;
pub const gateTuple = pair.gateTuple;
pub const chipTuple = pair.chipTuple;
pub const circuit_main_width = circuit.witness.direct_arithmetic.main_width;
pub const circuit_interaction_width = circuit.witness.direct_arithmetic.interaction_width;

const empty_call: Call = .{
    .call_id = 0,
    .rounds = 0,
    .constant = M31.zero(),
    .input = .{ 0, 0, 0, 0 },
    .output = .{ 0, 0, 0, 0 },
};

pub const Plan = struct {
    calls: [max_calls]Call = [_]Call{empty_call} ** max_calls,
    count: u8 = 0,

    pub fn callSlice(self: *const Plan) []const Call {
        return self.calls[0..self.count];
    }

    pub fn boundary(self: Plan) ManyBoundary {
        var result: ManyBoundary = .{ .count = self.count };
        for (self.callSlice(), 0..) |call, id|
            result.calls[id] = .{ .input = call.input, .output = call.output };
        return result;
    }

    pub fn validate(self: Plan, source: CircuitView, allocator: std.mem.Allocator) !void {
        if (self.count == 0 or self.count > max_calls) return error.InvalidManyCallCount;
        try source.validate();
        try source.validateUniqueProducers(allocator);
        if (source.eq.len != 0 or source.triple_xor.len != 0 or
            source.m31_to_u32.len != 0 or source.blake_g_gate.len != 0)
            return error.UnsupportedDirectCircuit;
        const rows = source.nQm31OpsRows();
        if (rows < 16 or rows > (1 << 16) or !std.math.isPowerOfTwo(rows))
            return error.InvalidManyCircuitRows;
        var total_rounds: u32 = 0;
        for (self.callSlice(), 0..) |call, id| {
            if (call.call_id != id) return error.NonCanonicalManyCallId;
            _ = try repeated.validateRounds(call.rounds);
            total_rounds = std.math.add(u32, total_rounds, call.rounds) catch
                return error.TooManyChipRounds;
            if (total_rounds > (1 << 18)) return error.TooManyChipRounds;
        }
        try self.boundary().validate(source);
        const committed_cells = @as(u64, 20) * @as(u64, @intCast(rows)) +
            @as(u64, 17) * total_rounds + @as(u64, 28) * 16 * self.count;
        if (committed_cells > 6_000_000) return error.TooManyTraceCells;
    }

    pub fn preprocessed(self: Plan, allocator: std.mem.Allocator, source: CircuitView) !DirectCircuit {
        try self.validate(source, allocator);
        return DirectCircuit.fromCircuitWithManyBoundary(allocator, source, self.boundary());
    }

    pub fn extract(self: Plan, values: []const QM31) ![max_calls]States {
        if (self.count == 0 or self.count > max_calls) return error.InvalidManyCallCount;
        var result: [max_calls]States = undefined;
        for (self.callSlice(), 0..) |call, id| {
            for (call.input, 0..) |address, lane| result[id].input[lane] = try m31At(values, address);
            for (call.output, 0..) |address, lane| result[id].output[lane] = try m31At(values, address);
            const computed = try repeated.direct(result[id].input, call.constant, call.rounds);
            if (!std.meta.eql(computed, result[id].output)) return error.WrongManyChipClaim;
        }
        return result;
    }
};

fn m31At(values: []const QM31, address: u32) !M31 {
    if (address >= values.len) return error.InvalidManyEndpoint;
    const limbs = values[address].toM31Array();
    if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero())
        return error.NonCanonicalManyValue;
    return limbs[0];
}

pub const ComponentKind = enum(u8) { circuit, chip, bridge };
pub const ComponentSpec = struct {
    kind: ComponentKind,
    call_id: ?u32,
    log_size: u32,
    main_offset: usize,
    main_columns: usize,
    interaction_offset: usize,
    interaction_columns: usize,
    constraint_offset: usize,
    constraint_count: usize,
};

pub const Roster = struct {
    entries: [max_components]ComponentSpec = undefined,
    count: usize,
    main_width: usize,
    interaction_width: usize,
    constraint_count: usize,

    pub fn slice(self: *const Roster) []const ComponentSpec {
        return self.entries[0..self.count];
    }
};

/// Circuit, all chips, then all bridges. Every offset is a prefix sum of
/// selected component widths/constraints; the verifier must instantiate the
/// same AIR handles and check their live geometry against this roster.
pub fn expectedRoster(plan: Plan, circuit_log: u32, circuit_constraints: usize) !Roster {
    if (plan.count == 0 or plan.count > max_calls) return error.InvalidManyCallCount;
    var result: Roster = .{
        .count = 1 + 2 * @as(usize, plan.count),
        .main_width = circuit_main_width + 17 * @as(usize, plan.count),
        .interaction_width = circuit_interaction_width + 28 * @as(usize, plan.count),
        .constraint_count = circuit_constraints + 19 * @as(usize, plan.count),
    };
    var main_offset: usize = 0;
    var interaction_offset: usize = 0;
    var constraint_offset: usize = 0;
    result.entries[0] = .{
        .kind = .circuit,
        .call_id = null,
        .log_size = circuit_log,
        .main_offset = main_offset,
        .main_columns = circuit_main_width,
        .interaction_offset = interaction_offset,
        .interaction_columns = circuit_interaction_width,
        .constraint_offset = constraint_offset,
        .constraint_count = circuit_constraints,
    };
    main_offset += circuit_main_width;
    interaction_offset += circuit_interaction_width;
    constraint_offset += circuit_constraints;
    for (plan.callSlice(), 0..) |call, id| {
        if (call.call_id != id) return error.NonCanonicalManyCallId;
        const log_size = try repeated.validateRounds(call.rounds);
        result.entries[1 + id] = .{
            .kind = .chip,
            .call_id = call.call_id,
            .log_size = log_size,
            .main_offset = main_offset,
            .main_columns = 9,
            .interaction_offset = interaction_offset,
            .interaction_columns = 8,
            .constraint_offset = constraint_offset,
            .constraint_count = chip_n_constraints,
        };
        main_offset += 9;
        interaction_offset += 8;
        constraint_offset += chip_n_constraints;
    }
    for (plan.callSlice(), 0..) |call, id| {
        result.entries[1 + @as(usize, plan.count) + id] = .{
            .kind = .bridge,
            .call_id = call.call_id,
            .log_size = bridge_log_size,
            .main_offset = main_offset,
            .main_columns = bridge_main_width,
            .interaction_offset = interaction_offset,
            .interaction_columns = bridge_interaction_width,
            .constraint_offset = constraint_offset,
            .constraint_count = bridge_n_constraints,
        };
        main_offset += bridge_main_width;
        interaction_offset += bridge_interaction_width;
        constraint_offset += bridge_n_constraints;
    }
    if (main_offset != result.main_width or interaction_offset != result.interaction_width or
        constraint_offset != result.constraint_count) return error.InvalidManyRoster;
    return result;
}

pub fn effectiveDigest(source_digest: [32]u8, manifest_digest: [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("S31-DIRECT-CHIP-MANY-MANIFEST-TRANSCRIPT-V4\x00");
    hash.update(&source_digest);
    hash.update(&manifest_digest);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

pub fn mixProfile(channel: anytype, digest: [32]u8, plan: Plan) void {
    channel.mixU64(profile_tag);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, id| word.* = std.mem.readInt(u32, digest[4 * id ..][0..4], .little);
    channel.mixU32s(&words);
    channel.mixU32s(&.{plan.count});
    for (plan.callSlice()) |call| {
        channel.mixU32s(&.{ call.call_id, call.rounds, call.constant.toU32() });
        channel.mixU32s(&(call.input ++ call.output));
    }
}

pub fn identityHash(effective_digest: [32]u8, preprocessed_root: [32]u8, circuit_log: u32, blowup: u32, plan: Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("S31-DIRECT-M31-CHIP-MANY-V1\x00");
    hash.update(&effective_digest);
    hash.update(&preprocessed_root);
    var word: [4]u8 = undefined;
    for ([_]u32{ circuit_log, blowup, plan.count }) |value| {
        std.mem.writeInt(u32, &word, value, .little);
        hash.update(&word);
    }
    for (plan.callSlice()) |call| {
        for ([_]u32{ call.call_id, call.rounds, call.constant.toU32() } ++ call.input ++ call.output) |value| {
            std.mem.writeInt(u32, &word, value, .little);
            hash.update(&word);
        }
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

/// Expected V4 transcript phases. The experimental in-memory native V4
/// scheduler checks these events while proving and verifying. This tracks
/// control-flow order; transcript binding still depends on the actual mixes.
pub const TranscriptEvent = enum {
    profile,
    channel_salt,
    fri_config,
    preprocessed_commitment,
    circuit_identity,
    public_statement,
    main_commitment,
    interaction_pow_nonce,
    lookup_challenge,
    claimed_sums,
    interaction_commitment,
    pcs_proof,
};

pub const transcript_order = [_]TranscriptEvent{
    .profile,
    .channel_salt,
    .fri_config,
    .preprocessed_commitment,
    .circuit_identity,
    .public_statement,
    .main_commitment,
    .interaction_pow_nonce,
    .lookup_challenge,
    .claimed_sums,
    .interaction_commitment,
    .pcs_proof,
};

pub const TranscriptOrder = struct {
    next: usize = 0,

    pub fn accept(self: *TranscriptOrder, event: TranscriptEvent) !void {
        if (self.next == transcript_order.len or transcript_order[self.next] != event)
            return error.ManyTranscriptOrder;
        self.next += 1;
    }

    pub fn finish(self: TranscriptOrder) !void {
        if (self.next != transcript_order.len) return error.IncompleteManyTranscript;
    }
};

test "V4 three-call boundary counts repeated addresses and has prefix-sum roster" {
    const allocator = std.testing.allocator;
    var gates: [32]circuit.builder.circuit.BinaryGate = undefined;
    for (&gates, 0..) |*gate, id|
        gate.* = .{ .in0 = 0, .in1 = 1, .out = @intCast(3 + id) };
    const source = CircuitView{ .n_vars = 36, .add = &gates, .output = &.{35} };
    var plan: Plan = .{ .count = 3 };
    plan.calls[0] = .{ .call_id = 0, .rounds = 16, .constant = M31.fromCanonical(3), .input = .{ 3, 4, 5, 6 }, .output = .{ 7, 8, 9, 10 } };
    plan.calls[1] = .{ .call_id = 1, .rounds = 32, .constant = M31.fromCanonical(5), .input = .{ 7, 8, 9, 10 }, .output = .{ 11, 12, 13, 14 } };
    plan.calls[2] = .{ .call_id = 2, .rounds = 16, .constant = M31.fromCanonical(7), .input = .{ 3, 4, 5, 6 }, .output = .{ 15, 16, 17, 18 } };
    var pp = try plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    const counts = pp.columnValues("qm31_ops_mults") orelse return error.MissingDirectColumn;
    try std.testing.expectEqual(M31.fromCanonical(2), counts[0]); // Address 3, two inputs.
    try std.testing.expectEqual(M31.fromCanonical(2), counts[4]); // Address 7, output and input.
    const roster = try expectedRoster(plan, 5, 11);
    try std.testing.expectEqual(@as(usize, 7), roster.count);
    try std.testing.expectEqual(@as(usize, 63), roster.main_width);
    try std.testing.expectEqual(@as(usize, 92), roster.interaction_width);
    try std.testing.expectEqual(@as(usize, 68), roster.constraint_count);
    try std.testing.expectEqual(@as(usize, 39), roster.entries[4].main_offset);
    try std.testing.expectEqual(@as(usize, 32), roster.entries[4].interaction_offset);
    try std.testing.expectEqual(@as(usize, 29), roster.entries[4].constraint_offset);
    var swapped = plan;
    swapped.calls[2].call_id = 1;
    try std.testing.expectError(error.NonCanonicalManyCallId, swapped.validate(source, allocator));
    var exposed = plan;
    exposed.calls[1].output[0] = 35;
    try std.testing.expectError(error.InvalidManyBoundary, exposed.validate(source, allocator));
}

test "V4 transcript schedule names every native pair phase in order" {
    var sequence: TranscriptOrder = .{};
    try std.testing.expectError(error.ManyTranscriptOrder, sequence.accept(.preprocessed_commitment));
    for (transcript_order) |event| try sequence.accept(event);
    try sequence.finish();
    try std.testing.expectError(error.ManyTranscriptOrder, sequence.accept(.pcs_proof));
    var truncated: TranscriptOrder = .{};
    try truncated.accept(.profile);
    try std.testing.expectError(error.IncompleteManyTranscript, truncated.finish());
}
