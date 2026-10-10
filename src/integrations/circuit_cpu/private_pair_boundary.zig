//! Checked, bounded two-call boundary protocol for the experimental direct-M31 AIR.
//!
//! This module is deliberately not wired into `direct_arithmetic.prove`:
//! its roster and transcript commitments are protocol inputs. An unexported
//! engine experiment proves this roster in memory; source-derived S31 plan and
//! manifest reconstruction plus a sealed verifier remain before release.
//! The live one-call proof format and verifier remain byte-for-byte unchanged.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const chip = @import("repeated_step_chip.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CircuitView = circuit.common.preprocessed.CircuitView;
const DirectCircuit = circuit.common.direct_arithmetic.Circuit;
const PairBoundary = circuit.common.direct_arithmetic.PairBoundary;
const addCanonicalMultiplicity = circuit.common.preprocessed.addCanonicalMultiplicity;

pub const n_calls: usize = 2;
pub const n_lanes: usize = 4;
pub const n_endpoints: usize = n_calls * n_lanes * 2;
pub const relation_id: u32 = 0x53333103;
pub const profile_tag: u64 = 0x5333315041495201;
pub const bridge_log_size: u32 = 4;
pub const bridge_main_width: usize = 8;
pub const bridge_interaction_width: usize = 20;
pub const bridge_n_constraints: usize = 13;
pub const chip_n_constraints: usize = 6;

pub const Side = enum(u1) { input, output };

pub const Endpoint = struct {
    call_id: u32,
    side: Side,
    lane: u32,
    address: u32,
};

pub const Call = struct {
    call_id: u32,
    rounds: u32,
    constant: M31,
    input: [n_lanes]u32,
    output: [n_lanes]u32,
};

pub const Plan = struct {
    calls: [n_calls]Call,

    pub fn boundary(self: Plan) PairBoundary {
        return .{ .calls = .{
            .{ .input = self.calls[0].input, .output = self.calls[0].output },
            .{ .input = self.calls[1].input, .output = self.calls[1].output },
        } };
    }

    /// Construct the actual preprocessed circuit that commits the checked
    /// multiplicities. Only the unexported pair engine accepts this profile;
    /// the S31 source-derived verifier reconstruction is still pending.
    pub fn preprocessed(self: Plan, allocator: std.mem.Allocator, source: CircuitView) !DirectCircuit {
        try self.validate(source, allocator);
        return DirectCircuit.fromCircuitWithPairBoundary(allocator, source, self.boundary());
    }

    /// Every endpoint has exactly one genuine circuit producer. Repeated
    /// addresses are permitted: each occurrence adds one Gate yield, and
    /// all occurrences read the same committed circuit variable.
    pub fn validate(self: Plan, source: CircuitView, allocator: std.mem.Allocator) !void {
        try source.validate();
        try source.validateUniqueProducers(allocator);
        if (source.eq.len != 0 or source.triple_xor.len != 0 or
            source.m31_to_u32.len != 0 or source.blake_g_gate.len != 0)
            return error.UnsupportedDirectCircuit;
        if (source.nQm31OpsRows() < 16 or !std.math.isPowerOfTwo(source.nQm31OpsRows()))
            return error.InvalidDirectTraceShape;
        for (self.calls, 0..) |call, id| {
            if (call.call_id != id) return error.NonCanonicalCallId;
            _ = try chip.validateRounds(call.rounds);
            for (call.input ++ call.output) |address| {
                if (address <= 2 or address >= source.n_vars or address >= core.fields.m31.Modulus)
                    return error.InvalidPairEndpoint;
                if (std.mem.indexOfScalar(u32, source.output, address) != null)
                    return error.PublicPairEndpoint;
                var producers: usize = 0;
                inline for (.{ source.add, source.sub, source.mul, source.pointwise_mul }) |gates| {
                    for (gates) |gate| producers += @intFromBool(gate.out == address);
                }
                for (source.permutation_outputs) |output| producers += @intFromBool(output == address);
                if (producers != 1) return error.InvalidPairProducer;
            }
        }
    }

    /// The exact order used by source-derived manifest generation. A verifier
    /// must reject a missing, extra, duplicated, or reordered endpoint.
    pub fn endpoints(self: Plan) [n_endpoints]Endpoint {
        var result: [n_endpoints]Endpoint = undefined;
        var at: usize = 0;
        for (self.calls) |call| {
            for (call.input, 0..) |address, lane| {
                result[at] = .{ .call_id = call.call_id, .side = .input, .lane = @intCast(lane), .address = address };
                at += 1;
            }
            for (call.output, 0..) |address, lane| {
                result[at] = .{ .call_id = call.call_id, .side = .output, .lane = @intCast(lane), .address = address };
                at += 1;
            }
        }
        return result;
    }

    pub fn checkEndpointManifest(self: Plan, endpoints_from_manifest: []const Endpoint) !void {
        if (endpoints_from_manifest.len != n_endpoints) return error.PairEndpointCount;
        const expected = self.endpoints();
        for (expected, endpoints_from_manifest) |left, right|
            if (!std.meta.eql(left, right)) return error.PairEndpointMismatch;
    }

    /// Mirrors the direct circuit's source-owned multiplicity calculation.
    /// The caller owns the returned counts. This is an integration input, not
    /// an alternative uncommitted multiplicity authority.
    pub fn checkedMultiplicities(self: Plan, allocator: std.mem.Allocator, source: CircuitView) ![]u32 {
        try self.validate(source, allocator);
        const counts = try source.computeUses(allocator);
        errdefer allocator.free(counts);
        try addCanonicalMultiplicity(&counts[0], source.permutationRows());
        for (self.endpoints()) |endpoint|
            try addCanonicalMultiplicity(&counts[endpoint.address], 1);
        return counts;
    }

    pub fn extract(self: Plan, values: []const QM31) ![n_calls]States {
        var result: [n_calls]States = undefined;
        for (self.calls, 0..) |call, id| {
            for (call.input, 0..) |address, lane|
                result[id].input[lane] = try m31At(values, address);
            for (call.output, 0..) |address, lane|
                result[id].output[lane] = try m31At(values, address);
            const computed = try chip.direct(result[id].input, call.constant, call.rounds);
            if (!std.meta.eql(computed, result[id].output)) return error.WrongPairChipClaim;
        }
        return result;
    }
};

pub const States = struct { input: [n_lanes]M31, output: [n_lanes]M31 };

pub const TraceRow = struct {
    call_id: u32,
    step: u32,
    input: [n_lanes]M31,
    output: [n_lanes]M31,
};

/// Check the logical rows before committing a candidate trace. The eventual
/// chip AIR separately enforces these equalities over committed row columns;
/// this local check alone makes no proof soundness claim.
pub fn checkTraceRows(call: Call, states: States, trace_rows: []const TraceRow) !void {
    if (trace_rows.len != call.rounds) return error.PairTraceLength;
    var previous = states.input;
    for (trace_rows, 0..) |row, step| {
        if (row.call_id != call.call_id or row.step != step)
            return error.PairTraceIndex;
        if (!std.meta.eql(row.input, previous)) return error.PairTraceLink;
        for (0..n_lanes) |lane| {
            if (!row.output[lane].eql(row.input[lane].mul(row.input[lane]).add(call.constant)))
                return error.PairTraceTransition;
        }
        previous = row.output;
    }
    if (!std.meta.eql(previous, states.output)) return error.PairTraceClaim;
}

pub fn writeTraceRows(allocator: std.mem.Allocator, call: Call, initial: [n_lanes]M31) ![]TraceRow {
    _ = try chip.validateRounds(call.rounds);
    const trace_rows = try allocator.alloc(TraceRow, call.rounds);
    var state = initial;
    for (trace_rows, 0..) |*row, step| {
        row.* = .{ .call_id = call.call_id, .step = @intCast(step), .input = state, .output = undefined };
        for (&state) |*word| word.* = word.*.mul(word.*).add(call.constant);
        row.output = state;
    }
    return trace_rows;
}

fn m31At(values: []const QM31, address: u32) !M31 {
    if (address >= values.len) return error.InvalidPairEndpoint;
    const limbs = values[address].toM31Array();
    if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero())
        return error.NonCanonicalPairValue;
    return limbs[0];
}

/// One shared Fiat-Shamir `(z, alpha)` is used for the existing six-field
/// Gate relation and both seven-field tagged chips. Fractions with these
/// arities enter the same LogUp sum; relation IDs separate their domains.
pub const Elements = struct {
    z: QM31,
    powers: [7]QM31,

    pub fn init(z: QM31, alpha: QM31) Elements {
        var powers: [7]QM31 = undefined;
        var power = QM31.one();
        for (&powers) |*slot| {
            slot.* = power;
            power = power.mul(alpha);
        }
        return .{ .z = z, .powers = powers };
    }

    pub fn combine(self: Elements, tuple: [7]M31) QM31 {
        var result = QM31.zero();
        for (tuple, self.powers) |word, power|
            result = result.add(power.mulM31(word));
        return result.sub(self.z);
    }

    pub fn combineGate(self: Elements, tuple: [6]M31) QM31 {
        var result = QM31.zero();
        for (tuple, self.powers[0..6]) |word, power|
            result = result.add(power.mulM31(word));
        return result.sub(self.z);
    }

    pub fn combineGateSecure(self: Elements, tuple: [6]QM31) QM31 {
        var result = QM31.zero();
        for (tuple, self.powers[0..6]) |word, power|
            result = result.add(power.mul(word));
        return result.sub(self.z);
    }

    pub fn combineSecure(self: Elements, tuple: [7]QM31) QM31 {
        var result = QM31.zero();
        for (tuple, self.powers) |word, power|
            result = result.add(power.mul(word));
        return result.sub(self.z);
    }
};

pub fn gateTuple(address: u32, value: M31) [6]M31 {
    return .{ M31.fromCanonical(circuit.common.component_list.GATE_RELATION_ID), M31.fromCanonical(address), value, M31.zero(), M31.zero(), M31.zero() };
}

pub fn chipTuple(call_id: u32, step: u32, state: [n_lanes]M31) [7]M31 {
    return .{ M31.fromCanonical(relation_id), M31.fromCanonical(call_id), M31.fromCanonical(step), state[0], state[1], state[2], state[3] };
}

/// Algebraic closure oracle for the exact two-call relation. It does not
/// replace the committed AIR and PCS verifier. It deliberately uses the
/// existing six-coordinate Gate compression and a seven-coordinate chip
/// compression with the same challenges.
pub fn closure(plan: Plan, circuit_values: []const QM31, states: [n_calls]States, elements: Elements) !QM31 {
    var circuit_sum = QM31.zero();
    var bridge_sum = QM31.zero();
    var chip_sum = QM31.zero();
    for (plan.calls, states) |call, state| {
        for (call.input, state.input) |address, value| {
            circuit_sum = circuit_sum.sub(try elements.combineGate(gateTuple(address, try m31At(circuit_values, address))).inv());
            bridge_sum = bridge_sum.add(try elements.combineGate(gateTuple(address, value)).inv());
        }
        for (call.output, state.output) |address, value| {
            circuit_sum = circuit_sum.sub(try elements.combineGate(gateTuple(address, try m31At(circuit_values, address))).inv());
            bridge_sum = bridge_sum.add(try elements.combineGate(gateTuple(address, value)).inv());
        }
        const first = try elements.combine(chipTuple(call.call_id, 0, state.input)).inv();
        const last = try elements.combine(chipTuple(call.call_id, call.rounds, state.output)).inv();
        bridge_sum = bridge_sum.sub(first).add(last);
        var current = state.input;
        for (0..call.rounds) |step| {
            const input = try elements.combine(chipTuple(call.call_id, @intCast(step), current)).inv();
            for (&current) |*word| word.* = word.*.mul(word.*).add(call.constant);
            const output = try elements.combine(chipTuple(call.call_id, @intCast(step + 1), current)).inv();
            chip_sum = chip_sum.add(input).sub(output);
        }
    }
    return circuit_sum.add(bridge_sum).add(chip_sum);
}

pub const Component = enum(u8) { circuit, chip_0, chip_1, bridge_0, bridge_1 };
pub const roster = [_]Component{ .circuit, .chip_0, .chip_1, .bridge_0, .bridge_1 };
pub const circuit_main_width = circuit.witness.direct_arithmetic.main_width;
pub const circuit_interaction_width = circuit.witness.direct_arithmetic.interaction_width;
pub const main_width = circuit_main_width + n_calls * (chip.main_width + bridge_main_width);
pub const interaction_width = circuit_interaction_width + n_calls * (chip.interaction_width + bridge_interaction_width);

comptime {
    std.debug.assert(main_width == 46);
    std.debug.assert(interaction_width == 64);
}

pub const ComponentSpec = struct {
    role: Component,
    log_size: u32,
    main_offset: usize,
    main_columns: usize,
    interaction_offset: usize,
    interaction_columns: usize,
    constraint_offset: usize,
    constraint_count: usize,
};

pub fn expectedSpecs(plan: Plan, circuit_log: u32, circuit_constraints: usize) ![roster.len]ComponentSpec {
    const log0 = try chip.validateRounds(plan.calls[0].rounds);
    const log1 = try chip.validateRounds(plan.calls[1].rounds);
    return .{
        .{ .role = .circuit, .log_size = circuit_log, .main_offset = 0, .main_columns = circuit_main_width, .interaction_offset = 0, .interaction_columns = circuit_interaction_width, .constraint_offset = 0, .constraint_count = circuit_constraints },
        .{ .role = .chip_0, .log_size = log0, .main_offset = circuit_main_width, .main_columns = chip.main_width, .interaction_offset = circuit_interaction_width, .interaction_columns = chip.interaction_width, .constraint_offset = circuit_constraints, .constraint_count = chip_n_constraints },
        .{ .role = .chip_1, .log_size = log1, .main_offset = circuit_main_width + chip.main_width, .main_columns = chip.main_width, .interaction_offset = circuit_interaction_width + chip.interaction_width, .interaction_columns = chip.interaction_width, .constraint_offset = circuit_constraints + chip_n_constraints, .constraint_count = chip_n_constraints },
        .{ .role = .bridge_0, .log_size = bridge_log_size, .main_offset = circuit_main_width + 2 * chip.main_width, .main_columns = bridge_main_width, .interaction_offset = circuit_interaction_width + 2 * chip.interaction_width, .interaction_columns = bridge_interaction_width, .constraint_offset = circuit_constraints + 2 * chip_n_constraints, .constraint_count = bridge_n_constraints },
        .{ .role = .bridge_1, .log_size = bridge_log_size, .main_offset = circuit_main_width + 2 * chip.main_width + bridge_main_width, .main_columns = bridge_main_width, .interaction_offset = circuit_interaction_width + 2 * chip.interaction_width + bridge_interaction_width, .interaction_columns = bridge_interaction_width, .constraint_offset = circuit_constraints + 2 * chip_n_constraints + bridge_n_constraints, .constraint_count = bridge_n_constraints },
    };
}

pub fn checkSpecs(expected: [roster.len]ComponentSpec, actual: []const ComponentSpec) !void {
    if (actual.len != roster.len) return error.InvalidPairRoster;
    for (expected, actual) |wanted, found|
        if (!std.meta.eql(wanted, found)) return error.InvalidPairRoster;
}

pub fn checkRoster(actual: []const Component) !void {
    if (actual.len != roster.len) return error.InvalidPairRoster;
    for (roster, actual) |expected, found|
        if (expected != found) return error.InvalidPairRoster;
}

pub const TranscriptEvent = enum {
    profile,
    preprocessed_commitment,
    statement,
    main_commitment,
    lookup_challenge,
    claimed_sums,
    interaction_commitment,
};

pub const transcript_order = [_]TranscriptEvent{
    .profile,          .preprocessed_commitment, .statement,              .main_commitment,
    .lookup_challenge, .claimed_sums,            .interaction_commitment,
};

/// A small integration guard for the pair prover and verifier. The profile
/// and manifest digest must be mixed before any commitment; the common
/// LogUp challenge follows all main commitments and precedes all claims.
pub const TranscriptOrder = struct {
    next: usize = 0,

    pub fn accept(self: *TranscriptOrder, event: TranscriptEvent) !void {
        if (self.next == transcript_order.len or transcript_order[self.next] != event)
            return error.PairTranscriptOrder;
        self.next += 1;
    }

    pub fn finish(self: TranscriptOrder) !void {
        if (self.next != transcript_order.len) return error.IncompletePairTranscript;
    }
};

/// S31's generated manifest digest is committed before the first PCS tree.
/// Source identity remains separately available to the key and verifier.
pub fn effectiveDigest(source_digest: [32]u8, manifest_digest: [32]u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("S31-DIRECT-CHIP-PAIR-MANIFEST-TRANSCRIPT-V3\x00");
    hash.update(&source_digest);
    hash.update(&manifest_digest);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

pub fn mixProfile(channel: anytype, digest: [32]u8, plan: Plan) void {
    channel.mixU64(profile_tag);
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i|
        word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
    for (plan.calls) |call| {
        channel.mixU32s(&.{ call.call_id, call.rounds, call.constant.toU32() });
        channel.mixU32s(&(call.input ++ call.output));
    }
}

test "two-call plan checks coherent repeated addresses and canonical Gate counts" {
    const allocator = std.testing.allocator;
    const gates = [_]circuit.builder.circuit.BinaryGate{
        .{ .in0 = 0, .in1 = 1, .out = 3 },  .{ .in0 = 0, .in1 = 1, .out = 4 },
        .{ .in0 = 0, .in1 = 1, .out = 5 },  .{ .in0 = 0, .in1 = 1, .out = 6 },
        .{ .in0 = 0, .in1 = 1, .out = 7 },  .{ .in0 = 0, .in1 = 1, .out = 8 },
        .{ .in0 = 0, .in1 = 1, .out = 9 },  .{ .in0 = 0, .in1 = 1, .out = 10 },
        .{ .in0 = 0, .in1 = 1, .out = 11 }, .{ .in0 = 0, .in1 = 1, .out = 12 },
        .{ .in0 = 0, .in1 = 1, .out = 13 }, .{ .in0 = 0, .in1 = 1, .out = 14 },
        .{ .in0 = 0, .in1 = 1, .out = 15 }, .{ .in0 = 0, .in1 = 1, .out = 16 },
        .{ .in0 = 0, .in1 = 1, .out = 17 }, .{ .in0 = 0, .in1 = 1, .out = 18 },
    };
    const source = CircuitView{ .n_vars = 20, .add = &gates, .output = &.{19} };
    const plan = Plan{ .calls = .{
        .{ .call_id = 0, .rounds = 16, .constant = M31.fromCanonical(1), .input = .{ 3, 4, 5, 6 }, .output = .{ 7, 8, 9, 10 } },
        .{ .call_id = 1, .rounds = 16, .constant = M31.fromCanonical(2), .input = .{ 3, 4, 11, 12 }, .output = .{ 13, 14, 15, 16 } },
    } };
    const counts = try plan.checkedMultiplicities(allocator, source);
    defer allocator.free(counts);
    try std.testing.expectEqual(@as(u32, 2), counts[3]);
    try std.testing.expectEqual(@as(u32, 2), counts[4]);
    try std.testing.expectEqual(@as(u32, 1), counts[5]);
    var pp = try plan.preprocessed(allocator, source);
    defer pp.deinit(allocator);
    try std.testing.expect(std.meta.eql(plan.boundary(), pp.private_pair_boundary.?));
    const mults = pp.columnValues("qm31_ops_mults") orelse return error.MissingDirectColumn;
    try std.testing.expectEqual(M31.fromCanonical(2), mults[0]);
    try std.testing.expectEqual(M31.fromCanonical(2), mults[1]);
    try std.testing.expectEqual(M31.fromCanonical(1), mults[2]);
    var repeated = plan;
    repeated.calls[0].input[1] = 3;
    const repeated_counts = try repeated.checkedMultiplicities(allocator, source);
    defer allocator.free(repeated_counts);
    try std.testing.expectEqual(@as(u32, 3), repeated_counts[3]);
    var repeated_pp = try repeated.preprocessed(allocator, source);
    defer repeated_pp.deinit(allocator);
    const repeated_mults = repeated_pp.columnValues("qm31_ops_mults") orelse return error.MissingDirectColumn;
    try std.testing.expectEqual(M31.fromCanonical(3), repeated_mults[0]);
    var swapped = plan;
    swapped.calls[0].call_id = 1;
    try std.testing.expectError(error.NonCanonicalCallId, swapped.validate(source, allocator));
    var public_endpoint = plan;
    public_endpoint.calls[0].input[0] = 19;
    try std.testing.expectError(error.PublicPairEndpoint, public_endpoint.validate(source, allocator));
    var missing_producer = plan;
    missing_producer.calls[0].input[0] = 2;
    try std.testing.expectError(error.InvalidPairEndpoint, missing_producer.validate(source, allocator));

    // The low-level public constructor must reject a duplicate producer
    // even when its address is outside all chip endpoints.
    var duplicate_gates = gates;
    duplicate_gates[15].out = 17;
    const duplicate_source = CircuitView{ .n_vars = 20, .add = &duplicate_gates, .output = &.{19} };
    try std.testing.expectError(error.DuplicateProducerAddress, plan.validate(duplicate_source, allocator));
    try std.testing.expectError(error.DuplicateProducerAddress, DirectCircuit.fromCircuitWithPairBoundary(
        allocator,
        duplicate_source,
        plan.boundary(),
    ));
}

test "pair endpoint manifest rejects missing, extra, swap and duplicate" {
    const plan = Plan{ .calls = .{
        .{ .call_id = 0, .rounds = 16, .constant = M31.one(), .input = .{ 3, 4, 5, 6 }, .output = .{ 7, 8, 9, 10 } },
        .{ .call_id = 1, .rounds = 16, .constant = M31.one(), .input = .{ 3, 4, 11, 12 }, .output = .{ 13, 14, 15, 16 } },
    } };
    const expected = plan.endpoints();
    try plan.checkEndpointManifest(&expected);
    try std.testing.expectError(error.PairEndpointCount, plan.checkEndpointManifest(expected[0 .. n_endpoints - 1]));
    const extra = expected ++ [_]Endpoint{expected[0]};
    try std.testing.expectError(error.PairEndpointCount, plan.checkEndpointManifest(&extra));
    var swapped = expected;
    swapped[0].call_id = 1;
    try std.testing.expectError(error.PairEndpointMismatch, plan.checkEndpointManifest(&swapped));
    var duplicated = expected;
    duplicated[1] = duplicated[0];
    try std.testing.expectError(error.PairEndpointMismatch, plan.checkEndpointManifest(&duplicated));
}

test "tagged pair tuples, wrong claims and transcript order" {
    const z = QM31.fromU32Unchecked(17, 2, 3, 5);
    const alpha = QM31.fromU32Unchecked(11, 7, 13, 19);
    const elements = Elements.init(z, alpha);
    const state = [4]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    try std.testing.expect(!elements.combine(chipTuple(0, 0, state)).eql(elements.combine(chipTuple(1, 0, state))));
    const first = try chip.direct(state, M31.fromCanonical(3), 16);
    const second = try chip.direct(state, M31.fromCanonical(4), 16);
    const plan = Plan{ .calls = .{
        .{ .call_id = 0, .rounds = 16, .constant = M31.fromCanonical(3), .input = .{ 3, 4, 5, 6 }, .output = .{ 7, 8, 9, 10 } },
        .{ .call_id = 1, .rounds = 16, .constant = M31.fromCanonical(4), .input = .{ 3, 4, 5, 6 }, .output = .{ 11, 12, 13, 14 } },
    } };
    const states = [2]States{ .{ .input = state, .output = first }, .{ .input = state, .output = second } };
    var circuit_values = [_]QM31{QM31.zero()} ** 15;
    for (state, 0..) |word, lane| circuit_values[3 + lane] = QM31.fromBase(word);
    for (first, 0..) |word, lane| circuit_values[7 + lane] = QM31.fromBase(word);
    for (second, 0..) |word, lane| circuit_values[11 + lane] = QM31.fromBase(word);
    try std.testing.expect(std.meta.eql(states, try plan.extract(&circuit_values)));
    try std.testing.expect((try closure(plan, &circuit_values, states, elements)).isZero());
    var wrong = states;
    wrong[1].output[0] = wrong[1].output[0].add(M31.one());
    try std.testing.expect(!(try closure(plan, &circuit_values, wrong, elements)).isZero());
    wrong = states;
    wrong[1].input[0] = wrong[1].input[0].add(M31.one());
    try std.testing.expect(!(try closure(plan, &circuit_values, wrong, elements)).isZero());
    circuit_values[3] = QM31.fromBase(state[0].add(M31.one()));
    try std.testing.expectError(error.WrongPairChipClaim, plan.extract(&circuit_values));
    try std.testing.expect(!(try closure(plan, &circuit_values, states, elements)).isZero());
    const a = [_]u8{1} ** 32;
    const b = [_]u8{2} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &effectiveDigest(a, b), &effectiveDigest(b, a)));
    try std.testing.expectError(error.InvalidPairRoster, checkRoster(&.{ .circuit, .chip_1, .chip_0, .bridge_0, .bridge_1 }));
    try std.testing.expectError(error.InvalidPairRoster, checkRoster(&.{ .circuit, .chip_0, .chip_1, .bridge_0 }));
    const specs = try expectedSpecs(plan, 4, 11);
    try checkSpecs(specs, &specs);
    try std.testing.expectEqual(@as(usize, 46), specs[4].main_offset + specs[4].main_columns);
    try std.testing.expectEqual(@as(usize, 64), specs[4].interaction_offset + specs[4].interaction_columns);
    try std.testing.expectEqual(@as(usize, 11 + 38), specs[4].constraint_offset + specs[4].constraint_count);
    var reordered = specs;
    std.mem.swap(ComponentSpec, &reordered[1], &reordered[2]);
    try std.testing.expectError(error.InvalidPairRoster, checkSpecs(specs, &reordered));

    var ordering = TranscriptOrder{};
    try ordering.accept(.profile);
    try std.testing.expectError(error.PairTranscriptOrder, ordering.accept(.main_commitment));
    try ordering.accept(.preprocessed_commitment);
    try ordering.accept(.statement);
    try ordering.accept(.main_commitment);
    try std.testing.expectError(error.PairTranscriptOrder, ordering.accept(.claimed_sums));
    try ordering.accept(.lookup_challenge);
    try ordering.accept(.claimed_sums);
    try std.testing.expectError(error.IncompletePairTranscript, ordering.finish());
    try ordering.accept(.interaction_commitment);
    try ordering.finish();
}

test "pair trace rows reject swapped calls, missing rows and broken links" {
    const allocator = std.testing.allocator;
    const call = Call{
        .call_id = 0,
        .rounds = 16,
        .constant = M31.fromCanonical(7),
        .input = .{ 3, 4, 5, 6 },
        .output = .{ 7, 8, 9, 10 },
    };
    const initial = [4]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) };
    const final = try chip.direct(initial, call.constant, call.rounds);
    const states = States{ .input = initial, .output = final };
    const trace_rows = try writeTraceRows(allocator, call, initial);
    defer allocator.free(trace_rows);
    try checkTraceRows(call, states, trace_rows);
    try std.testing.expectError(error.PairTraceLength, checkTraceRows(call, states, trace_rows[0..15]));
    trace_rows[0].call_id = 1;
    try std.testing.expectError(error.PairTraceIndex, checkTraceRows(call, states, trace_rows));
    trace_rows[0].call_id = 0;
    trace_rows[7].input[0] = trace_rows[7].input[0].add(M31.one());
    try std.testing.expectError(error.PairTraceLink, checkTraceRows(call, states, trace_rows));
    trace_rows[7].input[0] = trace_rows[6].output[0];
    trace_rows[15].output[0] = trace_rows[15].output[0].add(M31.one());
    try std.testing.expectError(error.PairTraceTransition, checkTraceRows(call, states, trace_rows));
}
