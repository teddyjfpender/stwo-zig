//! Conditional fixed-key candidate for direct-V8 transcript shared arithmetic.
//!
//! This is ONLY the proposed direct segment-transcript wrapper, where the
//! arithmetic lanes are VM AIR, statement, claim, LogUp, PCS, FRI, VM binary.
//! It does not describe the currently executing q193 SegmentV2 cohort, which
//! uses the native-public-sum lane instead of the three transcript lanes.
//!
//! The VM AIR graph is not independently reconstructed by the current direct
//! leaf verifier: preparation obtains it from the captured leaf. Therefore a
//! verifier MUST select `VmPin` and its graph before reading that leaf. This
//! module refuses an absent or mismatched pin and remains inactive until the
//! versioned outer verifier key owns that pin and the complete row IDs.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const fixed = @import("segment_leaf_public_graph_fixed_v8.zig");
const public_graphs = @import("vm_public_semantics_circuit.zig");
const statement = @import("statement_semantics_circuit.zig");
const statement_contract = @import("segment_statement_outer_source_contract.zig");
const public_source = @import("segment_public_outer_source.zig");
const graph_mod = @import("air/composition_circuit.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");
const pcs = @import("air/pcs_deep_circuit.zig");
const fri = @import("air/fri_verifier_circuit.zig");
const mul = @import("air/qm31_mul_full_witness.zig");
const inv = @import("air/qm31_inv_witness.zig");
const lin = @import("air/linear_ops_witness.zig");
const mul_air = @import("air/qm31_mul_full.zig");
const inv_air = @import("air/qm31_inv.zig");
const lin_air = @import("air/linear_ops.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;
const DOMAIN = "stwo-zig/riscv-direct-full-lowering-fixed/v1\x00";

/// Trusted configuration, fixed independently of the captured leaf.
pub const VmPin = struct {
    circuit_identity: [32]u8,
    graph_id: [32]u8,

    pub fn validate(self: VmPin, graph: graph_mod.CircuitGraph) !void {
        if (std.mem.allEqual(u8, &self.circuit_identity, 0) or
            std.mem.allEqual(u8, &self.graph_id, 0)) return error.MissingVerifierVmGraphPinV8;
        try graph.validate();
        if (!std.mem.eql(u8, &self.graph_id, &graph.identity_digest))
            return error.VerifierVmGraphPinMismatchV8;
    }
};

pub const Selected = struct {
    public_key: *const fixed.FixedKey,
    vm_pin: VmPin,
    vm_graph: graph_mod.CircuitGraph,
    pcs_profile: pcs.Profile,
    fri_profile: fri.Profile,
};

pub const Key = struct {
    public_key_seal: [32]u8,
    vm_pin: VmPin,
    pcs_profile_id: [32]u8,
    fri_profile_id: [32]u8,
    pcs_circuit_id: [32]u8,
    fri_circuit_id: [32]u8,
    reference_id: [32]u8,
    plan_id: [32]u8,
    log_sizes: [3]u32,
    fixed_ids: [3][32]u8,
    seal: [32]u8,

    pub fn build(allocator: std.mem.Allocator, selected: Selected) !Key {
        try selected.public_key.validate(allocator);
        try selected.vm_pin.validate(selected.vm_graph);
        if (selected.pcs_profile.lifting_log_size != selected.fri_profile.lifting_log_size or
            selected.pcs_profile.log_blowup_factor != selected.fri_profile.log_blowup_factor or
            selected.pcs_profile.query_count != selected.fri_profile.query_count)
            return error.PcsFriProfileMismatchV8;
        var statement_circuit = try statement.build(allocator);
        defer statement_circuit.deinit();
        const nodes = try allocator.alloc(graph_mod.Node, statement_circuit.graph().nodes().len);
        defer allocator.free(nodes);
        statement_contract.convertGraphNodes(statement_circuit.graph().nodes(), nodes);
        const statement_outputs = statement_circuit.graph().outputs();
        const statement_id = graph_mod.computeGraphDigest(nodes, statement_outputs);
        if (!std.mem.eql(u8, &statement_id, &statement_contract.LOWERING_GRAPH_DIGEST))
            return error.StatementLoweringGraphMismatchV8;
        const statement_graph = try graph_mod.CircuitGraph.authenticate(nodes, statement_outputs, statement_id);

        var claim = try public_graphs.ClaimReference.init(allocator, selected.public_key.shape.claim, public_source.CLAIM_CIRCUIT_ID);
        defer claim.deinit();
        var logup = try public_graphs.LogupReference.init(allocator, selected.public_key.shape.claim, public_source.PUBLIC_LOGUP_CIRCUIT_ID, selected.public_key.shape.claimed_sum_count);
        defer logup.deinit();
        if (!std.mem.eql(u8, &claim.authority_digest, &selected.public_key.claim_graph_id) or
            !std.mem.eql(u8, &logup.authority_digest, &selected.public_key.logup_graph_id))
            return error.PublicGraphKeyMismatchV8;
        var claim_graph = try public_source.OwnedGraph.init(allocator, &claim.circuit);
        defer claim_graph.deinit();
        var logup_graph = try public_source.OwnedGraph.init(allocator, &logup.circuit);
        defer logup_graph.deinit();
        var pcs_circuit = try pcs.build(allocator, selected.pcs_profile);
        defer pcs_circuit.deinit();
        var fri_circuit = try fri.build(allocator, selected.fri_profile);
        defer fri_circuit.deinit();
        try pcs_circuit.validate();
        try fri_circuit.validate();

        // Exact direct-leaf order in detached_fri_core_part_11. VM identity is
        // the only external graph input; all other graphs are rebuilt here.
        const lanes = [_]lowering.Lane{
            .{ .circuit_id = 1, .active_in = .segment, .circuit_identity = selected.vm_pin.circuit_identity, .graph = selected.vm_graph },
            .{ .circuit_id = 11, .active_in = .segment, .circuit_identity = statement_circuit.identity_digest, .graph = statement_graph },
            .{ .circuit_id = 40, .active_in = .segment, .circuit_identity = claim.authority_digest, .graph = claim_graph.graph },
            .{ .circuit_id = 41, .active_in = .segment, .circuit_identity = logup.authority_digest, .graph = logup_graph.graph },
            .{ .circuit_id = 201, .active_in = .segment, .circuit_identity = pcs_circuit.identity_digest, .graph = pcs_circuit.graph() },
            .{ .circuit_id = 301, .active_in = .segment, .circuit_identity = fri_circuit.identity_digest, .graph = fri_circuit.graph() },
            .{ .circuit_id = 2, .active_in = .binary, .circuit_identity = selected.vm_pin.circuit_identity, .graph = selected.vm_graph },
        };
        const reference = try lowering.Reference.seal(&lanes);
        var plan = try lowering.Plan.init(allocator, reference);
        defer plan.deinit();
        try plan.validateAgainstAuthority(allocator, reference);
        const log_sizes = [3]u32{
            try traceLogSize(plan.multiply_rows.len),
            try traceLogSize(plan.inverse_rows.len),
            try traceLogSize(plan.linear_rows.len),
        };
        var result = Key{
            .public_key_seal = selected.public_key.seal,
            .vm_pin = selected.vm_pin,
            .pcs_profile_id = selected.pcs_profile.identityDigest(),
            .fri_profile_id = selected.fri_profile.identityDigest(),
            .pcs_circuit_id = pcs_circuit.identity_digest,
            .fri_circuit_id = fri_circuit.identity_digest,
            .reference_id = reference.authority_digest,
            .plan_id = plan.authority_digest,
            .log_sizes = log_sizes,
            .fixed_ids = .{
                try rowId(30, log_sizes[0], mul.PREPROCESSED_COLUMN_COUNT, mul_air.SEMANTIC_DIGEST, plan.multiply_rows, mul.preprocessedRow),
                try rowId(31, log_sizes[1], inv.PREPROCESSED_COLUMN_COUNT, inv_air.SEMANTIC_DIGEST, plan.inverse_rows, inv.preprocessedRow),
                try rowId(32, log_sizes[2], lin.PREPROCESSED_COLUMN_COUNT, lin_air.SEMANTIC_DIGEST, plan.linear_rows, lin.preprocessedRow),
            },
            .seal = undefined,
        };
        result.seal = result.computeSeal();
        return result;
    }

    pub fn validate(self: *const Key, allocator: std.mem.Allocator, selected: Selected) !void {
        const fresh = try build(allocator, selected);
        if (!std.meta.eql(self.*, fresh)) return error.FullLoweringFixedKeyMismatchV8;
    }

    /// This is the admission gate for a later captured VM graph. It never
    /// constructs the expected pin from that graph; `selected` must already
    /// come from the verifier's pre-leaf key.
    pub fn validateCapturedVmLane(
        self: *const Key,
        allocator: std.mem.Allocator,
        selected: Selected,
        captured: lowering.Lane,
    ) !void {
        try self.validate(allocator, selected);
        if (captured.circuit_id != 1 or captured.active_in != .segment or
            !std.mem.eql(u8, &captured.circuit_identity, &self.vm_pin.circuit_identity))
            return error.CapturedVmGraphMismatchV8;
        try captured.graph.validate();
        if (!std.mem.eql(u8, &captured.graph.identity_digest, &self.vm_pin.graph_id))
            return error.CapturedVmGraphMismatchV8;
    }

    /// Admit the actual seven lanes selected by the direct transcript source.
    /// The existing q193 SegmentV2 cohort supplies five different lanes and
    /// must fail here; the two profiles have distinct fixed-column keys.
    pub fn validateDirectTranscriptSourceLanes(
        self: *const Key,
        allocator: std.mem.Allocator,
        selected: Selected,
        actual: []const lowering.Lane,
    ) !void {
        try self.validate(allocator, selected);
        const expected_ids = [_]u32{ 1, 11, 40, 41, 201, 301, 2 };
        if (actual.len != expected_ids.len) return error.WrongDirectTranscriptLaneProfileV8;
        for (actual, expected_ids, 0..) |lane, expected_id, index| {
            if (lane.circuit_id != expected_id or
                lane.active_in != if (index == expected_ids.len - 1) lowering.Mode.binary else lowering.Mode.segment)
                return error.WrongDirectTranscriptLaneProfileV8;
        }
        try self.validateCapturedVmLane(allocator, selected, actual[0]);
        const reference = try lowering.Reference.seal(actual);
        if (!std.mem.eql(u8, &self.reference_id, &reference.authority_digest))
            return error.DirectTranscriptSourceLaneMismatchV8;
        var plan = try lowering.Plan.init(allocator, reference);
        defer plan.deinit();
        try self.validatePlan(&plan);
    }

    /// A separately produced lowering plan must reconstruct the same three
    /// complete padded fixed-column sets before its rows can be published.
    pub fn validatePlan(self: *const Key, plan: *const lowering.Plan) !void {
        if (!std.mem.eql(u8, &self.plan_id, &plan.authority_digest) or
            self.log_sizes[0] != try traceLogSize(plan.multiply_rows.len) or
            self.log_sizes[1] != try traceLogSize(plan.inverse_rows.len) or
            self.log_sizes[2] != try traceLogSize(plan.linear_rows.len) or
            !std.mem.eql(u8, &self.fixed_ids[0], &try rowId(30, self.log_sizes[0], mul.PREPROCESSED_COLUMN_COUNT, mul_air.SEMANTIC_DIGEST, plan.multiply_rows, mul.preprocessedRow)) or
            !std.mem.eql(u8, &self.fixed_ids[1], &try rowId(31, self.log_sizes[1], inv.PREPROCESSED_COLUMN_COUNT, inv_air.SEMANTIC_DIGEST, plan.inverse_rows, inv.preprocessedRow)) or
            !std.mem.eql(u8, &self.fixed_ids[2], &try rowId(32, self.log_sizes[2], lin.PREPROCESSED_COLUMN_COUNT, lin_air.SEMANTIC_DIGEST, plan.linear_rows, lin.preprocessedRow)))
            return error.FullLoweringPlanMismatchV8;
    }

    fn computeSeal(self: *const Key) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.public_key_seal);
        hash.update(&self.vm_pin.circuit_identity);
        hash.update(&self.vm_pin.graph_id);
        hash.update(&self.pcs_profile_id);
        hash.update(&self.fri_profile_id);
        hash.update(&self.pcs_circuit_id);
        hash.update(&self.fri_circuit_id);
        hash.update(&self.reference_id);
        hash.update(&self.plan_id);
        for (self.log_sizes, self.fixed_ids) |log_size, id| {
            hashInt(&hash, u32, log_size);
            hash.update(&id);
        }
        return hash.finalResult();
    }
};

fn traceLogSize(count: usize) !u32 {
    if (count >= (@as(usize, 1) << 30)) return error.ArithmeticOverflow;
    return @intCast(@max(@as(usize, 1), std.math.log2_int_ceil(usize, @max(count, 1))));
}

fn rowId(
    comptime row: u8,
    log_size: u32,
    comptime width: usize,
    semantic_digest: [32]u8,
    rows: anytype,
    comptime values: anytype,
) ![32]u8 {
    const capacity = @as(usize, 1) << @intCast(log_size);
    if (rows.len > capacity) return error.FullLoweringFixedGeometryMismatchV8;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u8, row);
    hashInt(&hash, u32, log_size);
    hashInt(&hash, u32, width);
    hash.update(&semantic_digest);
    for (0..width) |column| for (0..capacity) |logical| {
        const value: M31 = if (logical < rows.len) values(rows[logical])[column] else M31.zero();
        hashInt(&hash, u32, value.toU32());
    };
    return hash.finalResult();
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    const bytes = std.mem.toBytes(std.mem.nativeToLittle(T, value));
    hash.update(&bytes);
}

test "V8 direct transcript seven-lane key requires independent VM pin" {
    const allocator = std.testing.allocator;
    const nodes = [_]graph_mod.Node{
        .{ .op = .{ .constant = .{ 0, 0, 0, 0 } } },
    };
    const outputs = [_]u32{0};
    const graph_id = graph_mod.computeGraphDigest(&nodes, &outputs);
    const graph = try graph_mod.CircuitGraph.authenticate(&nodes, &outputs, graph_id);
    const public_key = try fixed.FixedKey.build(allocator, .{
        .claim = try @import("vm_public_claim_layout.zig").Shape.init(0, 0),
        .claimed_sum_count = 4,
    });
    const logs = [_]u32{ 4, 3 };
    const trees = [_]pcs.TreeProfile{.{ .column_log_sizes = &logs }};
    const layouts = [_]pcs.SamplePointLayout{ .current_previous, .none };
    const widths = [_]u32{8};
    const selected = Selected{
        .public_key = &public_key,
        .vm_pin = .{ .circuit_identity = graph_id, .graph_id = graph_id },
        .vm_graph = graph,
        .pcs_profile = .{
            .trees = &trees,
            .sample_layouts = &layouts,
            .lifting_log_size = 5,
            .log_blowup_factor = 1,
            .query_count = 1,
        },
        .fri_profile = .{
            .lifting_log_size = 5,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 1,
            .fold_widths = &widths,
            .query_count = 1,
        },
    };
    const key = try Key.build(allocator, selected);
    try key.validate(allocator, selected);
    // Assemble the source-side lane list separately from the key builder.
    // This is the exact branch enabled by `segment_transcript_inputs != null`.
    var statement_circuit = try statement.build(allocator);
    defer statement_circuit.deinit();
    const statement_nodes = try allocator.alloc(graph_mod.Node, statement_circuit.graph().nodes().len);
    defer allocator.free(statement_nodes);
    statement_contract.convertGraphNodes(statement_circuit.graph().nodes(), statement_nodes);
    const statement_outputs = statement_circuit.graph().outputs();
    const statement_id = graph_mod.computeGraphDigest(statement_nodes, statement_outputs);
    const statement_graph = try graph_mod.CircuitGraph.authenticate(statement_nodes, statement_outputs, statement_id);
    var claim = try public_graphs.ClaimReference.init(allocator, public_key.shape.claim, public_source.CLAIM_CIRCUIT_ID);
    defer claim.deinit();
    var logup = try public_graphs.LogupReference.init(allocator, public_key.shape.claim, public_source.PUBLIC_LOGUP_CIRCUIT_ID, public_key.shape.claimed_sum_count);
    defer logup.deinit();
    var claim_graph = try public_source.OwnedGraph.init(allocator, &claim.circuit);
    defer claim_graph.deinit();
    var logup_graph = try public_source.OwnedGraph.init(allocator, &logup.circuit);
    defer logup_graph.deinit();
    var pcs_circuit = try pcs.build(allocator, selected.pcs_profile);
    defer pcs_circuit.deinit();
    var fri_circuit = try fri.build(allocator, selected.fri_profile);
    defer fri_circuit.deinit();
    const source_lanes = [_]lowering.Lane{
        .{ .circuit_id = 1, .active_in = .segment, .circuit_identity = graph_id, .graph = graph },
        .{ .circuit_id = 11, .active_in = .segment, .circuit_identity = statement_circuit.identity_digest, .graph = statement_graph },
        .{ .circuit_id = 40, .active_in = .segment, .circuit_identity = claim.authority_digest, .graph = claim_graph.graph },
        .{ .circuit_id = 41, .active_in = .segment, .circuit_identity = logup.authority_digest, .graph = logup_graph.graph },
        .{ .circuit_id = 201, .active_in = .segment, .circuit_identity = pcs_circuit.identity_digest, .graph = pcs_circuit.graph() },
        .{ .circuit_id = 301, .active_in = .segment, .circuit_identity = fri_circuit.identity_digest, .graph = fri_circuit.graph() },
        .{ .circuit_id = 2, .active_in = .binary, .circuit_identity = graph_id, .graph = graph },
    };
    try key.validateDirectTranscriptSourceLanes(allocator, selected, &source_lanes);
    var swapped = source_lanes;
    std.mem.swap(lowering.Lane, &swapped[2], &swapped[3]);
    try std.testing.expectError(error.WrongDirectTranscriptLaneProfileV8, key.validateDirectTranscriptSourceLanes(allocator, selected, &swapped));
    try key.validateCapturedVmLane(allocator, selected, .{
        .circuit_id = 1,
        .active_in = .segment,
        .circuit_identity = graph_id,
        .graph = graph,
    });
    for (key.fixed_ids) |id| try std.testing.expect(!std.mem.allEqual(u8, &id, 0));
    const short_lanes = [_]lowering.Lane{
        .{ .circuit_id = 1, .active_in = .segment, .circuit_identity = graph_id, .graph = graph },
        .{ .circuit_id = 2, .active_in = .binary, .circuit_identity = graph_id, .graph = graph },
    };
    const short_reference = try lowering.Reference.seal(&short_lanes);
    var short_plan = try lowering.Plan.init(allocator, short_reference);
    defer short_plan.deinit();
    try std.testing.expectError(error.FullLoweringPlanMismatchV8, key.validatePlan(&short_plan));
    const q193_cohort_lanes = [_]lowering.Lane{
        short_lanes[0],
        .{ .circuit_id = 42, .active_in = .segment, .circuit_identity = graph_id, .graph = graph },
        .{ .circuit_id = 201, .active_in = .segment, .circuit_identity = graph_id, .graph = graph },
        .{ .circuit_id = 301, .active_in = .segment, .circuit_identity = graph_id, .graph = graph },
        short_lanes[1],
    };
    try std.testing.expectError(error.WrongDirectTranscriptLaneProfileV8, key.validateDirectTranscriptSourceLanes(allocator, selected, &q193_cohort_lanes));
    var mutated = key;
    mutated.fixed_ids[2][0] ^= 1;
    try std.testing.expectError(error.FullLoweringFixedKeyMismatchV8, mutated.validate(allocator, selected));
    var missing = selected;
    missing.vm_pin.graph_id = [_]u8{0} ** 32;
    try std.testing.expectError(error.MissingVerifierVmGraphPinV8, Key.build(allocator, missing));
    var wrong = selected;
    wrong.vm_pin.graph_id[0] ^= 1;
    try std.testing.expectError(error.VerifierVmGraphPinMismatchV8, Key.build(allocator, wrong));
    var wrong_profile = selected;
    wrong_profile.pcs_profile.query_count = 2;
    try std.testing.expectError(error.PcsFriProfileMismatchV8, Key.build(allocator, wrong_profile));
    var wrong_lane_id = graph_id;
    wrong_lane_id[0] ^= 1;
    try std.testing.expectError(error.CapturedVmGraphMismatchV8, key.validateCapturedVmLane(allocator, selected, .{
        .circuit_id = 1,
        .active_in = .segment,
        .circuit_identity = wrong_lane_id,
        .graph = graph,
    }));
    const other_nodes = [_]graph_mod.Node{
        .{ .op = .{ .constant = .{ 1, 0, 0, 0 } } },
    };
    const other_id = graph_mod.computeGraphDigest(&other_nodes, &outputs);
    const other_graph = try graph_mod.CircuitGraph.authenticate(&other_nodes, &outputs, other_id);
    try std.testing.expectError(error.CapturedVmGraphMismatchV8, key.validateCapturedVmLane(allocator, selected, .{
        .circuit_id = 1,
        .active_in = .segment,
        .circuit_identity = graph_id,
        .graph = other_graph,
    }));
    var changed = selected;
    const more_sums = try fixed.FixedKey.build(allocator, .{
        .claim = public_key.shape.claim,
        .claimed_sum_count = 5,
    });
    changed.public_key = &more_sums;
    const changed_key = try Key.build(allocator, changed);
    try std.testing.expect(!std.mem.eql(u8, &key.seal, &changed_key.seal));
}
