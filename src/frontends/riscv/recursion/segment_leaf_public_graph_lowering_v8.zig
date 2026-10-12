//! Exact verifier-owned *contribution* to shared rows 30--32.
//!
//! Statement semantics, VM claim semantics, and public LogUp compile from
//! fixed verifier policy/shape and form one contiguous segment-lane block in
//! the full arithmetic lowering. This module seals their complete lowered
//! operation schedule together with the row-15/16 fixed key. It does not
//! claim to seal the final physical rows: VM/PCS/segment and binary lanes also
//! occupy those columns, and their overlay must be derived and keyed first.
const std = @import("std");
const fixed = @import("segment_leaf_public_graph_fixed_v8.zig");
const graphs = @import("vm_public_semantics_circuit.zig");
const statement = @import("statement_semantics_circuit.zig");
const statement_contract = @import("segment_statement_outer_source_contract.zig");
const source_mod = @import("segment_public_outer_source.zig");
const graph_mod = @import("air/composition_circuit.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const PRODUCTION_PROOF_ACTIVATION = false;
const DOMAIN = "stwo-zig/riscv-direct-public-graph-lowering/v1\x00";

/// Counts cover exactly the segment lanes [11, 40, 41]. The partial plan
/// includes one canonical inert binary anchor because the shared lowering
/// compiler requires both modes. Its IDs cannot be substituted for the full
/// row-30/31/32 fixed-column IDs.
pub const Contribution = struct {
    public_fixed_key_seal: [32]u8,
    statement_graph_id: [32]u8,
    reference_id: [32]u8,
    plan_id: [32]u8,
    multiply_rows: usize,
    inverse_rows: usize,
    linear_rows: usize,
    seal: [32]u8,

    pub fn build(allocator: std.mem.Allocator, public_key: *const fixed.FixedKey) !Contribution {
        try public_key.validate(allocator);
        var statement_circuit = try statement.build(allocator);
        defer statement_circuit.deinit();
        const statement_nodes = try allocator.alloc(
            graph_mod.Node,
            statement_circuit.graph().nodes().len,
        );
        defer allocator.free(statement_nodes);
        statement_contract.convertGraphNodes(
            statement_circuit.graph().nodes(),
            statement_nodes,
        );
        const statement_outputs = statement_circuit.graph().outputs();
        const statement_graph_id = graph_mod.computeGraphDigest(
            statement_nodes,
            statement_outputs,
        );
        if (!std.mem.eql(
            u8,
            &statement_graph_id,
            &statement_contract.LOWERING_GRAPH_DIGEST,
        )) return error.StatementLoweringGraphMismatchV8;
        const statement_graph = try graph_mod.CircuitGraph.authenticate(
            statement_nodes,
            statement_outputs,
            statement_graph_id,
        );

        var claim = try graphs.ClaimReference.init(
            allocator,
            public_key.shape.claim,
            source_mod.CLAIM_CIRCUIT_ID,
        );
        defer claim.deinit();
        var logup = try graphs.LogupReference.init(
            allocator,
            public_key.shape.claim,
            source_mod.PUBLIC_LOGUP_CIRCUIT_ID,
            public_key.shape.claimed_sum_count,
        );
        defer logup.deinit();
        if (!std.mem.eql(u8, &claim.authority_digest, &public_key.claim_graph_id) or
            !std.mem.eql(u8, &logup.authority_digest, &public_key.logup_graph_id))
            return error.PublicGraphKeyMismatchV8;
        var claim_graph = try source_mod.OwnedGraph.init(allocator, &claim.circuit);
        defer claim_graph.deinit();
        var logup_graph = try source_mod.OwnedGraph.init(allocator, &logup.circuit);
        defer logup_graph.deinit();
        // This constant-only binary lane is a compiler bootstrap, not the
        // production binary graph. It contributes no operation row. The real
        // full plan must replace it and rederive all physical fixed columns.
        const anchor_nodes = [_]graph_mod.Node{.{ .op = .{ .constant = .{ 0, 0, 0, 0 } } }};
        const anchor_outputs = [_]u32{0};
        const anchor_id = graph_mod.computeGraphDigest(&anchor_nodes, &anchor_outputs);
        const anchor_graph = try graph_mod.CircuitGraph.authenticate(
            &anchor_nodes,
            &anchor_outputs,
            anchor_id,
        );
        const lanes = [_]lowering.Lane{
            .{
                .circuit_id = statement_contract.STATEMENT_CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = statement_circuit.identity_digest,
                .graph = statement_graph,
            },
            .{
                .circuit_id = source_mod.CLAIM_CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = claim.authority_digest,
                .graph = claim_graph.graph,
            },
            .{
                .circuit_id = source_mod.PUBLIC_LOGUP_CIRCUIT_ID,
                .active_in = .segment,
                .circuit_identity = logup.authority_digest,
                .graph = logup_graph.graph,
            },
            .{
                .circuit_id = 12,
                .active_in = .binary,
                .circuit_identity = anchor_id,
                .graph = anchor_graph,
            },
        };
        const reference = try lowering.Reference.seal(&lanes);
        var plan = try lowering.Plan.init(allocator, reference);
        defer plan.deinit();
        try plan.validateAgainstAuthority(allocator, reference);
        const result = Contribution{
            .public_fixed_key_seal = public_key.seal,
            .statement_graph_id = statement_graph_id,
            .reference_id = reference.authority_digest,
            .plan_id = plan.authority_digest,
            .multiply_rows = plan.mode_counts[@intFromEnum(lowering.Mode.segment)].multiply,
            .inverse_rows = plan.mode_counts[@intFromEnum(lowering.Mode.segment)].inverse,
            .linear_rows = plan.mode_counts[@intFromEnum(lowering.Mode.segment)].linear,
            .seal = undefined,
        };
        var sealed = result;
        sealed.seal = sealed.computeSeal();
        return sealed;
    }

    pub fn validate(
        self: *const Contribution,
        allocator: std.mem.Allocator,
        public_key: *const fixed.FixedKey,
    ) !void {
        const fresh = try build(allocator, public_key);
        if (!std.meta.eql(self.*, fresh))
            return error.PublicGraphLoweringMismatchV8;
    }

    fn computeSeal(self: *const Contribution) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        hashInt(&hash, u16, FORMAT_VERSION);
        hash.update(&self.public_fixed_key_seal);
        hash.update(&self.statement_graph_id);
        hash.update(&self.reference_id);
        hash.update(&self.plan_id);
        hashInt(&hash, u64, @intCast(self.multiply_rows));
        hashInt(&hash, u64, @intCast(self.inverse_rows));
        hashInt(&hash, u64, @intCast(self.linear_rows));
        return hash.finalResult();
    }
};

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    const bytes = std.mem.toBytes(std.mem.nativeToLittle(T, value));
    hash.update(&bytes);
}

test "V8 statement and public graphs have one exact lowered schedule" {
    const allocator = std.testing.allocator;
    const shape_mod = @import("vm_public_claim_layout.zig");
    const shape = fixed.AdmittedShape{
        .claim = try shape_mod.Shape.init(0, 0),
        .claimed_sum_count = 4,
    };
    const key = try fixed.FixedKey.build(allocator, shape);
    const contribution = try Contribution.build(allocator, &key);
    try contribution.validate(allocator, &key);
    try std.testing.expect(contribution.multiply_rows > 0);
    try std.testing.expect(contribution.inverse_rows > 0);
    try std.testing.expect(contribution.linear_rows > 0);
    var mutated = contribution;
    mutated.plan_id[0] ^= 1;
    try std.testing.expectError(
        error.PublicGraphLoweringMismatchV8,
        mutated.validate(allocator, &key),
    );
    const more_sums = try fixed.FixedKey.build(allocator, .{
        .claim = shape.claim,
        .claimed_sum_count = shape.claimed_sum_count + 1,
    });
    const different = try Contribution.build(allocator, &more_sums);
    try std.testing.expect(!std.mem.eql(u8, &contribution.plan_id, &different.plan_id));
    try std.testing.expectError(
        error.PublicGraphLoweringMismatchV8,
        contribution.validate(allocator, &more_sums),
    );
}

test "V8 public graph key and lowering match independently prepared outer source" {
    const allocator = std.testing.allocator;
    const claim_shape = try @import("vm_public_claim_layout.zig").Shape.init(0, 0);
    const fixed_profile = @import("fixed_profile.zig");
    const protocol = @import("protocol.zig");
    const channel = @import("poseidon2_channel.zig");
    const schedule = @import("air/verifier_schedule.zig");
    const leaf = @import("segment_leaf_authority.zig");
    const statement_source = @import("segment_statement_outer_source.zig");
    const fri = try fixed_profile.FriSchedule.init(24, protocol.PCS_CONFIG.fri_config);
    const proof_shape = fixed_profile.ProofShapeV1{
        .air_program_id = channel.hashBytes("air-program", 0x5450),
        .preprocessing_id = channel.hashBytes("preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("ordered-table-layout", 0x5450),
        .table_count = 2_000,
        .claimed_sum_count = 4,
        .sampled_value_count = 2_100,
        .preprocessed_column_count = 128,
        .tree_column_counts = .{ 128, 1_500, 364, 8 },
        .tree_heights = .{ 25, 25, 25, 25 },
        .column_log_degree = 24,
        .proof_wire_bytes = 3_500_000,
        .fri = fri,
    };
    var vm_plan = try schedule.Plan.init(allocator, schedule.VM_PROGRAM_SPEC_V1, proof_shape);
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.init(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, proof_shape);
    defer recursion_plan.deinit();
    var preprocessing = try leaf.Preprocessing.init(allocator, claim_shape);
    defer preprocessing.deinit();
    var source = try source_mod.Source.init(
        allocator,
        &vm_plan,
        &recursion_plan,
        &preprocessing,
        4,
    );
    defer source.deinit();
    var statement_authority = try statement_source.Authority.init(allocator, &preprocessing);
    defer statement_authority.deinit();

    const public_key = try fixed.FixedKey.buildFromVerifierPlan(
        allocator,
        claim_shape,
        &vm_plan,
    );
    try public_key.validateAgainstSource(
        allocator,
        &source,
        &vm_plan,
        &recursion_plan,
        &preprocessing,
    );
    const contribution = try Contribution.build(allocator, &public_key);
    const source_lanes = source.loweringLanes();
    const anchor_nodes = [_]graph_mod.Node{.{ .op = .{ .constant = .{ 0, 0, 0, 0 } } }};
    const anchor_outputs = [_]u32{0};
    const anchor_id = graph_mod.computeGraphDigest(&anchor_nodes, &anchor_outputs);
    const anchor_graph = try graph_mod.CircuitGraph.authenticate(
        &anchor_nodes,
        &anchor_outputs,
        anchor_id,
    );
    const lanes = [_]lowering.Lane{
        statement_authority.loweringLane(),
        source_lanes[0],
        source_lanes[1],
        .{
            .circuit_id = 12,
            .active_in = .binary,
            .circuit_identity = anchor_id,
            .graph = anchor_graph,
        },
    };
    const reference = try lowering.Reference.seal(&lanes);
    var actual_plan = try lowering.Plan.init(allocator, reference);
    defer actual_plan.deinit();
    try std.testing.expectEqualDeep(contribution.reference_id, reference.authority_digest);
    try std.testing.expectEqualDeep(contribution.plan_id, actual_plan.authority_digest);
    try std.testing.expectEqualDeep(contribution.multiply_rows, actual_plan.mode_counts[0].multiply);
    try std.testing.expectEqualDeep(contribution.inverse_rows, actual_plan.mode_counts[0].inverse);
    try std.testing.expectEqualDeep(contribution.linear_rows, actual_plan.mode_counts[0].linear);

    // A use-count selected by the source instead of the canonical graph must
    // fail before it can be admitted to the fixed-key lowering schedule.
    source.claim_reference.row_bindings[0].use_count += 1;
    try std.testing.expectError(
        error.InputLayoutMismatch,
        public_key.validateAgainstSource(
            allocator,
            &source,
            &vm_plan,
            &recursion_plan,
            &preprocessing,
        ),
    );
    source.claim_reference.row_bindings[0].use_count -= 1;
    actual_plan.multiply_rows[0].segment.?.uses = @import("stwo_core").fields.m31.M31.fromCanonical(
        actual_plan.multiply_rows[0].segment.?.uses.toU32() + 1,
    );
    try std.testing.expectError(
        error.AuthorityMismatch,
        actual_plan.validateAgainstAuthority(allocator, reference),
    );
}
