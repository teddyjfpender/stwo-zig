const std = @import("std");
const subject = @import("recursion/air/segment_leaf_wrapper_roster_v3.zig");
const v2 = @import("recursion/air/segment_outer_adapter_manifest_v2.zig");
const catalog = @import("recursion/air/segment_outer_typed_catalog_v2.zig");
const universal = @import("recursion/air/universal_manifest.zig");
const roster = @import("recursion/air/universal_roster.zig");
const boundary = @import("recursion/segment_leaf_outer_authority_v2.zig");
const boundary_air = @import("recursion/segment_leaf_outer_air_v2.zig");
const provider = @import("recursion/segment_publication_input_provider_authority_v2.zig");
const range = @import("recursion/air/range_check_8_8_bridge.zig");
const row17 = @import("recursion/air/vm_public_logup_control_witness_v2.zig");
const program_mod = @import("recursion/ethereum_leaf_link_program_v1.zig");
const program_v2_mod = @import("recursion/ethereum_leaf_link_program_v2.zig");
const roster_v2 = @import("recursion/air/segment_leaf_wrapper_roster_v3_v2.zig");
const profile = @import("recursion/segment_leaf_wrapper_protocol_v3.zig");
const gate = @import("recursion/air/segment_leaf_wrapper_proof_gate_v3.zig");
const tree0_air = @import("recursion/air/segment_v2_tree0_field_link_v3.zig");
const relation_binding = @import("recursion/air/universal_relation_binding.zig");
const challenges = @import("recursion/air/universal_challenges.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

test "V3 wrapper roster pins all required rows without proof promotion" {
    std.testing.refAllDecls(subject);
    std.testing.refAllDecls(profile);
    std.testing.refAllDecls(gate);
    try std.testing.expectEqual(@as(usize, 49), subject.COMPONENT_COUNT);
    try std.testing.expectEqual(@as(usize, 39), subject.BASE_COUNT);
    try std.testing.expect(!subject.COMPLETE_WRAPPER_PROOF_AVAILABLE);
    try std.testing.expect(!subject.PRODUCTION_PROOF_ACTIVATION);
}

test "V3 wrapper roster combines exact 39 plus 10 rows and resizes one Poseidon provider" {
    const source_catalog = try catalog.build(fixtureLogSizes(), boundaryComponents());
    const plan_base = try v2.assemble(
        &source_catalog,
        authorityIds(),
    );
    var program = try program_mod.ProgramV1.init(std.testing.allocator);
    defer program.deinit();
    const shape = subject.Shape{
        .program_words = 100,
        .provider_words = 200,
        .base_poseidon_calls = 1193,
    };
    const plan = try subject.Plan.build(std.testing.allocator, &plan_base, &program, shape);
    try plan.validateAgainst(std.testing.allocator, &plan_base, &program, shape);
    for (plan.roster_rows, 0..) |row, index| try std.testing.expectEqual(@as(u8, @intCast(index)), row);
    try std.testing.expectEqual(@as(usize, 1193 + 77 + 7 + 13 + 26), plan.poseidon_calls.total);
    try std.testing.expectEqual(@as(u32, 11), plan.placements[34].?.geometry.log_size);
    try std.testing.expectEqual(@as(u8, 48), plan.placements[48].?.claimed_sum_index);
    try std.testing.expectEqual(@as(u32, 4), plan.placements[46].?.geometry.log_size);
    try std.testing.expectEqualSlices(u8, &@import("recursion/air/vm_public_claim_hash.zig").SEMANTIC_DIGEST, &plan.placements[47].?.geometry.semantic_digest);
    try std.testing.expectError(error.V3WrapperProofUnavailable, plan.requireCompleteWrapperProof());
    var program_v2 = try program_v2_mod.ProgramV2.init(std.testing.allocator);
    defer program_v2.deinit();
    const plan_v2 = try roster_v2.PlanV2.build(std.testing.allocator, &plan_base, &program_v2, shape);
    const v3_protocol_id = try profile.protocolId(&plan_v2);
    try std.testing.expect(!std.meta.eql(
        v3_protocol_id,
        @import("recursion/protocol.zig").PROTOCOL_ID_WORDS,
    ));
    const different_shape = try roster_v2.PlanV2.build(
        std.testing.allocator,
        &plan_base,
        &program_v2,
        .{ .program_words = 101, .provider_words = 200, .base_poseidon_calls = 1193 },
    );
    try std.testing.expect(!std.meta.eql(v3_protocol_id, try profile.protocolId(&different_shape)));
    const root_a = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var root_b = root_a;
    root_b[0] += 1;
    const key_a = try profile.verificationKeyId(&plan_v2, root_a);
    const key_b = try profile.verificationKeyId(&plan_v2, root_b);
    try std.testing.expect(!std.meta.eql(key_a, key_b));
    root_b[0] = @import("stwo_core").fields.m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalV3PreprocessedRoot,
        profile.verificationKeyId(&plan_v2, root_b),
    );
    var partial_gate = try gate.ProofGate.init(&plan);
    try std.testing.expectError(error.IncompleteV3WrapperGate, partial_gate.sealGate(&plan));
    var tree0_definition = try tree0_air.build(std.testing.allocator);
    defer tree0_definition.deinit();
    const tree0_relation = try relation_binding.Binding(tree0_air).authenticate(&tree0_definition);
    const relations = challenges.UniversalRelations.dummy();
    const tree0_component = try subject.Tree0Adapter.init(
        &tree0_definition,
        tree0_relation,
        &plan,
        .tree0_field,
        4,
        .{},
        &relations,
        QM31.zero(),
    );
    const tree0_binding = try tree0_component.binding(&plan);
    try std.testing.expectEqual(@as(u8, 46), tree0_binding.placement.geometry.roster_row);
    try std.testing.expectEqualSlices(u8, &plan.seal, &tree0_binding.manifest_seal);

    var tampered = plan;
    tampered.placements[34].?.geometry.log_size += 1;
    try std.testing.expectError(error.InvalidV3WrapperRoster, tampered.validate());
    tampered = plan;
    tampered.poseidon_calls.program += 1;
    try std.testing.expectError(error.InvalidV3WrapperRoster, tampered.validate());
    try std.testing.expectError(error.InvalidV3WrapperRoster, plan.validateAgainst(std.testing.allocator, &plan_base, &program, .{ .program_words = 101, .provider_words = 200, .base_poseidon_calls = 1193 }));
    try std.testing.expectError(
        error.V3PoseidonCallCountMismatch,
        subject.Plan.build(std.testing.allocator, &plan_base, &program, .{ .program_words = 100, .provider_words = 200, .base_poseidon_calls = 2049 }),
    );
}

pub fn fixtureLogSizes() universal.LogSizes {
    var result = [_]u32{4} ** roster.COMPONENT_COUNT;
    result[0] = 5;
    result[1] = 6;
    result[5] = 7;
    result[11] = 8;
    result[12] = 5;
    result[13] = 4;
    result[14] = 4;
    result[15] = 6;
    result[16] = 5;
    result[17] = row17.TRACE_LOG_SIZE;
    result[@intFromEnum(roster.Component.poseidon2)] = 11;
    result[@intFromEnum(roster.Component.range_check_8_8)] = range.LOG_SIZE;
    return result;
}

pub fn boundaryComponents() [boundary.COMPONENT_COUNT]boundary.ComponentGeometryV2 {
    const log_size: u8 = 8;
    return .{
        .{
            .kind = .statement_source,
            .component_tag = boundary.STATEMENT_COMPONENT_TAG,
            .logical_rows = (@as(u32, 1) << @intCast(log_size - 1)) + 1,
            .trace_log_size = log_size,
            .trace_rows = @as(u32, 1) << @intCast(log_size),
            .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = boundary.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = boundary.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = boundary.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = boundary.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
}

pub fn authorityIds() v2.AuthorityIds {
    return .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
        .provider_authority_sha_id = provider.sourceAuthorityShaId(),
    };
}

fn nativeDigest(seed: u32) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return out;
}

fn shaDigest(seed: u8) [32]u8 {
    var out: [32]u8 = undefined;
    for (&out, 0..) |*byte, index| byte.* = seed +% @as(u8, @truncate(index));
    return out;
}
