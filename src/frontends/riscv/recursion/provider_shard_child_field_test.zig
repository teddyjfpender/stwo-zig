const std = @import("std");
const core = @import("stwo_core");

const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const provider_authority =
    @import("../prover/memory_provider_shards/authority.zig");
const provider_order =
    @import("../prover/memory_provider_shards/provider_order_component.zig");
const proof_authority =
    @import("../prover/memory_provider_shards/joint_proof_authority.zig");
const subject = @import("provider_shard_child_field_emitter_v1.zig");
const program_mod = @import("provider_shard_composition_program_v1.zig");
const recursive_inputs =
    @import("provider_shard_recursive_verifier_inputs_v1.zig");
const wrapper_program = @import("provider_shard_wrapper_program_v1.zig");
const channel = @import("poseidon2_channel.zig");
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const QM31 = core.fields.qm31.QM31;

pub fn run() !void {
    std.testing.refAllDeclsRecursive(recursive_inputs);
    std.testing.refAllDeclsRecursive(wrapper_program);
    try runPinnedTests();
    try runDynamicWrapperTests();
}

test "provider shard verifier program and field authority cold-reopen typed inputs" {
    try runPinnedTests();
    try runDynamicWrapperTests();
}

fn runPinnedTests() !void {
    const allocator = std.testing.allocator;
    const calls = try providerCalls(allocator, 33);
    defer allocator.free(calls);
    var plan = try provider_authority.ProviderShardPlanV1.create(
        allocator,
        shaDigest(0x51),
        calls,
        providerResidencyRequest(calls.len),
    );
    defer plan.deinit(allocator);
    const compiler_input = program_mod.CompilerInputV1{
        .plan = &plan,
        .calls = calls,
        .shard_index = 1,
    };
    var program = try program_mod.compile(allocator, compiler_input);
    defer program.deinit();
    try program.validateAgainst(compiler_input);
    try std.testing.expectEqual(@as(u64, 16), program.geometry.first_call);
    try std.testing.expectEqual(@as(u32, 16), program.geometry.call_count);
    try std.testing.expectEqual(@as(u32, 4), program.geometry.log_size);

    const relation = try provider_authority.PoseidonRelationContextV1.canonical(
        plan.session,
        QM31.fromU32Unchecked(11, 12, 13, 14),
        QM31.fromU32Unchecked(21, 22, 23, 24),
    );
    const descriptor = plan.shards[1];
    const first: usize = @intCast(descriptor.first_call);
    const count: usize = @intCast(descriptor.call_count);
    var relations = relations_mod.Relations.dummy();
    relations.poseidon2 = relations_mod.RelationElements(16).init(
        relation.z,
        relation.alpha,
    );
    const ordered_claim = try provider_order.expectedClaim(
        descriptor.first_call,
        calls[first .. first + count],
        &relations,
    );
    const claims = poseidon2_air.Claims{ .sums = .{
        QM31.fromU32Unchecked(31, 32, 33, 34),
        QM31.fromU32Unchecked(41, 42, 43, 44),
    } };
    var statement = proof_authority.ProviderStatementV2{
        .format = proof_authority.provider_format_version_v2,
        .plan_identity = plan.identity,
        .manifest_identity = shaDigest(0x61),
        .stage_a_identity = shaDigest(0x62),
        .descriptor_identity = descriptor.identity,
        .relation_context_identity = relation.identity,
        .call_list_commitment = plan.call_list_commitment,
        .shard_index = 1,
        .first_call = descriptor.first_call,
        .call_count = descriptor.call_count,
        .log_size = descriptor.expected_log_size,
        .tree2_geometry = try proof_authority.ProviderTree2GeometryV2.canonical(
            descriptor.expected_log_size,
        ),
        .claims = claims,
        .ordered_call_claim = ordered_claim,
        .identity = undefined,
    };
    statement.identity = proof_authority.providerStatementIdentityV2(statement);
    const native_claim = provider_authority.ProviderShardClaimV1{
        .plan_identity = plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = 1,
        .relation_context_identity = relation.identity,
        .claims = claims,
    };
    var fresh_claim = proof_authority.FreshProviderClaimV2{
        .format = proof_authority.provider_format_version_v2,
        .manifest_identity = statement.manifest_identity,
        .statement_identity = statement.identity,
        .proof_commitments_identity = shaDigest(0x63),
        .fresh_provider_stark_verified = true,
        .ordered_call_air_verified = true,
        .ordered_call_claim_recomputed = true,
        .native_claim = native_claim,
        .ordered_call_claim = ordered_claim,
        .identity = undefined,
    };
    fresh_claim.identity = proof_authority.providerClaimIdentityV2(fresh_claim);
    const input = subject.FreshVerifierInputV1{
        .program = &program,
        .compiler_input = compiler_input,
        .statement = statement,
        .fresh_claim = fresh_claim,
        .relation = relation,
        .roots = .{
            .preprocessed_commitment_root = fieldDigest(101),
            .main_commitment_root = fieldDigest(201),
            .interaction_commitment_root = fieldDigest(301),
            .composition_commitment_root = fieldDigest(401),
        },
    };
    const authority = try subject.emitFromFreshVerifier(input);
    try authority.validateAgainst(input);
    try std.testing.expect(authority.program_word_count > 400);
    try std.testing.expect(authority.claim_word_count > 20);

    var root_mutation = input;
    root_mutation.roots.main_commitment_root[0] +%= 1;
    try std.testing.expectError(
        error.ProviderShardFieldAuthorityMismatch,
        authority.validateAgainst(root_mutation),
    );

    var receipt_mutation = input;
    receipt_mutation.statement.ordered_call_claim.terminal =
        receipt_mutation.statement.ordered_call_claim.terminal.add(QM31.one());
    receipt_mutation.statement.identity =
        proof_authority.providerStatementIdentityV2(receipt_mutation.statement);
    receipt_mutation.fresh_claim.statement_identity =
        receipt_mutation.statement.identity;
    receipt_mutation.fresh_claim.ordered_call_claim =
        receipt_mutation.statement.ordered_call_claim;
    receipt_mutation.fresh_claim.identity =
        proof_authority.providerClaimIdentityV2(receipt_mutation.fresh_claim);
    try receipt_mutation.fresh_claim.validate();
    try std.testing.expectError(
        error.InvalidProviderShardFieldAuthority,
        subject.emitFromFreshVerifier(receipt_mutation),
    );

    var graph_mutated = false;
    for (program.nodes) |*node| switch (node.op) {
        .constant => |*words| {
            words[0] +%= 1;
            graph_mutated = true;
            break;
        },
        else => {},
    };
    try std.testing.expect(graph_mutated);
    try program_mod.testing.reseal(&program);
    try program.validate();
    try std.testing.expectError(
        error.ProviderShardVerifierProgramMismatch,
        program.validateAgainst(compiler_input),
    );
}

fn runDynamicWrapperTests() !void {
    const allocator = std.testing.allocator;
    const calls = try providerCalls(allocator, 33);
    defer allocator.free(calls);
    var plan = try provider_authority.ProviderShardPlanV1.create(
        allocator,
        shaDigest(0x71),
        calls,
        providerResidencyRequest(calls.len),
    );
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 3), plan.shard_count);
    const relation = try provider_authority.PoseidonRelationContextV1.canonical(
        plan.session,
        QM31.fromU32Unchecked(51, 52, 53, 54),
        QM31.fromU32Unchecked(61, 62, 63, 64),
    );
    const programs = try allocator.alloc(
        program_mod.ProviderShardCompositionProgramV1,
        plan.shards.len,
    );
    var program_count: usize = 0;
    defer {
        for (programs[0..program_count]) |*program| program.deinit();
        allocator.free(programs);
    }
    const children = try allocator.alloc(
        subject.VerifiedWrapperChildV1,
        plan.shards.len,
    );
    defer allocator.free(children);
    const program_inputs = try allocator.alloc(
        wrapper_program.ChildProgramInputV1,
        plan.shards.len,
    );
    defer allocator.free(program_inputs);
    var provider_claim = QM31.zero();
    for (programs, children, program_inputs, 0..) |
        *program,
        *child,
        *program_input,
        index,
    | {
        const compiler_input = program_mod.CompilerInputV1{
            .plan = &plan,
            .calls = calls,
            .shard_index = @intCast(index),
        };
        program.* = try program_mod.compile(allocator, compiler_input);
        program_count += 1;
        const verifier_input = try freshInput(
            program,
            compiler_input,
            relation,
            @intCast(index),
        );
        child.* = .{
            .authority = try subject.emitFromFreshVerifier(verifier_input),
            .verifier_input = verifier_input,
        };
        program_input.* = .{
            .program = program,
            .compiler_input = compiler_input,
        };
        provider_claim = provider_claim.add(verifier_input.statement.claims.total());
    }
    const core_claim = provider_authority.CorePoseidonClaimV1{
        .plan_identity = plan.identity,
        .relation_context_identity = relation.identity,
        .claim = QM31.zero().sub(provider_claim),
    };
    const input = subject.WrapperManifestInputV1{
        .plan = &plan,
        .calls = calls,
        .relation = relation,
        .core_claim = core_claim,
        .children = children,
    };
    const manifest = try subject.compileWrapperManifest(input);
    try manifest.validateAgainst(input);
    try std.testing.expectEqual(plan.shard_count, manifest.shard_count);
    try std.testing.expect(manifest.closed_sum.isZero());

    const wrapper_input = wrapper_program.CompilerInputV1{
        .plan = &plan,
        .calls = calls,
        .children = program_inputs,
    };
    var compiled_wrapper = try wrapper_program.compile(
        allocator,
        wrapper_input,
    );
    defer compiled_wrapper.deinit();
    try compiled_wrapper.validateAgainst(wrapper_input);
    compiled_wrapper.residency_plan_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProviderWrapperCompilerAuthority,
        compiled_wrapper.validate(),
    );
    compiled_wrapper.residency_plan_sha256[0] ^= 1;
    try compiled_wrapper.validateAgainst(wrapper_input);
    const pending_root = fieldDigest(2001);
    const pending = try wrapper_program.bindPendingPreprocessedCommitment(
        &compiled_wrapper,
        wrapper_input,
        pending_root,
    );
    try pending.validateAgainst(&compiled_wrapper, wrapper_input, pending_root);
    try std.testing.expectError(
        error.ProviderWrapperFreshVerifierUnavailable,
        pending.requireFreshVerifierMint(),
    );

    compiled_wrapper.children[0].first_call += 1;
    try wrapper_program.testing.reseal(&compiled_wrapper);
    try compiled_wrapper.validate();
    try std.testing.expectError(
        error.ProviderWrapperCompilerAuthorityMismatch,
        compiled_wrapper.validateAgainst(wrapper_input),
    );
    compiled_wrapper.children[0].first_call -= 1;
    try wrapper_program.testing.reseal(&compiled_wrapper);
    try compiled_wrapper.validateAgainst(wrapper_input);

    var root_mutation = pending_root;
    root_mutation[0] +%= 1;
    try std.testing.expectError(
        error.ProviderWrapperPreprocessedBindingMismatch,
        pending.validateAgainst(&compiled_wrapper, wrapper_input, root_mutation),
    );

    std.mem.swap(
        wrapper_program.ChildProgramInputV1,
        &program_inputs[0],
        &program_inputs[1],
    );
    try std.testing.expectError(
        error.InvalidProviderWrapperCompilerInput,
        wrapper_program.compile(allocator, wrapper_input),
    );
    std.mem.swap(
        wrapper_program.ChildProgramInputV1,
        &program_inputs[0],
        &program_inputs[1],
    );

    var short_input = input;
    short_input.children = children[0 .. children.len - 1];
    try std.testing.expectError(
        error.InvalidProviderWrapperManifest,
        subject.compileWrapperManifest(short_input),
    );
    std.mem.swap(subject.VerifiedWrapperChildV1, &children[0], &children[1]);
    defer std.mem.swap(
        subject.VerifiedWrapperChildV1,
        &children[0],
        &children[1],
    );
    try std.testing.expectError(
        error.InvalidProviderWrapperManifest,
        subject.compileWrapperManifest(input),
    );
}

fn freshInput(
    program: *const program_mod.ProviderShardCompositionProgramV1,
    compiler_input: program_mod.CompilerInputV1,
    relation: provider_authority.PoseidonRelationContextV1,
    ordinal: u32,
) !subject.FreshVerifierInputV1 {
    const descriptor = compiler_input.plan.shards[ordinal];
    const first: usize = @intCast(descriptor.first_call);
    const count: usize = @intCast(descriptor.call_count);
    var relations = relations_mod.Relations.dummy();
    relations.poseidon2 = relations_mod.RelationElements(16).init(
        relation.z,
        relation.alpha,
    );
    const ordered_claim = try provider_order.expectedClaim(
        descriptor.first_call,
        compiler_input.calls[first .. first + count],
        &relations,
    );
    const claims = poseidon2_air.Claims{ .sums = .{
        QM31.fromU32Unchecked(ordinal + 1, ordinal + 2, 0, 0),
        QM31.fromU32Unchecked(ordinal + 3, ordinal + 4, 0, 0),
    } };
    var statement = proof_authority.ProviderStatementV2{
        .format = proof_authority.provider_format_version_v2,
        .plan_identity = compiler_input.plan.identity,
        .manifest_identity = shaDigest(0x81),
        .stage_a_identity = shaDigest(0x82 +% @as(u8, @intCast(ordinal))),
        .descriptor_identity = descriptor.identity,
        .relation_context_identity = relation.identity,
        .call_list_commitment = compiler_input.plan.call_list_commitment,
        .shard_index = ordinal,
        .first_call = descriptor.first_call,
        .call_count = descriptor.call_count,
        .log_size = descriptor.expected_log_size,
        .tree2_geometry = try proof_authority.ProviderTree2GeometryV2.canonical(
            descriptor.expected_log_size,
        ),
        .claims = claims,
        .ordered_call_claim = ordered_claim,
        .identity = undefined,
    };
    statement.identity = proof_authority.providerStatementIdentityV2(statement);
    const native_claim = provider_authority.ProviderShardClaimV1{
        .plan_identity = compiler_input.plan.identity,
        .descriptor_identity = descriptor.identity,
        .shard_index = ordinal,
        .relation_context_identity = relation.identity,
        .claims = claims,
    };
    var fresh_claim = proof_authority.FreshProviderClaimV2{
        .format = proof_authority.provider_format_version_v2,
        .manifest_identity = statement.manifest_identity,
        .statement_identity = statement.identity,
        .proof_commitments_identity = shaDigest(
            0x91 +% @as(u8, @intCast(ordinal)),
        ),
        .fresh_provider_stark_verified = true,
        .ordered_call_air_verified = true,
        .ordered_call_claim_recomputed = true,
        .native_claim = native_claim,
        .ordered_call_claim = ordered_claim,
        .identity = undefined,
    };
    fresh_claim.identity = proof_authority.providerClaimIdentityV2(fresh_claim);
    const root_seed = 1000 + 100 * ordinal;
    return .{
        .program = program,
        .compiler_input = compiler_input,
        .statement = statement,
        .fresh_claim = fresh_claim,
        .relation = relation,
        .roots = .{
            .preprocessed_commitment_root = fieldDigest(root_seed + 1),
            .main_commitment_root = fieldDigest(root_seed + 21),
            .interaction_commitment_root = fieldDigest(root_seed + 41),
            .composition_commitment_root = fieldDigest(root_seed + 61),
        },
    };
}

fn providerCalls(
    allocator: std.mem.Allocator,
    count: usize,
) ![]poseidon2_air.Call {
    const result = try allocator.alloc(poseidon2_air.Call, count);
    for (result, 0..) |*call, index| call.* =
        poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    return result;
}

fn providerResidencyRequest(count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(count),
        .column_count = provider_authority.main_column_count,
        .min_shard_log_size = 4,
        .max_shard_log_size = 4,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}

fn shaDigest(seed: u8) provider_authority.Digest {
    var result: provider_authority.Digest = undefined;
    for (&result, 0..) |*value, index| value.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn fieldDigest(seed: u32) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*value, index| value.* = seed + @as(u32, @intCast(index));
    return result;
}
