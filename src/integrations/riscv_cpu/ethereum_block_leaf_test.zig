const std = @import("std");
const contract = @import("ethereum_block_leaf_contract.zig");
const materializer = @import("ethereum_block_leaf_materializer.zig");
const poseidon_contract = @import("ethereum_poseidon_leaf_product_contract.zig");
const poseidon_producer = @import("ethereum_poseidon_leaf_product_producer.zig");
const poseidon_request = @import("ethereum_poseidon_leaf_product_request.zig");
const poseidon_verifier = @import("ethereum_poseidon_leaf_product_verifier.zig");
const producer = @import("ethereum_block_leaf_producer.zig");
const verifier = @import("ethereum_block_leaf_verifier.zig");
const frontend = @import("stwo_riscv_frontend");

test "streamed leaf entrypoints fail closed before filesystem access" {
    try std.testing.expectError(
        error.InvalidArguments,
        materializer.run(std.testing.allocator, &.{}),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        producer.run(std.testing.allocator, &.{}),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        verifier.run(std.testing.allocator, &.{}),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        poseidon_producer.run(std.testing.allocator, &.{}),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        poseidon_request.run(std.testing.allocator, &.{}),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        poseidon_verifier.run(std.testing.allocator, &.{}),
    );
}

test "source request V1 canonical shape and secure authority are exact" {
    const allocator = std.testing.allocator;
    const profile = std.fmt.bytesToHex(
        frontend.isa.execution_profile.ethereum_semantic_digest,
        .lower,
    );
    const value = contract.SourceRequest{
        .clock_frame = contract.clock_frame,
        .elf = identity("/retained/guest.elf", 'a'),
        .execution_journal = identity("/retained/execution.ndjson", 'b'),
        .execution_profile = contract.profile_name,
        .expected_output = identity("/retained/output.bin", 'c'),
        .input = emptyIdentity(),
        .pcs = .{
            .commitment_hash = "Blake2s",
            .field = "M31",
            .fold_step = 1,
            .lifting_log_size = null,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 70,
            .pow_bits = 26,
            .transcript_hash = "Blake2s",
        },
        .profile_abi_version = 1,
        .profile_semantic_digest = &profile,
        .profile_wire_id = 3,
        .schema = contract.source_schema,
        .segment_authority_magic = contract.segment_magic,
        .segment_authority_version = 1,
        .segment_count = 210,
        .segment_step_budget = 4_194_304,
        .strict_completion = true,
    };
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(raw);
    const canonical = try std.fmt.allocPrint(allocator, "{s}\n", .{raw});
    defer allocator.free(canonical);
    var parsed = try contract.parseSource(allocator, canonical);
    defer parsed.deinit();
    try std.testing.expectEqual(
        contract.SourceKind.native_blake2s_v1,
        try contract.sourceKind(allocator, canonical),
    );
    try std.testing.expectEqual(@as(u32, 210), parsed.value.segment_count);
    try std.testing.expectEqual(@as(u64, 0), parsed.value.input.bytes);
    try std.testing.expectEqualStrings(
        "/retained/input.bin",
        parsed.value.input.path,
    );
    try std.testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        parsed.value.input.sha256,
    );
    try std.testing.expectEqualStrings(
        contract.segment_magic,
        parsed.value.segment_authority_magic,
    );

    var mutated = try allocator.dupe(u8, canonical);
    defer allocator.free(mutated);
    const needle = "\"profile_wire_id\":3";
    const at = std.mem.indexOf(u8, mutated, needle) orelse unreachable;
    mutated[at + needle.len - 1] = '2';
    try std.testing.expectError(
        error.SourceAuthorityMismatch,
        contract.parseSource(allocator, mutated),
    );
}

test "recursive source V2 binds security and dynamic verifier descriptor policy" {
    const allocator = std.testing.allocator;
    const profile = std.fmt.bytesToHex(
        frontend.isa.execution_profile.ethereum_semantic_digest,
        .lower,
    );
    const value = recursiveSource(&profile);
    const raw = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(raw);
    const canonical = try std.fmt.allocPrint(allocator, "{s}\n", .{raw});
    defer allocator.free(canonical);
    var parsed = try contract.parseRecursiveSource(allocator, canonical);
    defer parsed.deinit();
    try std.testing.expectEqual(
        contract.SourceKind.recursive_poseidon2_v2,
        try contract.sourceKind(allocator, canonical),
    );
    try std.testing.expectEqual(
        @as(u16, 14),
        parsed.value.proof_policy.extension_component_count,
    );
    try std.testing.expectEqual(@as(u64, 0), parsed.value.input.bytes);

    var mutated = try allocator.dupe(u8, canonical);
    defer allocator.free(mutated);
    const needle = "\"extension_component_count\":14";
    const at = std.mem.indexOf(u8, mutated, needle) orelse unreachable;
    mutated[at + needle.len - 1] = '2';
    try std.testing.expectError(
        error.RecursiveProofProfileMismatch,
        contract.parseRecursiveSource(allocator, mutated),
    );

    const policy_mutated = try allocator.dupe(u8, canonical);
    defer allocator.free(policy_mutated);
    const policy_needle = "fresh-verifier-minted-dynamic-child-v1";
    const policy_at = std.mem.indexOf(u8, policy_mutated, policy_needle) orelse
        unreachable;
    policy_mutated[policy_at] = 'x';
    try std.testing.expectError(
        error.RecursiveProofProfileMismatch,
        contract.parseRecursiveSource(allocator, policy_mutated),
    );
}

test "materializer admits recursive policy before retained input custody" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const elf = try std.fs.path.join(allocator, &.{ root, "guest.elf" });
    defer allocator.free(elf);
    const output = try std.fs.path.join(allocator, &.{ root, "output.bin" });
    defer allocator.free(output);
    const input = try std.fs.path.join(allocator, &.{ root, "input.bin" });
    defer allocator.free(input);
    const journal = try std.fs.path.join(allocator, &.{ root, "execution.ndjson" });
    defer allocator.free(journal);
    const result = try std.fs.path.join(allocator, &.{ root, "result.json" });
    defer allocator.free(result);
    const source_request = try std.fs.path.join(allocator, &.{ root, "source.json" });
    defer allocator.free(source_request);
    const arguments = [_][]const u8{
        "--elf",                 elf,
        "--expected-output",     output,
        "--input",               input,
        "--journal",             journal,
        "--proof-profile",       contract.recursive_proof_profile_name,
        "--result",              result,
        "--segment-count",       "210",
        "--segment-step-budget", "4194304",
        "--source-request",      source_request,
        "--source-root",         root,
    };
    try std.testing.expectError(
        error.FileNotFound,
        materializer.run(allocator, &arguments),
    );
}

test "exact input authority fits the authenticated ELF input region" {
    try materializer.requireInputFitsRegion(0x2000, 0x2004, 0);
    try materializer.requireInputFitsRegion(0x2000, 0x2004, 1);
    try materializer.requireInputFitsRegion(0x2000, 0x2004, 4);
    try std.testing.expectError(
        error.InputLayoutMismatch,
        materializer.requireInputFitsRegion(0x2000, 0x2004, 5),
    );
    try std.testing.expectError(
        error.InputLayoutMismatch,
        materializer.requireInputFitsRegion(0x2001, 0x2000, 0),
    );
    const overflow = std.math.cast(
        usize,
        @as(u64, std.math.maxInt(u32)) + 1,
    ) orelse return;
    try std.testing.expectError(
        error.InputLayoutMismatch,
        materializer.requireInputFitsRegion(0, std.math.maxInt(u32), overflow),
    );
}

test "Poseidon one-leaf contract stays explicitly pre-descriptor" {
    const allocator = std.testing.allocator;
    const sha = [_]u8{'a'} ** 64;
    const zero_m31 = [_]u8{'0'} ** 64;
    const request_bytes = try poseidon_contract.encodeRequest(allocator, .{
        .expected_recursive_statement_sha256 = &sha,
        .expected_source_public_statement_sha256 = &sha,
        .producer_sha256 = &sha,
        .segment_index = 0,
        .session_id = &sha,
        .source_request = .{
            .bytes = 1,
            .path = "/retained/source-v2.json",
            .schema = contract.recursive_source_schema,
            .sha256 = &sha,
        },
        .source_segment = identity("/retained/segment-000000.stwesg31", 'a'),
        .verifier_sha256 = &sha,
    });
    defer allocator.free(request_bytes);
    var request = try poseidon_contract.parseRequest(allocator, request_bytes);
    defer request.deinit();
    const producer_bytes = try poseidon_contract.encodeProducerResult(
        allocator,
        .{
            .producer_sha256 = &sha,
            .proof = identity("/retained/poseidon-v4-leaf.stw", 'a'),
            .prove_timing = .{ .system_ns = 1, .user_ns = 2, .wall_ns = 3 },
            .recursive_statement_sha256 = &sha,
            .request_sha256 = request.value.content_sha256,
            .root_sha256 = &sha,
            .security_identity_sha256 = &sha,
            .segment_index = 0,
            .source_public_statement_sha256 = &sha,
            .transcript_state_sha256 = &sha,
            .verified_capture_sha256 = &sha,
            .verified_link_id_m31_le = &zero_m31,
        },
    );
    defer allocator.free(producer_bytes);
    var producer_result = try poseidon_contract.parseProducerResult(
        allocator,
        producer_bytes,
    );
    defer producer_result.deinit();
    try std.testing.expect(!producer_result.value.recursive_admissible);
    const result_bytes = try poseidon_contract.encodeVerifierResult(allocator, .{
        .proof_bytes = 1,
        .proof_sha256 = &sha,
        .recursive_statement_sha256 = &sha,
        .request_sha256 = request.value.content_sha256,
        .root_sha256 = &sha,
        .security_identity_sha256 = &sha,
        .segment_index = 0,
        .source_public_statement_sha256 = &sha,
        .transcript_state_sha256 = &sha,
        .verified_capture_sha256 = &sha,
        .verified_link_id_m31_le = &zero_m31,
        .verifier_sha256 = &sha,
    });
    defer allocator.free(result_bytes);
    var result = try poseidon_contract.parseVerifierResult(
        allocator,
        result_bytes,
    );
    defer result.deinit();
    try std.testing.expect(!result.value.recursive_admissible);
    try std.testing.expectEqualStrings(
        poseidon_contract.descriptor_unavailable_status,
        result.value.descriptor_status,
    );
    const mutated = try allocator.dupe(u8, request_bytes);
    defer allocator.free(mutated);
    const content_prefix = "{\"content_sha256\":\"";
    mutated[content_prefix.len] = if (mutated[content_prefix.len] == '0')
        '1'
    else
        '0';
    try std.testing.expectError(
        error.InvalidContentSha256,
        poseidon_contract.parseRequest(allocator, mutated),
    );
    try std.testing.expectError(
        error.RequestAuthorityMismatch,
        poseidon_contract.encodeRequest(allocator, .{
            .expected_recursive_statement_sha256 = &sha,
            .expected_source_public_statement_sha256 = &sha,
            .producer_sha256 = &sha,
            .segment_index = 0,
            .session_id = &sha,
            .source_request = .{
                .bytes = 1,
                .path = "/retained/source-v2.json",
                .schema = contract.recursive_source_schema,
                .sha256 = &sha,
            },
            .source_segment = .{
                .bytes = 1,
                .path = "relative-source.stwesg31",
                .sha256 = &sha,
            },
            .verifier_sha256 = &sha,
        }),
    );

    try std.testing.expectError(
        error.VerifierResultMismatch,
        poseidon_contract.encodeVerifierResult(allocator, .{
            .proof_bytes = 1,
            .proof_sha256 = &sha,
            .recursive_admissible = true,
            .recursive_statement_sha256 = &sha,
            .request_sha256 = request.value.content_sha256,
            .root_sha256 = &sha,
            .security_identity_sha256 = &sha,
            .segment_index = 0,
            .source_public_statement_sha256 = &sha,
            .transcript_state_sha256 = &sha,
            .verified_capture_sha256 = &sha,
            .verified_link_id_m31_le = &zero_m31,
            .verifier_sha256 = &sha,
        }),
    );
}

fn recursiveSource(
    profile_semantic_digest: []const u8,
) contract.RecursiveSourceRequestV2 {
    return .{
        .clock_frame = contract.clock_frame,
        .elf = identity("/retained/guest.elf", 'a'),
        .execution_journal = identity("/retained/execution.ndjson", 'b'),
        .execution_profile = contract.profile_name,
        .expected_output = identity("/retained/output.bin", 'c'),
        .input = emptyIdentity(),
        .pcs = .{
            .commitment_hash = "Poseidon2-M31",
            .field = "M31",
            .fold_step = 4,
            .lifting_log_size = null,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 193,
            .pow_bits = 16,
            .transcript_hash = "Poseidon2-M31",
        },
        .profile_abi_version = 1,
        .profile_semantic_digest = profile_semantic_digest,
        .profile_wire_id = 3,
        .proof_policy = .{
            .configured_pcs_bits = 209,
            .conjectured_security_bits = 120,
            .descriptor_authority = contract.recursive_descriptor_authority,
            .execution_semantics_authority = contract.recursive_execution_semantics_authority,
            .extension_component_count = 14,
            .hash_suite = "Poseidon2-M31",
            .interaction_pow_bits = 10,
            .profile_name = contract.recursive_proof_profile_name,
            .proof_kind = contract.recursive_proof_kind,
            .recursive_ingress = contract.recursive_ingress,
            .security_identity_sha256 = contract.recursive_security_identity_sha256,
            .verifier_identity_authority = contract.recursive_verifier_identity_authority,
        },
        .schema = contract.recursive_source_schema,
        .segment_authority_magic = contract.segment_magic,
        .segment_authority_version = 1,
        .segment_count = 210,
        .segment_step_budget = 4_194_304,
        .strict_completion = true,
    };
}

fn identity(comptime path: []const u8, comptime byte: u8) contract.Identity {
    return .{
        .bytes = 1,
        .path = path,
        .sha256 = &([_]u8{byte} ** 64),
    };
}

fn emptyIdentity() contract.Identity {
    return .{
        .bytes = 0,
        .path = "/retained/input.bin",
        .sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    };
}
