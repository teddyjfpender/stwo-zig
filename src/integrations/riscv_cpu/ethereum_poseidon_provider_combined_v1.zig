//! First runnable, create-only provider-free Ethereum SegmentV2 proof route.
//!
//! `capture-calls` preserves the existing authenticated call capture.  One
//! `prove-combined` invocation then reexecutes the retained segment, commits
//! provider Stage A without a synthetic core, proves and cold-verifies the
//! physically provider-free Ethereum core, proves and cold-verifies every
//! ordered provider shard, and publishes a sealed nonproduction closure last.
//! The independent provider API takes an explicit ordinal; a later command
//! split may schedule those raw proofs concurrently without changing bytes.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const fused = @import("ethereum_poseidon_provider_fused_v1.zig");
const legacy = @import("ethereum_poseidon_provider_orchestration_v1.zig");
const prepared_capture = @import("ethereum_poseidon_provider_prepared_capture_v1.zig");
const provider_artifact = @import("ethereum_poseidon_provider_proof_artifact_v2.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const omit_protocol = frontend.prover_mod.ethereum_native_provider_omit_protocol_v1;
const omit_proof = frontend.prover_mod.ethereum_native_provider_omit_proof_v1;
const lookup = frontend.air.lookup_physical_manifest_v2;
const Engine = support.RecursiveEngine;

pub const command_name = "ethereum-poseidon-provider-combined";
pub const result_schema =
    "stwo.ethereum.poseidon-provider-combined-result.v1";
pub const checkpoint_schema =
    "stwo.ethereum.poseidon-provider-combined-checkpoint.v1";
pub const status = "fresh-verified-closure-nonproduction";

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    if (arguments.len == 0) return error.MissingProviderPhase;
    if (std.mem.eql(u8, arguments[0], "capture-calls"))
        return legacy.run(allocator, arguments);
    if (std.mem.eql(u8, arguments[0], "prove-fused"))
        return fused.run(allocator, arguments[1..], provePreparedSegment);
    if (!std.mem.eql(u8, arguments[0], "prove-combined"))
        return error.UnsupportedProviderPhase;
    var options = try Options.parseAndResolve(allocator, arguments[1..]);
    defer options.deinit(allocator);
    try artifact_io.createDirectoryCreateOnly(options.output_root);
    var opened = try legacy.OpenedCallAuthority.open(
        allocator,
        options.call_artifact,
    );
    defer opened.deinit(allocator);
    try reexecuteAndProve(allocator, options.output_root, &opened);
}

const Options = struct {
    call_artifact: []u8,
    output_root: []u8,

    fn parseAndResolve(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        if (arguments.len != 4) return error.InvalidArguments;
        var call_artifact: ?[]const u8 = null;
        var output_root: ?[]const u8 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--call-artifact")) {
                if (call_artifact != null) return error.DuplicateArgument;
                call_artifact = value;
            } else if (std.mem.eql(u8, name, "--output-root")) {
                if (output_root != null) return error.DuplicateArgument;
                output_root = value;
            } else return error.InvalidArguments;
        }
        const resolved_calls = try artifact_io.resolveAbsolute(
            allocator,
            call_artifact orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_calls);
        const resolved_output = try artifact_io.resolveAbsolute(
            allocator,
            output_root orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_output);
        if (std.mem.eql(u8, resolved_calls, resolved_output))
            return error.DuplicateProviderOrchestrationPath;
        return .{
            .call_artifact = resolved_calls,
            .output_root = resolved_output,
        };
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.call_artifact);
        allocator.free(self.output_root);
        self.* = undefined;
    }
};

fn reexecuteAndProve(
    allocator: std.mem.Allocator,
    output_root: []const u8,
    opened: *const legacy.OpenedCallAuthority,
) !void {
    var source_authority = try @import("ethereum_poseidon_leaf_product_support.zig")
        .openAuthority(allocator, &opened.request.value);
    defer source_authority.deinit();
    const source = &source_authority.source.value;
    const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
    const elf = try support.readIdentity(
        allocator,
        source.elf,
        product_support.max_elf_bytes,
    );
    defer allocator.free(elf);
    const input = try support.readIdentity(
        allocator,
        source.input,
        product_support.max_input_bytes,
    );
    defer allocator.free(input);
    const expected_output = try support.readIdentity(
        allocator,
        source.expected_output,
        product_support.max_output_bytes,
    );
    defer allocator.free(expected_output);
    var session = try frontend.runner.EthereumExecutionSession.init(
        allocator,
        elf,
        .{
            .input = input,
            .stop_on_halt_flag = true,
            .strict_completion = true,
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
        },
    );
    defer session.deinit();
    var continuation: ?frontend.runner.result_mod.ContinuationToken = null;
    var position: u32 = 0;
    while (position <= opened.request.value.segment_index) : (position += 1) {
        var segment = if (position == 0)
            try session.startSegment(source.segment_step_budget)
        else
            try session.resumeSegment(
                continuation orelse return error.MissingContinuation,
                source.segment_step_budget,
            );
        defer segment.deinit();
        if (segment.base.segment_index != position)
            return error.ExecutionSegmentOrderMismatch;
        const complete = segment.base.isComplete();
        if (complete != (position + 1 == source.segment_count))
            return error.ExecutionCompletionMismatch;
        if (complete) {
            const output = segment.base.output orelse return error.MissingOutput;
            if (!std.mem.eql(u8, output, expected_output))
                return error.PublicOutputMismatch;
        }
        if (position == opened.request.value.segment_index) {
            try proveSegment(
                allocator,
                output_root,
                opened,
                &source_authority.expected,
                &segment,
            );
            return;
        }
        continuation = segment.base.continuation;
        if (continuation == null) return error.MissingContinuation;
    }
    unreachable;
}

fn proveSegment(
    allocator: std.mem.Allocator,
    output_root: []const u8,
    opened: *const legacy.OpenedCallAuthority,
    expected: *const support.source_wire.Source,
    segment: *const frontend.runner.EthereumSegmentResult,
) !void {
    var preparation = try prepared_capture.prepare(
        allocator,
        expected,
        segment,
        try contract.parseSha256(opened.request.value.session_id),
    );
    defer preparation.deinit();
    return provePreparedSegment(
        allocator,
        output_root,
        opened,
        expected,
        segment,
        &preparation.prepared,
    );
}

fn provePreparedSegment(
    allocator: std.mem.Allocator,
    output_root: []const u8,
    opened: *const legacy.OpenedCallAuthority,
    expected: *const support.source_wire.Source,
    segment: *const frontend.runner.EthereumSegmentResult,
    prepared: *const prepared_capture.PreparedSegmentV1,
) !void {
    try prepared.validateAgainst(
        expected,
        segment,
        try contract.parseSha256(opened.request.value.session_id),
    );
    const projection = &prepared.projection;
    const calls = prepared.calls.calls;
    const public = prepared.public_data;
    prepared_capture.requireCallCustodyParity(
        calls,
        opened.calls.calls,
        prepared.call_list_commitment,
        opened.plan.call_list_commitment,
        prepared.calls.public_data_wire_id,
        opened.calls.public_data_wire_id,
    ) catch return error.ReexecutedProviderCallsMismatch;

    const roots = try allocator.alloc(
        harness.StageACommitment(Engine),
        opened.plan.shards.len,
    );
    defer allocator.free(roots);
    for (roots, 0..) |*root, index|
        root.* = try harness.commitStageA(
            Engine,
            allocator,
            support.recursive_pcs_config,
            &opened.plan,
            calls,
            @intCast(index),
        );
    var owned_stage_a = try omit_protocol.ProviderStageAManifestV1(Engine)
        .createFromRoots(allocator, &opened.plan, calls, roots);
    defer owned_stage_a.deinit(allocator);
    const provider_stage_a = &owned_stage_a.manifest;

    var prove_extension = try omit_protocol.Extension(Engine).init(
        &opened.plan,
        calls,
        provider_stage_a,
    );
    var prove_channel = Engine.Channel{};
    var core_clock = try evidence.Clock.start();
    var core_output = try support.prover
        .proveEthereumSegmentWithEngineUsingChannelAndExecutionAndNativeProviderOmission(
        Engine,
        allocator,
        support.recursive_pcs_config,
        &projection.local_result,
        &segment.keccakf_calls,
        &segment.keccakf_execution_rows,
        &segment.signer_recovery_calls,
        &segment.signer_recovery_execution_rows,
        null,
        public,
        &prove_channel,
        support.executionOptions(),
        &prove_extension,
    );
    var core_proof_owned = true;
    defer if (core_proof_owned)
        core_output.deinit(allocator)
    else
        core_output.deinitAfterProofMoved(allocator);
    const core_prove_timing = try core_clock.finish();
    const projected = try prove_extension.providerProjection();
    const shared = prove_extension.shared_relation orelse
        return error.MissingEthereumProviderSharedAuthority;

    const core_path = try outputPath(allocator, output_root, "core-proof.stw");
    defer allocator.free(core_path);
    const encoded_core = try support.recursive_artifact.encodeAllocWithLimits(
        allocator,
        .{
            .security_identity_sha256 = support.recursive_security_identity,
            .statement = &projected.projected_native,
            .extension = &core_output.extension,
            .global = &expected.metadata,
            .base_claim = core_output.base_claim,
            .extension_claim = &core_output.extension_claim,
            .proof = &core_output.proof,
        },
        support.artifact_limits,
    );
    defer allocator.free(encoded_core);
    try artifact_io.publishCreateOnlyDurable(core_path, encoded_core);
    const core_file = evidence.identity(core_path, encoded_core);
    core_output.proof.deinit(allocator);
    core_proof_owned = false;

    var decoded = try support.recursive_artifact.decodeAlloc(
        allocator,
        encoded_core,
        support.recursive_security_identity,
        support.artifact_limits,
    );
    var decoded_proof_owned = true;
    defer if (decoded_proof_owned)
        decoded.deinit(allocator)
    else
        decoded.deinitAfterProofMoved(allocator);
    if (!std.meta.eql(decoded.statement, projected.projected_native) or
        !std.meta.eql(decoded.extension, core_output.extension) or
        !std.meta.eql(decoded.global, expected.metadata))
    {
        return error.OmittedCoreArtifactAuthorityMismatch;
    }
    var verify_extension = try omit_protocol.Extension(Engine).initForFreshVerify(
        &opened.plan,
        calls,
        provider_stage_a,
        shared,
    );
    var verify_channel = Engine.Channel{};
    var core_verify_clock = try evidence.Clock.start();
    decoded_proof_owned = false;
    try support.prover
        .verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmission(
        Engine,
        allocator,
        support.recursive_pcs_config,
        core_output.statement,
        core_output.extension,
        decoded.proof,
        decoded.base_claim,
        &decoded.extension_claim,
        &verify_channel,
        &verify_extension,
    );
    const core_verify_timing = try core_verify_clock.finish();
    const fresh_core = verify_extension.fresh_core orelse
        return error.MissingEthereumProviderFreshCore;
    const verified_projection = try verify_extension.providerProjection();
    var lookup_manifest = lookup.Manifest.native();
    const authenticated = try lookup.AuthenticatedStatement.init(
        &core_output.statement.core,
        &lookup_manifest,
    );
    const provider_source = omit_proof.Source(Engine){
        .native = &core_output.statement,
        .extension = &core_output.extension,
        .lookup_manifest = &lookup_manifest,
        .authenticated_lookup = &authenticated,
        .projection = verified_projection,
        .plan = &opened.plan,
        .calls = calls,
        .provider_stage_a = provider_stage_a,
        .shared = verify_extension.shared_relation orelse
            return error.MissingEthereumProviderSharedAuthority,
    };
    try proveProvidersAndClose(
        allocator,
        output_root,
        opened,
        provider_source,
        fresh_core,
        core_file,
        core_prove_timing,
        core_verify_timing,
    );
}

const CheckpointUnsigned = struct {
    call_artifact: contract.Identity,
    executable_sha256: []const u8,
    fresh_core_identity_sha256: []const u8,
    interaction_pow: u64,
    interaction_pow_bits: u32,
    manifest_identity_sha256: []const u8,
    plan_identity_sha256: []const u8,
    production_eligible: bool,
    projection_identity_sha256: []const u8,
    providers: []const ProviderStageARecord,
    recursive_admissible: bool,
    relation_alpha_m31: [4]u32,
    relation_context_identity_sha256: []const u8,
    relation_z_m31: [4]u32,
    resource_plan_identity_sha256: []const u8,
    schema: []const u8,
    shard_count: u32,
    shared_relation_identity_sha256: []const u8,
    status: []const u8,
    tree0_root_m31: [8]u32,
    tree1_root_m31: [8]u32,
};

const ProviderStageARecord = struct {
    call_count: u32,
    descriptor_identity_sha256: []const u8,
    first_call: u64,
    identity_sha256: []const u8,
    log_size: u32,
    main_root_m31: [8]u32,
    preprocessed_root_m31: [8]u32,
    shard_index: u32,
};

const ProviderResult = struct {
    artifact: contract.Identity,
    claim_identity_sha256: []const u8,
    ordered_call_air_verified: bool,
    proof: contract.Identity,
    shard_index: u32,
    statement_identity_sha256: []const u8,
    verify_timing: evidence.Timing,
};

const ResultUnsigned = struct {
    call_artifact: contract.Identity,
    checkpoint: contract.Identity,
    closed_sum_m31: [4]u32,
    closure_identity_sha256: []const u8,
    core_proof: contract.Identity,
    core_prove_timing: evidence.Timing,
    core_verify_timing: evidence.Timing,
    every_proof_freshly_verified: bool,
    executable_sha256: []const u8,
    omit_recompute_owner_verified: bool,
    production_eligible: bool,
    providers: []const ProviderResult,
    recursive_admissible: bool,
    schema: []const u8,
    shard_count: u32,
    status: []const u8,
};

fn proveProvidersAndClose(
    allocator: std.mem.Allocator,
    output_root: []const u8,
    opened: *const legacy.OpenedCallAuthority,
    source: omit_proof.Source(Engine),
    fresh_core: omit_protocol.FreshCoreResidualV1,
    core_file: evidence.FileIdentity,
    core_prove_timing: evidence.Timing,
    core_verify_timing: evidence.Timing,
) !void {
    const executable_sha256 = opened.executable_sha256;
    const checkpoint_path = try outputPath(
        allocator,
        output_root,
        "checkpoint.json",
    );
    defer allocator.free(checkpoint_path);
    const checkpoint_bytes = try encodeCheckpoint(
        allocator,
        opened,
        source,
        fresh_core,
    );
    defer allocator.free(checkpoint_bytes);
    try artifact_io.publishCreateOnlyDurable(checkpoint_path, checkpoint_bytes);
    const checkpoint_file = evidence.identity(checkpoint_path, checkpoint_bytes);
    const checkpoint_content = try sealedContentSha256(checkpoint_bytes);

    const fresh = try allocator.alloc(
        omit_proof.FreshProviderClaimV2,
        source.plan.shards.len,
    );
    defer allocator.free(fresh);
    const results = try allocator.alloc(ProviderResult, source.plan.shards.len);
    defer allocator.free(results);
    var initialized: usize = 0;
    defer for (results[0..initialized]) |record| {
        allocator.free(record.artifact.path);
        allocator.free(record.artifact.sha256);
        allocator.free(record.proof.path);
        allocator.free(record.proof.sha256);
        allocator.free(record.claim_identity_sha256);
        allocator.free(record.statement_identity_sha256);
    };

    for (source.plan.shards, 0..) |_, index| {
        const proof_name = try std.fmt.allocPrint(
            allocator,
            "provider-{d:0>3}-proof.stw",
            .{index},
        );
        defer allocator.free(proof_name);
        const artifact_name = try std.fmt.allocPrint(
            allocator,
            "provider-{d:0>3}-artifact.json",
            .{index},
        );
        defer allocator.free(artifact_name);
        const proof_path = try outputPath(allocator, output_root, proof_name);
        defer allocator.free(proof_path);
        const metadata_path = try outputPath(
            allocator,
            output_root,
            artifact_name,
        );
        defer allocator.free(metadata_path);

        var prove_clock = try evidence.Clock.start();
        var output = try omit_proof.proveProviderV2(
            Engine,
            allocator,
            support.recursive_pcs_config,
            source,
            @intCast(index),
        );
        var proof_owned = true;
        defer if (proof_owned) output.proof.deinit(allocator);
        const prove_timing = try prove_clock.finish();
        const shape = try provider_artifact.proofShape(output.statement);
        const proof_bytes = try provider_artifact.serializeProofAlloc(
            allocator,
            output.proof,
            shape,
        );
        defer allocator.free(proof_bytes);
        try artifact_io.publishCreateOnlyDurable(proof_path, proof_bytes);
        const proof_file = evidence.identity(proof_path, proof_bytes);
        const artifact_bytes = try provider_artifact.encode(
            allocator,
            .{
                .producer_sha256 = executable_sha256,
                .proof = proof_file,
                .prove_timing = prove_timing,
                .resource_plan_identity = opened.resource_plan.identity,
                .stage_a_checkpoint = checkpoint_file,
                .stage_a_checkpoint_content_sha256 = checkpoint_content,
            },
            output.statement,
        );
        defer allocator.free(artifact_bytes);
        try provider_artifact.publishCreateOnly(metadata_path, artifact_bytes);
        const artifact_file = evidence.identity(metadata_path, artifact_bytes);

        output.proof.deinit(allocator);
        proof_owned = false;
        var decoded_proof = try provider_artifact.deserializeProof(
            allocator,
            proof_bytes,
            shape,
        );
        var decoded_owned = true;
        errdefer if (decoded_owned) decoded_proof.deinit(allocator);
        var verify_clock = try evidence.Clock.start();
        decoded_owned = false;
        fresh[index] = try omit_proof.verifyProviderFreshV2(
            Engine,
            allocator,
            support.recursive_pcs_config,
            source,
            output.statement,
            decoded_proof,
        );
        const verify_timing = try verify_clock.finish();
        results[index] = .{
            .artifact = try ownedIdentity(allocator, artifact_file),
            .claim_identity_sha256 = try hexAlloc(
                allocator,
                fresh[index].identity,
            ),
            .ordered_call_air_verified = fresh[index].ordered_call_air_verified and
                fresh[index].ordered_call_claim_recomputed,
            .proof = try ownedIdentity(allocator, proof_file),
            .shard_index = @intCast(index),
            .statement_identity_sha256 = try hexAlloc(
                allocator,
                output.statement.identity,
            ),
            .verify_timing = verify_timing,
        };
        initialized += 1;
    }

    const closure = try omit_proof.closeFreshClaimsV1(
        allocator,
        source,
        fresh_core,
        fresh,
    );
    const result_path = try outputPath(allocator, output_root, "result.json");
    defer allocator.free(result_path);
    const result_bytes = try encodeResult(
        allocator,
        opened,
        checkpoint_file,
        core_file,
        core_prove_timing,
        core_verify_timing,
        results,
        closure,
    );
    defer allocator.free(result_bytes);
    try artifact_io.publishCreateOnlyDurable(result_path, result_bytes);
}

fn encodeCheckpoint(
    allocator: std.mem.Allocator,
    opened: *const legacy.OpenedCallAuthority,
    source: omit_proof.Source(Engine),
    fresh_core: omit_protocol.FreshCoreResidualV1,
) ![]u8 {
    const provider_records = try allocator.alloc(
        ProviderStageARecord,
        source.provider_stage_a.providers.len,
    );
    defer allocator.free(provider_records);
    const provider_hex = try allocator.alloc(
        struct { descriptor: [64]u8, identity: [64]u8 },
        provider_records.len,
    );
    defer allocator.free(provider_hex);
    for (
        source.provider_stage_a.providers,
        provider_hex,
        provider_records,
    ) |record, *storage, *wire| {
        storage.* = .{
            .descriptor = hex(record.descriptor_identity),
            .identity = hex(record.identity),
        };
        wire.* = .{
            .call_count = record.call_count,
            .descriptor_identity_sha256 = &storage.descriptor,
            .first_call = record.first_call,
            .identity_sha256 = &storage.identity,
            .log_size = record.expected_log_size,
            .main_root_m31 = rootWords(record.main_root),
            .preprocessed_root_m31 = rootWords(record.preprocessed_root),
            .shard_index = record.shard_index,
        };
    }
    const call_sha = hex(opened.artifact_file.sha256);
    const executable = hex(opened.executable_sha256);
    const fresh_core_id = hex(fresh_core.identity);
    const manifest_id = hex(source.provider_stage_a.identity);
    const plan_id = hex(source.plan.identity);
    const projection_id = hex(source.projection.identity);
    const relation_id = hex(source.shared.relation_context.identity);
    const resource_id = hex(opened.resource_plan.identity);
    const shared_id = hex(source.shared.identity);
    const value = CheckpointUnsigned{
        .call_artifact = .{
            .bytes = opened.artifact_file.bytes,
            .path = opened.artifact_file.path,
            .sha256 = &call_sha,
        },
        .executable_sha256 = &executable,
        .fresh_core_identity_sha256 = &fresh_core_id,
        .interaction_pow = source.shared.interaction_pow,
        .interaction_pow_bits = source.shared.interaction_pow_bits,
        .manifest_identity_sha256 = &manifest_id,
        .plan_identity_sha256 = &plan_id,
        .production_eligible = false,
        .projection_identity_sha256 = &projection_id,
        .providers = provider_records,
        .recursive_admissible = false,
        .relation_alpha_m31 = qm31Words(source.shared.relation_context.alpha),
        .relation_context_identity_sha256 = &relation_id,
        .relation_z_m31 = qm31Words(source.shared.relation_context.z),
        .resource_plan_identity_sha256 = &resource_id,
        .schema = checkpoint_schema,
        .shard_count = source.plan.shard_count,
        .shared_relation_identity_sha256 = &shared_id,
        .status = "fresh-core-verified-provider-stage-a-complete",
        .tree0_root_m31 = rootWords(source.shared.tree0_root),
        .tree1_root_m31 = rootWords(source.shared.tree1_root),
    };
    return sealValue(allocator, value);
}

fn encodeResult(
    allocator: std.mem.Allocator,
    opened: *const legacy.OpenedCallAuthority,
    checkpoint: evidence.FileIdentity,
    core_proof: evidence.FileIdentity,
    core_prove_timing: evidence.Timing,
    core_verify_timing: evidence.Timing,
    providers: []const ProviderResult,
    closure: omit_protocol.VerifiedJointClosureV1,
) ![]u8 {
    try closure.validate();
    const call_sha = hex(opened.artifact_file.sha256);
    const checkpoint_sha = hex(checkpoint.sha256);
    const core_sha = hex(core_proof.sha256);
    const closure_id = hex(closure.identity);
    const executable = hex(opened.executable_sha256);
    const value = ResultUnsigned{
        .call_artifact = .{
            .bytes = opened.artifact_file.bytes,
            .path = opened.artifact_file.path,
            .sha256 = &call_sha,
        },
        .checkpoint = .{
            .bytes = checkpoint.bytes,
            .path = checkpoint.path,
            .sha256 = &checkpoint_sha,
        },
        .closed_sum_m31 = qm31Words(closure.closed_sum),
        .closure_identity_sha256 = &closure_id,
        .core_proof = .{
            .bytes = core_proof.bytes,
            .path = core_proof.path,
            .sha256 = &core_sha,
        },
        .core_prove_timing = core_prove_timing,
        .core_verify_timing = core_verify_timing,
        .every_proof_freshly_verified = true,
        .executable_sha256 = &executable,
        .omit_recompute_owner_verified = true,
        .production_eligible = false,
        .providers = providers,
        .recursive_admissible = false,
        .schema = result_schema,
        .shard_count = closure.shard_count,
        .status = status,
    };
    return sealValue(allocator, value);
}

fn sealValue(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const unsigned = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(unsigned);
    return evidence.seal(allocator, unsigned);
}

fn sealedContentSha256(bytes: []const u8) ![32]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix) or bytes.len < prefix.len + 64)
        return error.InvalidSealedProviderCheckpoint;
    return contract.parseSha256(bytes[prefix.len .. prefix.len + 64]);
}

fn outputPath(
    allocator: std.mem.Allocator,
    root: []const u8,
    basename: []const u8,
) ![]u8 {
    if (!std.mem.eql(u8, basename, std.fs.path.basename(basename)))
        return error.InvalidOutputPath;
    return std.fs.path.join(allocator, &.{ root, basename });
}

fn ownedIdentity(
    allocator: std.mem.Allocator,
    source: evidence.FileIdentity,
) !contract.Identity {
    const path = try allocator.dupe(u8, source.path);
    errdefer allocator.free(path);
    return .{
        .bytes = source.bytes,
        .path = path,
        .sha256 = try hexAlloc(allocator, source.sha256),
    };
}

fn hexAlloc(allocator: std.mem.Allocator, value: [32]u8) ![]u8 {
    const result = try allocator.alloc(u8, 64);
    _ = std.fmt.bufPrint(result, "{s}", .{&hex(value)}) catch unreachable;
    return result;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

fn rootWords(value: Engine.Hasher.Hash) [8]u32 {
    if (@TypeOf(value) != [8]u32)
        @compileError("combined provider receipt hash width drifted");
    return value;
}

fn qm31Words(value: @import("stwo_core").fields.qm31.QM31) [4]u32 {
    var result: [4]u32 = undefined;
    for (value.toM31Array(), &result) |word, *destination|
        destination.* = word.toU32();
    return result;
}

comptime {
    if (omit_proof.ACTIVATES_PRODUCTION_PROOF or
        omit_proof.RECURSIVE_VERIFICATION_IMPLEMENTED)
    {
        @compileError("combined provider-free route must remain nonproduction");
    }
}

pub const testing = struct {
    pub fn options(allocator: std.mem.Allocator) !void {
        var parsed = try Options.parseAndResolve(allocator, &.{
            "--output-root",
            "relative/out",
            "--call-artifact",
            "relative/calls.json",
        });
        defer parsed.deinit(allocator);
        try std.testing.expect(std.fs.path.isAbsolute(parsed.output_root));
        try std.testing.expect(std.fs.path.isAbsolute(parsed.call_artifact));
    }
};
