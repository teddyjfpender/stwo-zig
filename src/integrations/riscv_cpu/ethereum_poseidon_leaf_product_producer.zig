//! Create-only producer for one expected Poseidon2-M31 SegmentV3 leaf.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prover_api = @import("stwo_prover_api");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const profile_receipt = @import("ethereum_poseidon_leaf_profile_receipt.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    return runUsingExecution(
        allocator,
        arguments,
        support.executionOptions(),
    );
}

/// Additive execution-policy entrypoint. The ordinary CLI continues through
/// `run` and therefore retains its exact eight-worker default.
pub fn runUsingExecution(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    execution: support.prover.EthereumExecutionOptions,
) !void {
    if (execution.cpu.contention_policy != .strict or
        execution.cpu.worker_count == 0 or
        execution.cpu.host_byte_budget == 0)
    {
        return error.InvalidLeafExecutionPolicy;
    }
    const parsed_options = try Options.parse(arguments);
    var options = try parsed_options.resolve(allocator);
    defer options.deinit(allocator);
    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        options.request,
        contract.max_json_bytes,
    );
    defer allocator.free(request_bytes);
    var parsed_request = try product.parseRequest(allocator, request_bytes);
    defer parsed_request.deinit();
    const request = &parsed_request.value;
    const executable_sha = try support.executableSha256(allocator);
    if (!std.meta.eql(
        executable_sha,
        try contract.parseSha256(request.producer_sha256),
    )) return error.ProducerIdentityMismatch;

    var authority = try product_support.openAuthority(allocator, request);
    defer authority.deinit();
    const source = &authority.source.value;
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
    while (position <= request.segment_index) : (position += 1) {
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
        if (position == request.segment_index) {
            try proveAndPublish(
                allocator,
                options,
                request,
                &authority.expected,
                &segment,
                executable_sha,
                execution,
                .{
                    .bytes = request_bytes.len,
                    .path = options.request,
                    .sha256 = support.sha256(request_bytes),
                },
            );
            return;
        }
        continuation = segment.base.continuation;
        if (continuation == null) return error.MissingContinuation;
    }
    unreachable;
}

fn proveAndPublish(
    allocator: std.mem.Allocator,
    options: Options,
    request: *const product.Request,
    expected: *const support.source_wire.Source,
    segment: *const frontend.runner.EthereumSegmentResult,
    executable_sha: [32]u8,
    execution: support.prover.EthereumExecutionOptions,
    request_identity: evidence.FileIdentity,
) !void {
    const global_statement = try frontend.recursion.span_statement
        .SpanStatement.fromCanonicalWords(
        &expected.metadata.base_statement_words,
    );
    const global_source = try frontend.recursion
        .segment_leaf_local_authority_v3.SourceV3.fromSegmentResult(
        global_statement,
        &segment.base,
    );
    if (!std.meta.eql(try global_source.metadata(), expected.metadata))
        return error.ReexecutedSegmentMismatch;
    var projection = try frontend.recursion.segment_leaf_local_projection_v3
        .ProjectionV3.init(&global_source);
    const local_source = try projection.sourceV2(
        &global_source,
        support.sessionDigest(try contract.parseSha256(request.session_id)),
    );
    const public = try support.encodeLocalPublicData(allocator, &local_source);
    defer allocator.free(public.words);

    var recorder: prover_api.stage_profile.Recorder = undefined;
    const profiling = options.profile_receipt != null;
    if (profiling) recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        profile_receipt.runtime,
        profile_receipt.example,
        .{ .capture_tasks = true, .capture_work = true },
    );
    defer if (profiling) recorder.deinit();

    var clock = try evidence.Clock.start();
    var prove_diagnostic: ?support.prover.EthereumSegmentProveDiagnostic = null;
    var output = support.prover.proveEthereumSegmentWithEngineUsingExecutionDiagnosed(
        support.RecursiveEngine,
        allocator,
        support.recursive_pcs_config,
        &projection.local_result,
        &segment.keccakf_calls,
        &segment.keccakf_execution_rows,
        &segment.signer_recovery_calls,
        &segment.signer_recovery_execution_rows,
        if (profiling) &recorder else null,
        public.value,
        execution,
        &prove_diagnostic,
    ) catch |err| {
        if (prove_diagnostic) |diagnostic| {
            if (diagnostic.evaluation) |evaluation| {
                std.debug.print(
                    "v4-prove-failure phase={s} subphase={s} " ++
                        "evaluation_stage={s} component={any} tree={any} " ++
                        "column={any} actual={any} expected={any} cause={s}\n",
                    .{
                        @tagName(diagnostic.phase),
                        if (diagnostic.composition_subphase) |subphase|
                            @tagName(subphase)
                        else
                            "none",
                        @tagName(evaluation.stage),
                        evaluation.component_index,
                        evaluation.tree_index,
                        evaluation.column_index,
                        evaluation.actual,
                        evaluation.expected,
                        @errorName(evaluation.cause),
                    },
                );
            } else if (diagnostic.composition_subphase) |subphase|
                std.debug.print(
                    "v4-prove-failure phase={s} subphase={s} cause={s}\n",
                    .{
                        @tagName(diagnostic.phase),
                        @tagName(subphase),
                        @errorName(diagnostic.cause),
                    },
                )
            else
                std.debug.print(
                    "v4-prove-failure phase={s} cause={s}\n",
                    .{
                        @tagName(diagnostic.phase),
                        @errorName(diagnostic.cause),
                    },
                );
        }
        return err;
    };
    defer output.deinit(allocator);
    const timing = try clock.finish();
    var encode_diagnostic: ?support.recursive_artifact.EncodeDiagnostic = null;
    const encoded = support.recursive_artifact.encodeAllocWithLimitsDiagnosed(
        allocator,
        .{
            .security_identity_sha256 = support.recursive_security_identity,
            .statement = &output.statement,
            .extension = &output.extension,
            .global = &expected.metadata,
            .base_claim = output.base_claim,
            .extension_claim = &output.extension_claim,
            .proof = &output.proof,
        },
        support.artifact_limits,
        &encode_diagnostic,
    ) catch |err| {
        if (encode_diagnostic) |diagnostic| {
            if (diagnostic.preflight) |preflight| {
                std.debug.print(
                    "v4-encode-failure phase={s} cause={s} stage={s} " ++
                        "tree={any} index={any} offset={d} actual={d} " ++
                        "expected={d}\n",
                    .{
                        @tagName(diagnostic.phase),
                        @errorName(diagnostic.cause),
                        @tagName(preflight.stage),
                        preflight.tree,
                        preflight.index,
                        preflight.offset,
                        preflight.actual,
                        preflight.expected,
                    },
                );
            } else {
                std.debug.print(
                    "v4-encode-failure phase={s} cause={s}\n",
                    .{
                        @tagName(diagnostic.phase),
                        @errorName(diagnostic.cause),
                    },
                );
            }
        }
        return err;
    };
    defer allocator.free(encoded);
    var verified = try support.verifyPoseidonArtifactWithCapture(
        allocator,
        encoded,
        expected,
    );
    defer verified.deinit(allocator);

    const proof_digest = support.sha256(encoded);
    const proof_hex = product_support.digestHex(proof_digest);
    const producer_hex = product_support.digestHex(executable_sha);
    const request_hex = product_support.digestHex(
        try contract.parseSha256(request.content_sha256),
    );
    const recursive_statement = product_support.digestHex(
        verified.recursive_statement_sha256,
    );
    const root = product_support.digestHex(verified.root_sha256);
    const security = product_support.digestHex(support.recursive_security_identity);
    const source_statement = product_support.digestHex(
        verified.source_public_statement_sha256,
    );
    const transcript = product_support.digestHex(
        verified.transcript_state_sha256,
    );
    const capture = product_support.digestHex(verified.capture.identity_digest);
    const link = product_support.fieldDigestHex(
        verified.capture.verified_link.identity,
    );
    const result = try product.encodeProducerResult(allocator, .{
        .producer_sha256 = &producer_hex,
        .proof = .{
            .bytes = encoded.len,
            .path = options.proof,
            .sha256 = &proof_hex,
        },
        .prove_timing = .{
            .system_ns = timing.system_ns,
            .user_ns = timing.user_ns,
            .wall_ns = timing.wall_ns,
        },
        .recursive_statement_sha256 = &recursive_statement,
        .request_sha256 = &request_hex,
        .root_sha256 = &root,
        .security_identity_sha256 = &security,
        .segment_index = request.segment_index,
        .source_public_statement_sha256 = &source_statement,
        .transcript_state_sha256 = &transcript,
        .verified_capture_sha256 = &capture,
        .verified_link_id_m31_le = &link,
    });
    defer allocator.free(result);
    const profiling_bytes = if (options.profile_receipt != null)
        try encodeProfileReceipt(
            allocator,
            &recorder,
            request,
            request_identity,
            options,
            encoded,
            result,
            executable_sha,
            execution,
            timing,
            &verified,
        )
    else
        null;
    defer if (profiling_bytes) |bytes| allocator.free(bytes);
    try artifact_io.publishCreateOnlyDurable(options.proof, encoded);
    try artifact_io.publishCreateOnlyDurable(options.result, result);
    if (options.profile_receipt) |path|
        try profile_receipt.publishCreateOnly(path, profiling_bytes.?);
}

fn encodeProfileReceipt(
    allocator: std.mem.Allocator,
    recorder: *prover_api.stage_profile.Recorder,
    request: *const product.Request,
    request_identity: evidence.FileIdentity,
    options: Options,
    proof_bytes: []const u8,
    result_bytes: []const u8,
    executable_sha: [32]u8,
    execution: support.prover.EthereumExecutionOptions,
    timing: evidence.Timing,
    verified: *const support.VerifiedPoseidonV4,
) ![]u8 {
    var stage = try recorder.snapshot(allocator);
    defer stage.deinit(allocator);
    var tasks = try recorder.taskSnapshot(allocator);
    defer tasks.deinit(allocator);
    const work_recorder = recorder.workCaptureRecorder() orelse
        return error.MissingWorkProfileRecorder;
    _ = try work_recorder.finalizePlannedProducerCoverage();
    const work = try recorder.workSnapshot();

    const base_profile = &verified.capture.base.vm_air.profile;
    const base_profile_hex = product_support.digestHex(
        base_profile.identity_digest,
    );
    const manifest_hex = product_support.digestHex(
        base_profile.lookup_manifest_identity,
    );
    const statement_hex = product_support.digestHex(
        base_profile.lookup_statement_identity,
    );
    const activation_hex = product_support.digestHex(
        base_profile.lookup_activation_identity,
    );
    var base_geometry = try profile_receipt.buildBaseGeometry(
        allocator,
        base_profile,
        &base_profile_hex,
        &manifest_hex,
        &statement_hex,
        &activation_hex,
    );
    defer base_geometry.deinit(allocator);

    const extension_context = &verified.capture.extension_context;
    const extension_context_hex = product_support.digestHex(
        extension_context.identity_digest,
    );
    const extension_statement_hex = product_support.digestHex(
        extension_context.statement_sha256,
    );
    const extension_claim_hex = product_support.digestHex(
        extension_context.claim_sha256,
    );
    var extension_components: [frontend.recursion.ethereum_leaf_context_v1.EXTENSION_COMPONENT_COUNT]profile_receipt.ExtensionComponent = undefined;
    const extension_geometry = profile_receipt.extensionGeometry(
        extension_context,
        &extension_components,
        &extension_context_hex,
        &extension_statement_hex,
        &extension_claim_hex,
    );

    const proof_digest = support.sha256(proof_bytes);
    const proof_hex = product_support.digestHex(proof_digest);
    const result_digest = support.sha256(result_bytes);
    const result_hex = product_support.digestHex(result_digest);
    const request_file_hex = product_support.digestHex(request_identity.sha256);
    const producer_hex = product_support.digestHex(executable_sha);
    return profile_receipt.encode(allocator, .{
        .base_geometry = base_geometry.value,
        .execution_policy = try profile_receipt.executionPolicy(
            execution.cpu.worker_count,
            execution.cpu.host_byte_budget,
        ),
        .extension_geometry = extension_geometry,
        .producer_result = .{
            .bytes = result_bytes.len,
            .path = options.result,
            .sha256 = &result_hex,
        },
        .producer_sha256 = &producer_hex,
        .proof = .{
            .bytes = proof_bytes.len,
            .path = options.proof,
            .sha256 = &proof_hex,
        },
        .prove_timing = .{
            .system_ns = timing.system_ns,
            .user_ns = timing.user_ns,
            .wall_ns = timing.wall_ns,
        },
        .request = .{
            .bytes = request_identity.bytes,
            .path = request_identity.path,
            .sha256 = &request_file_hex,
        },
        .request_content_sha256 = request.content_sha256,
        .segment_index = request.segment_index,
        .stage_profile = stage,
        .task_profile = tasks,
        .work_complete_exact = work.completeExact(),
        .work_profile = work,
    });
}

const Options = struct {
    profile_receipt: ?[]const u8 = null,
    proof: []const u8,
    request: []const u8,
    result: []const u8,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 6 and arguments.len != 8)
            return error.InvalidArguments;
        var result = Options{
            .proof = undefined,
            .request = undefined,
            .result = undefined,
        };
        var seen: u4 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len or arguments[index + 1].len == 0)
                return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, name, "--profile-receipt")) {
                if (seen & 8 != 0) return error.DuplicateArgument;
                seen |= 8;
                result.profile_receipt = value;
            } else if (std.mem.eql(u8, name, "--proof")) {
                if (seen & 1 != 0) return error.DuplicateArgument;
                seen |= 1;
                result.proof = value;
            } else if (std.mem.eql(u8, name, "--request")) {
                if (seen & 2 != 0) return error.DuplicateArgument;
                seen |= 2;
                result.request = value;
            } else if (std.mem.eql(u8, name, "--result")) {
                if (seen & 4 != 0) return error.DuplicateArgument;
                seen |= 4;
                result.result = value;
            } else return error.InvalidArguments;
        }
        if (seen != 7 and seen != 15) return error.InvalidArguments;
        return result;
    }

    fn resolve(self: Options, allocator: std.mem.Allocator) !Options {
        var result = self;
        if (self.profile_receipt) |path| {
            result.profile_receipt = try artifact_io.resolveAbsolute(
                allocator,
                path,
            );
        }
        errdefer if (result.profile_receipt) |path| allocator.free(path);
        result.proof = try artifact_io.resolveAbsolute(allocator, self.proof);
        errdefer allocator.free(result.proof);
        result.request = try artifact_io.resolveAbsolute(allocator, self.request);
        errdefer allocator.free(result.request);
        result.result = try artifact_io.resolveAbsolute(allocator, self.result);
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        if (self.profile_receipt) |path| allocator.free(path);
        allocator.free(self.proof);
        allocator.free(self.request);
        allocator.free(self.result);
        self.* = undefined;
    }
};

pub const testing = struct {
    pub fn parseHasProfileReceipt(arguments: []const []const u8) !bool {
        return (try Options.parse(arguments)).profile_receipt != null;
    }
};
