//! Phased, create-only orchestration for the real-leaf Poseidon provider split.
//!
//! Every invocation owns at most one proof/commitment phase. `capture-calls`
//! reexecutes the exact retained leaf and publishes only the authenticated
//! call list. `stage-a` commits the core and providers sequentially and then
//! publishes the common transcript checkpoint. `prove-core` and each
//! `prove-provider` invocation recompute one owner, freshly verify it, and
//! publish the next immutable prefix last. `close` reopens every raw proof,
//! freshly verifies the complete ordered set, and publishes the closure last.
//!
//! This route is intentionally nonproduction and nonrecursive. The current
//! frontend joint proof still uses the bounded Merkle caller bridge rather
//! than the complete RISC-V caller, even though provider V2 AIR-binds each
//! ordered call range and endpoint.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const call_artifact = @import("ethereum_poseidon_provider_call_artifact_v1.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_contract = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const lifecycle = @import("ethereum_poseidon_provider_stage_b_lifecycle_v1.zig");
const prefix_v2 = @import("ethereum_poseidon_provider_stage_b_prefix_v2.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const stage_a = @import("ethereum_poseidon_provider_stage_a_checkpoint_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const Engine = support.RecursiveEngine;

pub const command_name = "ethereum-poseidon-provider";

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    if (arguments.len == 0) return error.MissingProviderPhase;
    const phase = arguments[0];
    const options = arguments[1..];
    if (std.mem.eql(u8, phase, "capture-calls")) {
        try captureCalls(allocator, options);
    } else if (std.mem.eql(u8, phase, "stage-a")) {
        try commitStageA(allocator, options);
    } else if (std.mem.eql(u8, phase, "prove-core")) {
        try proveCore(allocator, options);
    } else if (std.mem.eql(u8, phase, "prove-provider")) {
        try proveProvider(allocator, options);
    } else if (std.mem.eql(u8, phase, "close")) {
        try close(allocator, options);
    } else return error.UnsupportedProviderPhase;
}

fn captureCalls(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var paths = try parseAndResolve(allocator, arguments, &.{
        "--request",
        "--geometry",
        "--calls",
        "--call-artifact",
    });
    defer paths.deinit(allocator);
    try requireDistinct(paths.items[0..]);

    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        paths.items[0],
        contract.max_json_bytes,
    );
    defer allocator.free(request_bytes);
    var parsed_request = try product.parseRequest(allocator, request_bytes);
    defer parsed_request.deinit();
    const request = &parsed_request.value;
    const executable_sha256 = try support.executableSha256(allocator);
    try requireExecutableRequest(request, executable_sha256);
    const request_file = evidence.identity(paths.items[0], request_bytes);

    const geometry_bytes = try artifact_io.readFileBounded(
        allocator,
        paths.items[1],
        geometry_contract.max_snapshot_bytes,
    );
    defer allocator.free(geometry_bytes);
    var geometry = try geometry_contract.parse(allocator, geometry_bytes);
    defer geometry.deinit();
    const geometry_file = evidence.identity(paths.items[1], geometry_bytes);
    try validateGeometryAgainstRequest(
        geometry.value,
        geometry_file,
        request.*,
        request_file,
        executable_sha256,
    );
    const resource_plan = try resource.ProviderResourcePlanV1.create(
        &geometry.value,
        geometry_file.sha256,
    );

    var source_authority = try product_support.openAuthority(allocator, request);
    defer source_authority.deinit();
    const source = &source_authority.source.value;
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
            try captureSegmentCalls(
                allocator,
                paths.items[2],
                paths.items[3],
                request,
                request_file,
                &source_authority.expected,
                &segment,
                geometry.value,
                geometry_file,
                resource_plan,
                executable_sha256,
            );
            return;
        }
        continuation = segment.base.continuation;
        if (continuation == null) return error.MissingContinuation;
    }
    unreachable;
}

fn captureSegmentCalls(
    allocator: std.mem.Allocator,
    calls_path: []const u8,
    metadata_path: []const u8,
    request: *const product.Request,
    request_file: evidence.FileIdentity,
    expected: *const support.source_wire.Source,
    segment: *const frontend.runner.EthereumSegmentResult,
    geometry: geometry_contract.Snapshot,
    geometry_file: evidence.FileIdentity,
    resource_plan: resource.ProviderResourcePlanV1,
    executable_sha256: [32]u8,
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
    var call_authority = try support.prover
        .buildEthereumSegmentProviderCallAuthorityV1(
        allocator,
        &projection.local_result,
        &segment.keccakf_calls,
        &segment.keccakf_execution_rows,
        &segment.signer_recovery_calls,
        &segment.signer_recovery_execution_rows,
        public.value,
    );
    defer call_authority.deinit();
    if (!std.meta.eql(call_authority.public_data_wire_id, public.value.wireId()))
        return error.ProviderPublicDataAuthorityMismatch;
    const encoded = try call_artifact.encode(allocator, .{
        .calls = call_authority.calls,
        .calls_path = calls_path,
        .geometry_snapshot = geometry_file,
        .geometry_snapshot_content_sha256 = try contract.parseSha256(
            geometry.content_sha256,
        ),
        .producer_sha256 = executable_sha256,
        .public_data_wire_id = product_support.fieldDigestBytes(
            call_authority.public_data_wire_id,
        ),
        .request = request_file,
        .request_content_sha256 = try contract.parseSha256(
            request.content_sha256,
        ),
        .resource_plan = &resource_plan,
        .session = try contract.parseSha256(request.session_id),
    });
    var owned = encoded;
    defer owned.deinit(allocator);
    try call_artifact.publishCreateOnly(
        allocator,
        calls_path,
        metadata_path,
        encoded,
    );
}

fn commitStageA(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var paths = try parseAndResolve(allocator, arguments, &.{
        "--call-artifact",
        "--checkpoint",
    });
    defer paths.deinit(allocator);
    try requireDistinct(paths.items[0..]);
    var opened = try OpenedCallAuthority.open(allocator, paths.items[0]);
    defer opened.deinit(allocator);

    const core_roots = try joint_proof().commitCoreStageA(
        Engine,
        allocator,
        support.recursive_pcs_config,
        &opened.plan,
        opened.calls.calls,
    );
    const provider_roots = try allocator.alloc(
        harness.StageACommitment(Engine),
        opened.plan.shards.len,
    );
    defer allocator.free(provider_roots);
    for (provider_roots, 0..) |*roots, index| {
        roots.* = try harness.commitStageA(
            Engine,
            allocator,
            support.recursive_pcs_config,
            &opened.plan,
            opened.calls.calls,
            @intCast(index),
        );
    }
    var manifest = try joint.JointManifest(Engine).create(
        allocator,
        &opened.plan,
        opened.calls.calls,
        core_roots,
        provider_roots,
    );
    defer manifest.deinit(allocator);
    const prepared = try joint.prepareSharedTranscript(
        Engine,
        allocator,
        support.recursive_pcs_config,
        &opened.plan,
        opened.calls.calls,
        &manifest,
    );
    const bytes = try stage_a.encode(allocator, .{
        .calls = opened.calls.calls,
        .manifest = &manifest,
        .plan = &opened.plan,
        .resource_plan = &opened.resource_plan,
        .shared_relation = prepared.authority_value,
    });
    defer allocator.free(bytes);
    try stage_a.publishCreateOnly(paths.items[1], bytes);
}

fn proveCore(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var paths = try parseAndResolve(allocator, arguments, &.{
        "--call-artifact",
        "--checkpoint",
        "--proof",
        "--proof-artifact",
        "--prefix",
    });
    defer paths.deinit(allocator);
    try requireDistinct(paths.items[0..]);
    var opened = try OpenedCallAuthority.open(allocator, paths.items[0]);
    defer opened.deinit(allocator);
    var checkpoint = try OpenedStageA.open(
        allocator,
        paths.items[1],
        &opened,
    );
    defer checkpoint.deinit(allocator);
    const context = checkpoint.context(&opened);
    const publication = try lifecycle.proveCoreCreateOnly(
        allocator,
        context,
        opened.executable_sha256,
        paths.items[2],
        paths.items[3],
    );
    var fresh = try lifecycle.verifyCoreFresh(
        allocator,
        context,
        opened.executable_sha256,
        opened.executable_sha256,
        publication.metadata,
    );
    defer fresh.deinit(allocator);
    const authority_value = checkpoint.prefixAuthority(&opened);
    const bytes = try prefix_v2.encodeCorePrefix(
        allocator,
        authority_value,
        &fresh,
    );
    defer allocator.free(bytes);
    try prefix_v2.publishPrefixCreateOnly(paths.items[4], bytes);
}

fn proveProvider(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var paths = try parseAndResolve(allocator, arguments, &.{
        "--call-artifact",
        "--checkpoint",
        "--previous-prefix",
        "--proof",
        "--proof-artifact",
        "--next-prefix",
    });
    defer paths.deinit(allocator);
    try requireDistinct(paths.items[0..]);
    var opened = try OpenedCallAuthority.open(allocator, paths.items[0]);
    defer opened.deinit(allocator);
    var checkpoint = try OpenedStageA.open(
        allocator,
        paths.items[1],
        &opened,
    );
    defer checkpoint.deinit(allocator);
    var previous = try prefix_v2.openPrefix(allocator, paths.items[2]);
    defer previous.deinit(allocator);
    const authority_value = checkpoint.prefixAuthority(&opened);
    try prefix_v2.validateAgainst(previous.parsed.value, authority_value);
    const ordinal = previous.parsed.value.next_provider_ordinal;
    if (ordinal >= opened.plan.shard_count)
        return error.CompleteProviderProofPrefix;
    const context = checkpoint.context(&opened);
    const publication = try lifecycle.proveProviderV2CreateOnly(
        allocator,
        context,
        opened.executable_sha256,
        ordinal,
        paths.items[3],
        paths.items[4],
    );
    var fresh = try lifecycle.verifyProviderV2Fresh(
        allocator,
        context,
        opened.executable_sha256,
        opened.executable_sha256,
        ordinal,
        publication.metadata,
    );
    defer fresh.deinit(allocator);
    const bytes = try prefix_v2.encodeAppendProvider(
        allocator,
        authority_value,
        previous.parsed.value,
        previous.file,
        &fresh,
    );
    defer allocator.free(bytes);
    try prefix_v2.publishPrefixCreateOnly(paths.items[5], bytes);
}

fn close(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var paths = try parseAndResolve(allocator, arguments, &.{
        "--call-artifact",
        "--checkpoint",
        "--complete-prefix",
        "--result",
    });
    defer paths.deinit(allocator);
    try requireDistinct(paths.items[0..]);
    var opened = try OpenedCallAuthority.open(allocator, paths.items[0]);
    defer opened.deinit(allocator);
    var checkpoint = try OpenedStageA.open(
        allocator,
        paths.items[1],
        &opened,
    );
    defer checkpoint.deinit(allocator);
    var complete = try prefix_v2.openPrefix(allocator, paths.items[2]);
    defer complete.deinit(allocator);
    const authority_value = checkpoint.prefixAuthority(&opened);
    const closure = try prefix_v2.reverifyCompleteAndClose(
        allocator,
        authority_value,
        opened.executable_sha256,
        opened.executable_sha256,
        complete.parsed.value,
    );
    const bytes = try prefix_v2.encodeFinalReceipt(
        allocator,
        authority_value,
        complete.parsed.value,
        complete.file,
        closure,
    );
    defer allocator.free(bytes);
    try prefix_v2.publishFinalCreateOnly(paths.items[3], bytes);
}

pub const OpenedCallAuthority = struct {
    artifact_bytes: []u8,
    artifact_file: evidence.FileIdentity,
    artifact: std.json.Parsed(call_artifact.Artifact),
    geometry_bytes: []u8,
    geometry_file: evidence.FileIdentity,
    geometry: std.json.Parsed(geometry_contract.Snapshot),
    request_bytes: []u8,
    request_file: evidence.FileIdentity,
    request: std.json.Parsed(product.Request),
    calls: call_artifact.Reopened,
    resource_plan: resource.ProviderResourcePlanV1,
    plan: authority.ProviderShardPlanV1,
    executable_sha256: [32]u8,

    pub fn open(
        allocator: std.mem.Allocator,
        artifact_path: []const u8,
    ) !OpenedCallAuthority {
        if (!std.fs.path.isAbsolute(artifact_path))
            return error.InvalidProviderOrchestrationPath;
        const executable_sha256 = try support.executableSha256(allocator);
        const artifact_bytes = try artifact_io.readFileBounded(
            allocator,
            artifact_path,
            call_artifact.max_metadata_bytes,
        );
        errdefer allocator.free(artifact_bytes);
        var artifact = try call_artifact.parse(allocator, artifact_bytes);
        errdefer artifact.deinit();
        const artifact_file = evidence.identity(artifact_path, artifact_bytes);
        if (!std.mem.eql(
            u8,
            artifact.value.producer_sha256,
            &hex(executable_sha256),
        )) return error.ProviderExecutableIdentityMismatch;

        const geometry_bytes = try support.readIdentity(
            allocator,
            artifact.value.geometry_snapshot,
            geometry_contract.max_snapshot_bytes,
        );
        errdefer allocator.free(geometry_bytes);
        var geometry = try geometry_contract.parse(allocator, geometry_bytes);
        errdefer geometry.deinit();
        const geometry_file = evidence.identity(
            artifact.value.geometry_snapshot.path,
            geometry_bytes,
        );
        const request_bytes = try support.readIdentity(
            allocator,
            artifact.value.request,
            contract.max_json_bytes,
        );
        errdefer allocator.free(request_bytes);
        var request = try product.parseRequest(allocator, request_bytes);
        errdefer request.deinit();
        const request_file = evidence.identity(
            artifact.value.request.path,
            request_bytes,
        );
        try requireExecutableRequest(&request.value, executable_sha256);
        try validateGeometryAgainstRequest(
            geometry.value,
            geometry_file,
            request.value,
            request_file,
            executable_sha256,
        );
        const resource_plan = try resource.ProviderResourcePlanV1.create(
            &geometry.value,
            geometry_file.sha256,
        );
        var calls = try call_artifact.reopen(
            allocator,
            artifact.value,
            &resource_plan,
        );
        errdefer calls.deinit(allocator);
        const session = try contract.parseSha256(request.value.session_id);
        if (!std.meta.eql(calls.session, session) or
            !std.mem.eql(
                u8,
                artifact.value.request_content_sha256,
                request.value.content_sha256,
            ) or artifact.value.segment_index != request.value.segment_index)
        {
            return error.ProviderCallArtifactAuthorityMismatch;
        }
        var plan = try authority.ProviderShardPlanV1.create(
            allocator,
            session,
            calls.calls,
            resource_plan.providerShardRequest(),
        );
        errdefer plan.deinit(allocator);
        if (!std.meta.eql(plan.call_list_commitment, calls.call_list_commitment) or
            !std.meta.eql(plan.residency.result, resource_plan.shard_planning))
        {
            return error.ProviderCallArtifactAuthorityMismatch;
        }
        return .{
            .artifact_bytes = artifact_bytes,
            .artifact_file = artifact_file,
            .artifact = artifact,
            .geometry_bytes = geometry_bytes,
            .geometry_file = geometry_file,
            .geometry = geometry,
            .request_bytes = request_bytes,
            .request_file = request_file,
            .request = request,
            .calls = calls,
            .resource_plan = resource_plan,
            .plan = plan,
            .executable_sha256 = executable_sha256,
        };
    }

    pub fn deinit(self: *OpenedCallAuthority, allocator: std.mem.Allocator) void {
        self.plan.deinit(allocator);
        self.calls.deinit(allocator);
        self.request.deinit();
        allocator.free(self.request_bytes);
        self.geometry.deinit();
        allocator.free(self.geometry_bytes);
        self.artifact.deinit();
        allocator.free(self.artifact_bytes);
        self.* = undefined;
    }
};

const OpenedStageA = struct {
    bytes: []u8,
    file: evidence.FileIdentity,
    content_sha256: [32]u8,
    parsed: std.json.Parsed(stage_a.Checkpoint),
    reopened: stage_a.Reopened,

    fn open(
        allocator: std.mem.Allocator,
        path: []const u8,
        calls: *const OpenedCallAuthority,
    ) !OpenedStageA {
        if (!std.fs.path.isAbsolute(path))
            return error.InvalidProviderOrchestrationPath;
        const bytes = try artifact_io.readFileBounded(
            allocator,
            path,
            stage_a.max_checkpoint_bytes,
        );
        errdefer allocator.free(bytes);
        var parsed = try stage_a.parse(allocator, bytes);
        errdefer parsed.deinit();
        var reopened = try stage_a.reopen(
            allocator,
            parsed.value,
            &calls.resource_plan,
            &calls.plan,
            calls.calls.calls,
        );
        errdefer reopened.deinit(allocator);
        return .{
            .bytes = bytes,
            .file = evidence.identity(path, bytes),
            .content_sha256 = try contract.parseSha256(
                parsed.value.content_sha256,
            ),
            .parsed = parsed,
            .reopened = reopened,
        };
    }

    fn context(
        self: *const OpenedStageA,
        calls: *const OpenedCallAuthority,
    ) lifecycle.Context {
        return .{
            .calls = calls.calls.calls,
            .plan = &calls.plan,
            .resource_plan = &calls.resource_plan,
            .stage_a_checkpoint = self.file,
            .stage_a_checkpoint_content_sha256 = self.content_sha256,
            .stage_a_reopened = &self.reopened,
        };
    }

    fn prefixAuthority(
        self: *const OpenedStageA,
        calls: *const OpenedCallAuthority,
    ) prefix_v2.Authority {
        return .{
            .call_artifact = calls.artifact_file,
            .call_artifact_content_sha256 = contract.parseSha256(
                calls.artifact.value.content_sha256,
            ) catch unreachable,
            .call_artifact_value = &calls.artifact.value,
            .context = self.context(calls),
        };
    }

    fn deinit(self: *OpenedStageA, allocator: std.mem.Allocator) void {
        self.reopened.deinit(allocator);
        self.parsed.deinit();
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn validateGeometryAgainstRequest(
    geometry: geometry_contract.Snapshot,
    geometry_file: evidence.FileIdentity,
    request: product.Request,
    request_file: evidence.FileIdentity,
    executable_sha256: [32]u8,
) !void {
    try geometry.validate();
    try request.validate();
    if (!identityMatches(geometry.request, request_file) or
        !std.mem.eql(
            u8,
            geometry.request_content_sha256,
            request.content_sha256,
        ) or !std.mem.eql(
        u8,
        geometry.producer_sha256,
        &hex(executable_sha256),
    ) or geometry.segment_index != request.segment_index or
        !typedIdentityEqual(geometry.source_request, request.source_request) or
        !identityEqual(geometry.source_segment, request.source_segment) or
        geometry_file.bytes == 0)
    {
        return error.ProviderGeometryAuthorityMismatch;
    }
}

pub fn requireExecutableRequest(
    request: *const product.Request,
    executable_sha256: [32]u8,
) !void {
    try request.validate();
    const expected = hex(executable_sha256);
    if (!std.mem.eql(u8, request.producer_sha256, &expected) or
        !std.mem.eql(u8, request.verifier_sha256, &expected))
    {
        return error.ProviderExecutableIdentityMismatch;
    }
}

fn identityMatches(
    actual: contract.Identity,
    expected: evidence.FileIdentity,
) bool {
    if (actual.bytes != expected.bytes or
        !std.mem.eql(u8, actual.path, expected.path)) return false;
    const digest = contract.parseSha256(actual.sha256) catch return false;
    return std.meta.eql(digest, expected.sha256);
}

fn identityEqual(left: contract.Identity, right: contract.Identity) bool {
    return left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn typedIdentityEqual(
    left: contract.TypedIdentity,
    right: contract.TypedIdentity,
) bool {
    return std.mem.eql(u8, left.schema, right.schema) and
        left.bytes == right.bytes and
        std.mem.eql(u8, left.path, right.path) and
        std.mem.eql(u8, left.sha256, right.sha256);
}

fn requireDistinct(paths: []const []const u8) !void {
    for (paths, 0..) |left, index|
        for (paths[index + 1 ..]) |right|
            if (std.mem.eql(u8, left, right))
                return error.DuplicateProviderOrchestrationPath;
}

fn ResolvedPaths(comptime count: usize) type {
    return struct {
        items: [count][]u8,

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.items) |path| allocator.free(path);
            self.* = undefined;
        }
    };
}

fn parseAndResolve(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    comptime names: []const []const u8,
) !ResolvedPaths(names.len) {
    if (arguments.len != 2 * names.len) return error.InvalidArguments;
    var parsed: [names.len][]const u8 = undefined;
    var seen = [_]bool{false} ** names.len;
    var cursor: usize = 0;
    while (cursor < arguments.len) : (cursor += 2) {
        const name = arguments[cursor];
        const value = arguments[cursor + 1];
        if (value.len == 0) return error.InvalidArguments;
        var matched = false;
        for (names, 0..) |expected, index| {
            if (!std.mem.eql(u8, name, expected)) continue;
            if (seen[index]) return error.DuplicateArgument;
            seen[index] = true;
            parsed[index] = value;
            matched = true;
            break;
        }
        if (!matched) return error.InvalidArguments;
    }
    for (seen) |present| if (!present) return error.InvalidArguments;

    var result: ResolvedPaths(names.len) = undefined;
    var initialized: usize = 0;
    errdefer for (result.items[0..initialized]) |path| allocator.free(path);
    for (parsed, &result.items) |path, *destination| {
        destination.* = try artifact_io.resolveAbsolute(allocator, path);
        initialized += 1;
    }
    return result;
}

fn joint_proof() type {
    return frontend.testing.narrow_memory_provider_joint_proof;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

comptime {
    const provider_v2 = frontend.testing.narrow_memory_provider_joint_proof_v2;
    if (provider_v2.ACTIVATES_PRODUCTION_PROOF or
        !provider_v2.PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED or
        provider_v2.FULL_RISCV_CORE_EXTERNALIZED or
        provider_v2.RECURSIVE_VERIFICATION_IMPLEMENTED)
    {
        @compileError("provider orchestration readiness drifted");
    }
}

pub const testing = struct {
    pub fn options(allocator: std.mem.Allocator) !void {
        var parsed = try parseAndResolve(allocator, &.{
            "--prefix",
            "relative/prefix.json",
            "--proof",
            "./relative/proof.stw",
        }, &.{ "--proof", "--prefix" });
        defer parsed.deinit(allocator);
        for (parsed.items) |path|
            try std.testing.expect(std.fs.path.isAbsolute(path));
        try std.testing.expectError(
            error.DuplicateArgument,
            parseAndResolve(allocator, &.{
                "--proof",
                "one",
                "--proof",
                "two",
            }, &.{ "--proof", "--prefix" }),
        );
    }
};
