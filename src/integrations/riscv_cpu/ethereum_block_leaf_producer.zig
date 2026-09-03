//! Persistent, one-session producer for all real Ethereum segment leaves.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const journal_authority = @import("ethereum_block_leaf_journal.zig");
const support = @import("ethereum_block_leaf_support.zig");

const max_elf_bytes: usize = 64 * 1024 * 1024;
const max_input_bytes: usize = 64 * 1024 * 1024;
const max_output_bytes: usize = 16 * 1024 * 1024;
const max_journal_bytes: usize = 64 * 1024 * 1024;

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const parsed_options = try Options.parse(arguments);
    var options = try parsed_options.resolve(allocator);
    defer options.deinit(allocator);
    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        options.request,
        contract.max_json_bytes,
    );
    defer allocator.free(request_bytes);
    var parsed_stream = try contract.parseStream(allocator, request_bytes);
    defer parsed_stream.deinit();
    const stream = parsed_stream.value;
    try validateSpoolPaths(
        allocator,
        options.proof_root,
        stream.durable_progress.path,
        stream.durable_progress.publication_prefix,
    );

    const source_identity = contract.Identity{
        .bytes = stream.source_request.bytes,
        .path = stream.source_request.path,
        .sha256 = stream.source_request.sha256,
    };
    const source_bytes = try support.readIdentity(
        allocator,
        source_identity,
        contract.max_json_bytes,
    );
    defer allocator.free(source_bytes);
    switch (try contract.sourceKind(allocator, source_bytes)) {
        .native_blake2s_v1 => {},
        .recursive_poseidon2_v2 => return error.RecursiveLeafProfileUnavailable,
    }
    var parsed_source = try contract.parseSource(allocator, source_bytes);
    defer parsed_source.deinit();
    const source = parsed_source.value;
    if (!std.mem.eql(u8, source.schema, stream.source_request.schema) or
        source.segment_count != stream.real_segment_count)
    {
        return error.SourceRequestMismatch;
    }
    const executable = try support.executableSha256(allocator);
    if (!std.meta.eql(
        executable,
        try contract.parseSha256(stream.producer_sha256),
    )) return error.ProducerIdentityMismatch;

    const elf = try support.readIdentity(allocator, source.elf, max_elf_bytes);
    defer allocator.free(elf);
    const input = try support.readIdentity(allocator, source.input, max_input_bytes);
    defer allocator.free(input);
    const expected_output = try support.readIdentity(
        allocator,
        source.expected_output,
        max_output_bytes,
    );
    defer allocator.free(expected_output);
    const journal = try support.readIdentity(
        allocator,
        source.execution_journal,
        max_journal_bytes,
    );
    defer allocator.free(journal);
    const journal_segments = try journal_authority.validate(
        allocator,
        journal,
        source,
    );
    defer allocator.free(journal_segments);
    const session_id = support.sessionDigest(
        try contract.parseSha256(stream.session_id),
    );
    const request_sha = try contract.parseSha256(stream.content_sha256);
    const stream_session_sha = try contract.parseSha256(
        stream.stream_session_sha256,
    );

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
    var published: std.ArrayList(evidence.StreamPublication) = .empty;
    defer {
        for (published.items) |publication| {
            allocator.free(publication.proof.path);
            allocator.free(publication.result.path);
        }
        published.deinit(allocator);
    }

    for (stream.segments, 0..) |expected_segment, position| {
        var segment = if (position == 0)
            try session.startSegment(source.segment_step_budget)
        else
            try session.resumeSegment(
                continuation orelse return error.MissingContinuation,
                source.segment_step_budget,
            );
        const next = segment.base.continuation;
        defer segment.deinit();
        if (segment.base.segment_index != position)
            return error.ExecutionSegmentOrderMismatch;

        const expected_bytes = try support.readIdentity(
            allocator,
            expected_segment.expected_authority,
            support.source_wire.encoded_size,
        );
        defer allocator.free(expected_bytes);
        const expected_source = try support.source_wire.decode(expected_bytes);
        if (expected_source.metadata.segment_index != position or
            expected_source.metadata.segment_count != source.segment_count or
            !std.meta.eql(
                journal_segments[position],
                expected_source.journal_record_sha256,
            ))
        {
            return error.SegmentSourceMismatch;
        }
        const expected_statement = try expected_source.statementSha256();
        if (!std.meta.eql(
            expected_statement,
            try contract.parseSha256(expected_segment.expected_statement_sha256),
        )) return error.ExpectedStatementMismatch;

        const global_statement = try frontend.recursion.span_statement
            .SpanStatement.fromCanonicalWords(
            &expected_source.metadata.base_statement_words,
        );
        const global_source = try frontend.recursion
            .segment_leaf_local_authority_v3.SourceV3.fromSegmentResult(
            global_statement,
            &segment.base,
        );
        const actual_metadata = try global_source.metadata();
        if (!std.meta.eql(actual_metadata, expected_source.metadata))
            return error.ReexecutedSegmentMismatch;

        if (position < stream.first_uncommitted_segment) {
            try validateCommitted(
                allocator,
                expected_segment.committed.?,
                &expected_source,
                try contract.parseSha256(stream.verifier_sha256),
            );
        } else {
            const publication = try proveAndPublish(
                allocator,
                options.proof_root,
                &stream,
                &expected_segment,
                &expected_source,
                &global_source,
                &segment,
                session_id,
                request_sha,
                stream_session_sha,
            );
            errdefer {
                allocator.free(publication.proof.path);
                allocator.free(publication.result.path);
            }
            try published.append(allocator, publication);
        }

        const complete = segment.base.isComplete();
        if (complete != (position + 1 == stream.segments.len))
            return error.ExecutionCompletionMismatch;
        if (complete) {
            const output = segment.base.output orelse return error.MissingOutput;
            if (!std.mem.eql(u8, output, expected_output))
                return error.PublicOutputMismatch;
        }
        continuation = next;
        if (position + 1 != stream.segments.len and continuation == null)
            return error.MissingContinuation;
    }

    const result = try evidence.encodeStreamResult(allocator, .{
        .first_segment_index = stream.first_uncommitted_segment,
        .producer_sha256 = executable,
        .publications = published.items,
        .request_sha256 = request_sha,
        .stream_session_sha256 = stream_session_sha,
    });
    defer allocator.free(result);
    try artifact_io.publishCreateOnlyDurable(options.result, result);
}

fn proveAndPublish(
    allocator: std.mem.Allocator,
    proof_root: []const u8,
    stream: *const contract.StreamRequest,
    expected_segment: *const contract.StreamSegment,
    expected_source: *const support.source_wire.Source,
    global_source: *const frontend.recursion.segment_leaf_local_authority_v3.SourceV3,
    segment: *const frontend.runner.EthereumSegmentResult,
    session_id: frontend.recursion.span_statement.Digest,
    request_sha: [32]u8,
    stream_session_sha: [32]u8,
) !evidence.StreamPublication {
    var projection = try frontend.recursion.segment_leaf_local_projection_v3
        .ProjectionV3.init(global_source);
    const local_source = try projection.sourceV2(global_source, session_id);
    const public = try support.encodeLocalPublicData(allocator, &local_source);
    defer allocator.free(public.words);

    var prove_clock = try evidence.Clock.start();
    var output = try support.prover.proveEthereumSegmentWithEngineUsingExecution(
        support.Engine,
        allocator,
        support.pcs_config,
        &projection.local_result,
        &segment.keccakf_calls,
        &segment.keccakf_execution_rows,
        &segment.signer_recovery_calls,
        &segment.signer_recovery_execution_rows,
        null,
        public.value,
        support.executionOptions(),
    );
    defer output.deinit(allocator);
    const prove_timing = try prove_clock.finish();
    const encoded = try support.artifact.encodeAllocWithLimits(
        allocator,
        .{
            .pcs_config = support.pcs_config,
            .statement = &output.statement,
            .extension = &output.extension,
            .global = &expected_source.metadata,
            .base_claim = output.base_claim,
            .extension_claim = &output.extension_claim,
            .proof = &output.proof,
        },
        support.artifact_limits,
    );
    defer allocator.free(encoded);
    const verified = try support.verifyArtifact(allocator, encoded);
    const expected_statement = try expected_source.statementSha256();
    if (!std.meta.eql(verified.statement_sha256, expected_statement))
        return error.VerifiedStatementMismatch;

    const names = try segmentPaths(
        allocator,
        proof_root,
        expected_segment.segment_index,
    );
    defer names.deinit(allocator);
    const proof_identity = evidence.identity(names.proof_name, encoded);
    try publishIdentical(allocator, names.proof_path, encoded);
    const leaf_result = try evidence.encodeLeafResult(allocator, .{
        .expected_authority_sha256 = try contract.parseSha256(
            expected_segment.expected_authority.sha256,
        ),
        .proof = proof_identity,
        .prove_timing = prove_timing,
        .request_sha256 = request_sha,
        .root_sha256 = verified.root_sha256,
        .segment_index = expected_segment.segment_index,
        .statement_sha256 = expected_statement,
    });
    defer allocator.free(leaf_result);
    const result_identity = evidence.identity(names.result_name, leaf_result);
    try publishIdentical(allocator, names.result_path, leaf_result);
    const progress_proof_path = try std.fs.path.join(
        allocator,
        &.{ stream.durable_progress.publication_prefix, names.proof_name },
    );
    defer allocator.free(progress_proof_path);
    const progress_result_path = try std.fs.path.join(
        allocator,
        &.{ stream.durable_progress.publication_prefix, names.result_name },
    );
    defer allocator.free(progress_result_path);
    const progress_proof = evidence.FileIdentity{
        .bytes = proof_identity.bytes,
        .path = progress_proof_path,
        .sha256 = proof_identity.sha256,
    };
    const progress_result = evidence.FileIdentity{
        .bytes = result_identity.bytes,
        .path = progress_result_path,
        .sha256 = result_identity.sha256,
    };
    const progress = try evidence.encodeProgress(allocator, .{
        .proof = progress_proof,
        .request_sha256 = request_sha,
        .result = progress_result,
        .segment_index = expected_segment.segment_index,
        .stream_session_sha256 = stream_session_sha,
    });
    defer allocator.free(progress);
    try artifact_io.appendDurable(stream.durable_progress.path, progress);
    const retained_proof_path = try allocator.dupe(u8, progress_proof_path);
    errdefer allocator.free(retained_proof_path);
    const retained_result_path = try allocator.dupe(u8, progress_result_path);
    return .{
        .progress_record_sha256 = support.sha256(progress),
        .proof = .{
            .bytes = progress_proof.bytes,
            .path = retained_proof_path,
            .sha256 = progress_proof.sha256,
        },
        .result = .{
            .bytes = progress_result.bytes,
            .path = retained_result_path,
            .sha256 = progress_result.sha256,
        },
        .segment_index = expected_segment.segment_index,
    };
}

fn validateCommitted(
    allocator: std.mem.Allocator,
    committed: contract.CommittedLeaf,
    source: *const support.source_wire.Source,
    verifier_sha256: [32]u8,
) !void {
    const proof = try support.readIdentity(
        allocator,
        committed.proof,
        support.artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(proof);
    const verified = try support.verifyArtifact(allocator, proof);
    const statement = try source.statementSha256();
    const committed_statement = try contract.parseSha256(
        committed.statement_sha256,
    );
    const committed_root = try contract.parseSha256(committed.root_sha256);
    if (verified.segment_index != source.metadata.segment_index or
        verified.segment_count != source.metadata.segment_count or
        !std.meta.eql(verified.statement_sha256, statement) or
        !std.meta.eql(committed_statement, statement) or
        !std.meta.eql(verified.root_sha256, committed_root))
    {
        return error.CommittedArtifactMismatch;
    }
    const receipt_bytes = try support.readIdentity(
        allocator,
        committed.verification_receipt,
        contract.max_json_bytes,
    );
    defer allocator.free(receipt_bytes);
    var receipt = try contract.parseVerificationReceipt(
        allocator,
        receipt_bytes,
    );
    defer receipt.deinit();
    const value = receipt.value;
    if (value.node_index != source.metadata.segment_index or
        value.proof_bytes != proof.len or
        !std.meta.eql(
            try contract.parseSha256(value.proof_sha256),
            support.sha256(proof),
        ) or
        !std.meta.eql(
            try contract.parseSha256(value.statement_sha256),
            statement,
        ) or
        !std.meta.eql(try contract.parseSha256(value.root_sha256), committed_root) or
        !std.meta.eql(
            try contract.parseSha256(value.verifier_sha256),
            verifier_sha256,
        ))
    {
        return error.CommittedReceiptMismatch;
    }
}

fn publishIdentical(
    allocator: std.mem.Allocator,
    path: []const u8,
    bytes: []const u8,
) !void {
    artifact_io.publishCreateOnlyDurable(path, bytes) catch |err| switch (err) {
        error.PathAlreadyExists => {
            const retained = try artifact_io.readFileBounded(
                allocator,
                path,
                bytes.len,
            );
            defer allocator.free(retained);
            if (!std.mem.eql(u8, retained, bytes))
                return error.ConflictingPublication;
        },
        else => return err,
    };
}

const SegmentPaths = struct {
    proof_name: []u8,
    proof_path: []u8,
    result_name: []u8,
    result_path: []u8,

    fn deinit(self: SegmentPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.proof_name);
        allocator.free(self.proof_path);
        allocator.free(self.result_name);
        allocator.free(self.result_path);
    }
};

fn segmentPaths(
    allocator: std.mem.Allocator,
    root: []const u8,
    index: u32,
) !SegmentPaths {
    const proof_name = try std.fmt.allocPrint(allocator, "segment-{d:0>6}.stw", .{index});
    errdefer allocator.free(proof_name);
    const proof_path = try std.fs.path.join(allocator, &.{ root, proof_name });
    errdefer allocator.free(proof_path);
    const result_name = try std.fmt.allocPrint(
        allocator,
        "segment-{d:0>6}.result.json",
        .{index},
    );
    errdefer allocator.free(result_name);
    const result_path = try std.fs.path.join(allocator, &.{ root, result_name });
    return .{
        .proof_name = proof_name,
        .proof_path = proof_path,
        .result_name = result_name,
        .result_path = result_path,
    };
}

fn validateSpoolPaths(
    allocator: std.mem.Allocator,
    proof_root: []const u8,
    progress_path: []const u8,
    publication_prefix: []const u8,
) !void {
    const progress_parent = std.fs.path.dirname(progress_path) orelse
        return error.ProgressPathMismatch;
    const stream_root = std.fs.path.dirname(progress_parent) orelse
        return error.ProgressPathMismatch;
    const expected_progress = try std.fs.path.resolve(
        allocator,
        &.{ stream_root, "proofs", "progress.ndjson" },
    );
    defer allocator.free(expected_progress);
    const actual_progress = try std.fs.path.resolve(
        allocator,
        &.{progress_path},
    );
    defer allocator.free(actual_progress);
    if (!std.mem.eql(u8, expected_progress, actual_progress))
        return error.ProgressPathMismatch;

    const expected_root = try std.fs.path.resolve(
        allocator,
        &.{ stream_root, publication_prefix },
    );
    defer allocator.free(expected_root);
    const actual_root = try std.fs.path.resolve(allocator, &.{proof_root});
    defer allocator.free(actual_root);
    if (!std.mem.eql(u8, expected_root, actual_root))
        return error.PublicationPrefixMismatch;
}

const Options = struct {
    request: []const u8,
    proof_root: []const u8,
    result: []const u8,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 6) return error.InvalidArguments;
        var result: Options = undefined;
        var seen: u3 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len) return error.InvalidArguments;
            const value = arguments[index + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, arguments[index], "--request")) {
                if (seen & 1 != 0) return error.DuplicateArgument;
                seen |= 1;
                result.request = value;
            } else if (std.mem.eql(u8, arguments[index], "--proof-root")) {
                if (seen & 2 != 0) return error.DuplicateArgument;
                seen |= 2;
                result.proof_root = value;
            } else if (std.mem.eql(u8, arguments[index], "--result")) {
                if (seen & 4 != 0) return error.DuplicateArgument;
                seen |= 4;
                result.result = value;
            } else return error.InvalidArguments;
        }
        if (seen != 7) return error.InvalidArguments;
        return result;
    }

    fn resolve(self: Options, allocator: std.mem.Allocator) !Options {
        var result = self;
        result.request = try artifact_io.resolveAbsolute(allocator, self.request);
        errdefer allocator.free(result.request);
        result.proof_root = try artifact_io.resolveAbsolute(
            allocator,
            self.proof_root,
        );
        errdefer allocator.free(result.proof_root);
        result.result = try artifact_io.resolveAbsolute(allocator, self.result);
        return result;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.request);
        allocator.free(self.proof_root);
        allocator.free(self.result);
        self.* = undefined;
    }
};
