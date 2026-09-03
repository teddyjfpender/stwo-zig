//! Diagnostic-only pre-Engine geometry snapshot for one expected real leaf.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_contract = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const support = @import("ethereum_block_leaf_support.zig");

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
            try inspectAndPublish(
                allocator,
                options,
                request,
                &authority.expected,
                &segment,
                executable_sha,
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

fn inspectAndPublish(
    allocator: std.mem.Allocator,
    options: Options,
    request: *const product.Request,
    expected: *const support.source_wire.Source,
    segment: *const frontend.runner.EthereumSegmentResult,
    executable_sha: [32]u8,
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

    const log_blowup_factor =
        support.recursive_pcs_config.fri_config.log_blowup_factor;
    var geometry = try support.prover.inspectEthereumSegmentPreEngineGeometry(
        allocator,
        log_blowup_factor,
        &projection.local_result,
        &segment.keccakf_calls,
        &segment.keccakf_execution_rows,
        &segment.signer_recovery_calls,
        &segment.signer_recovery_execution_rows,
        public.value,
    );
    defer geometry.deinit();
    const encoded = try geometry_contract.encode(allocator, .{
        .geometry = &geometry,
        .log_blowup_factor = log_blowup_factor,
        .producer_sha256 = executable_sha,
        .request = request_identity,
        .request_content_sha256 = try contract.parseSha256(
            request.content_sha256,
        ),
        .request_value = request,
    });
    defer allocator.free(encoded);
    try geometry_contract.publishCreateOnly(options.snapshot, encoded);
}

const Options = struct {
    request: []const u8,
    snapshot: []const u8,

    fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 4) return error.InvalidArguments;
        var result = Options{ .request = undefined, .snapshot = undefined };
        var seen: u2 = 0;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            if (index + 1 >= arguments.len or arguments[index + 1].len == 0)
                return error.InvalidArguments;
            const name = arguments[index];
            const value = arguments[index + 1];
            if (std.mem.eql(u8, name, "--request")) {
                if (seen & 1 != 0) return error.DuplicateArgument;
                seen |= 1;
                result.request = value;
            } else if (std.mem.eql(u8, name, "--snapshot")) {
                if (seen & 2 != 0) return error.DuplicateArgument;
                seen |= 2;
                result.snapshot = value;
            } else return error.InvalidArguments;
        }
        if (seen != 3) return error.InvalidArguments;
        return result;
    }

    fn resolve(self: Options, allocator: std.mem.Allocator) !Options {
        const request = try artifact_io.resolveAbsolute(allocator, self.request);
        errdefer allocator.free(request);
        const snapshot = try artifact_io.resolveAbsolute(allocator, self.snapshot);
        return .{ .request = request, .snapshot = snapshot };
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.request);
        allocator.free(self.snapshot);
        self.* = undefined;
    }
};

pub const testing = struct {
    pub fn parse(arguments: []const []const u8) !void {
        _ = try Options.parse(arguments);
    }
};
