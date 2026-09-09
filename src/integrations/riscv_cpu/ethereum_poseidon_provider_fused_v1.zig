//! Additive single-process capture -> prepared omitted-core route.
//!
//! The retained `capture-calls` and `prove-combined` phases are unchanged.
//! This diagnostic route executes the requested segment once, publishes the
//! exact call artifact, cold-reopens it for custody, seals stage telemetry,
//! and only then passes the still-live prepared segment to the caller's proof
//! continuation.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const geometry_contract = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");
const legacy = @import("ethereum_poseidon_provider_orchestration_v1.zig");
const prepared_capture = @import("ethereum_poseidon_provider_prepared_capture_v1.zig");
const prepared_receipt = @import("ethereum_poseidon_provider_prepared_capture_receipt_v1.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");
const product_support = @import("ethereum_poseidon_leaf_product_support.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    comptime consumePrepared: anytype,
) !void {
    var options = try Options.parse(allocator, arguments);
    defer options.deinit(allocator);
    try options.requireDistinct();
    try artifact_io.createDirectoryCreateOnly(options.output_root);

    var total_clock = try evidence.Clock.start();
    const request_bytes = try artifact_io.readFileBounded(
        allocator,
        options.request,
        contract.max_json_bytes,
    );
    defer allocator.free(request_bytes);
    var parsed_request = try product.parseRequest(allocator, request_bytes);
    defer parsed_request.deinit();
    const request = &parsed_request.value;
    const executable_sha256 = try support.executableSha256(allocator);
    try legacy.requireExecutableRequest(request, executable_sha256);
    const request_file = evidence.identity(options.request, request_bytes);

    const geometry_bytes = try artifact_io.readFileBounded(
        allocator,
        options.geometry,
        geometry_contract.max_snapshot_bytes,
    );
    defer allocator.free(geometry_bytes);
    var geometry = try geometry_contract.parse(allocator, geometry_bytes);
    defer geometry.deinit();
    const geometry_file = evidence.identity(options.geometry, geometry_bytes);
    try legacy.validateGeometryAgainstRequest(
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

    var execution_clock = try evidence.Clock.start();
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
            const execution_timing = try execution_clock.finish();
            var preparation = try prepared_capture.prepare(
                allocator,
                &source_authority.expected,
                &segment,
                try contract.parseSha256(request.session_id),
            );
            defer preparation.deinit();
            const custody = try prepared_capture.publishCallCustody(
                allocator,
                &preparation.prepared,
                options.calls,
                options.call_artifact,
                request,
                request_file,
                geometry.value,
                geometry_file,
                &resource_plan,
                executable_sha256,
            );
            var opened = try legacy.OpenedCallAuthority.open(
                allocator,
                options.call_artifact,
            );
            defer opened.deinit(allocator);
            if (!std.meta.eql(
                opened.artifact_file.sha256,
                custody.artifact_file.sha256,
            )) {
                return error.PreparedCallCustodyMismatch;
            }
            try prepared_capture.requireCallCustodyParity(
                preparation.prepared.calls.calls,
                opened.calls.calls,
                preparation.prepared.call_list_commitment,
                opened.plan.call_list_commitment,
                preparation.prepared.calls.public_data_wire_id,
                opened.calls.public_data_wire_id,
            );
            const stage_bytes = try encodeStageReceipt(
                allocator,
                request,
                request_file,
                geometry_file,
                custody,
                &preparation,
                executable_sha256,
                execution_timing,
                try total_clock.finish(),
            );
            defer allocator.free(stage_bytes);
            try prepared_receipt.publishCreateOnly(
                options.stage_receipt,
                stage_bytes,
            );
            return consumePrepared(
                allocator,
                options.output_root,
                &opened,
                &source_authority.expected,
                &segment,
                &preparation.prepared,
            );
        }
        continuation = segment.base.continuation;
        if (continuation == null) return error.MissingContinuation;
    }
    unreachable;
}

fn encodeStageReceipt(
    allocator: std.mem.Allocator,
    request: *const product.Request,
    request_file: evidence.FileIdentity,
    geometry_file: evidence.FileIdentity,
    custody: prepared_capture.PublishedCallCustodyV1,
    preparation: *const prepared_capture.PreparationV1,
    executable_sha256: [32]u8,
    execution_timing: evidence.Timing,
    total_timing: evidence.Timing,
) ![]u8 {
    const placeholder = [_]u8{'0'} ** 64;
    const call_file_sha = hex(custody.artifact_file.sha256);
    const call_content = hex(custody.content_sha256);
    const call_list = hex(preparation.prepared.call_list_commitment);
    const executable = hex(executable_sha256);
    const geometry_sha = hex(geometry_file.sha256);
    const prepared_identity = hex(preparation.prepared.identity);
    const public_wire = hex(product_support.fieldDigestBytes(
        preparation.prepared.public_data.wireId(),
    ));
    const request_sha = hex(request_file.sha256);
    return prepared_receipt.encode(allocator, .{
        .content_sha256 = &placeholder,
        .call_artifact = identity(
            custody.artifact_file,
            &call_file_sha,
        ),
        .call_artifact_content_sha256 = &call_content,
        .call_authority_build_count = 1,
        .call_authority_build_timing = preparation.call_authority_build_timing,
        .call_list_commitment_sha256 = &call_list,
        .executable_sha256 = &executable,
        .execution_pass_count = 1,
        .execution_timing = execution_timing,
        .geometry_snapshot = identity(geometry_file, &geometry_sha),
        .prepared_identity_sha256 = &prepared_identity,
        .prepare_timing = preparation.prepare_timing,
        .production_eligible = false,
        .public_data_wire_id_sha256 = &public_wire,
        .recursive_admissible = false,
        .reexecution_eliminated = true,
        .request = identity(request_file, &request_sha),
        .request_content_sha256 = request.content_sha256,
        .schema = prepared_receipt.schema,
        .segment_index = request.segment_index,
        .status = prepared_receipt.status,
        .total_timing = total_timing,
    });
}

const Options = struct {
    request: []u8,
    geometry: []u8,
    calls: []u8,
    call_artifact: []u8,
    stage_receipt: []u8,
    output_root: []u8,

    fn parse(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        const names = [_][]const u8{
            "--request",
            "--geometry",
            "--calls",
            "--call-artifact",
            "--stage-receipt",
            "--output-root",
        };
        if (arguments.len != 2 * names.len) return error.InvalidArguments;
        var values: [names.len]?[]const u8 = .{null} ** names.len;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            var found = false;
            for (names, 0..) |expected, index| {
                if (!std.mem.eql(u8, name, expected)) continue;
                if (values[index] != null) return error.DuplicateArgument;
                values[index] = value;
                found = true;
                break;
            }
            if (!found) return error.InvalidArguments;
        }
        var resolved: [names.len][]u8 = undefined;
        var initialized: usize = 0;
        errdefer for (resolved[0..initialized]) |path| allocator.free(path);
        for (&resolved, values) |*destination, maybe_value| {
            destination.* = try artifact_io.resolveAbsolute(
                allocator,
                maybe_value orelse return error.InvalidArguments,
            );
            initialized += 1;
        }
        return .{
            .request = resolved[0],
            .geometry = resolved[1],
            .calls = resolved[2],
            .call_artifact = resolved[3],
            .stage_receipt = resolved[4],
            .output_root = resolved[5],
        };
    }

    fn requireDistinct(self: Options) !void {
        const paths = [_][]const u8{
            self.request,
            self.geometry,
            self.calls,
            self.call_artifact,
            self.stage_receipt,
            self.output_root,
        };
        for (paths, 0..) |left, index|
            for (paths[index + 1 ..]) |right|
                if (std.mem.eql(u8, left, right))
                    return error.DuplicateProviderFusedPath;
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.output_root);
        allocator.free(self.stage_receipt);
        allocator.free(self.call_artifact);
        allocator.free(self.calls);
        allocator.free(self.geometry);
        allocator.free(self.request);
        self.* = undefined;
    }
};

fn identity(
    value: evidence.FileIdentity,
    digest: *const [64]u8,
) contract.Identity {
    return .{ .bytes = value.bytes, .path = value.path, .sha256 = digest };
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

pub const testing = struct {
    pub fn parseOptions(allocator: std.mem.Allocator) !void {
        var options = try Options.parse(allocator, &.{
            "--output-root",
            "/fresh/result",
            "--calls",
            "/fresh/calls.stwepc01",
            "--geometry",
            "/retained/geometry.json",
            "--stage-receipt",
            "/fresh/stage.json",
            "--request",
            "/retained/request.json",
            "--call-artifact",
            "/fresh/calls.json",
        });
        defer options.deinit(allocator);
        try options.requireDistinct();
        try std.testing.expectError(
            error.InvalidArguments,
            Options.parse(allocator, &.{ "--request", "/one" }),
        );
    }
};
