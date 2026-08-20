//! Canonical one-attempt producer for the typed-recursion CSP benchmark.
//!
//! The process accepts one sealed workload request, proves and independently
//! verifies the native leaf and active outer proof in-process, then publishes
//! the verifier-owned outer-child wire and its attempt report as one logical
//! transaction. Standard output is not an evidence transport.

const std = @import("std");
const build_identity = @import("build_identity");
const output_transaction = @import("output_transaction");
const stwo = @import("stwo");
const contract = @import("contract.zig");
const pipeline = @import("pipeline.zig");
const report = @import("report.zig");

const atomic_file = stwo.interop.atomic_file;

const Options = struct {
    request_path: []const u8,
    artifact_out: []const u8,
    attempt_out: []const u8,
};

const FailureContext = struct {
    stage: []const u8 = "request_validation",
    request_sha256: ?[32]u8 = null,
    plan_digest: ?[32]u8 = null,
    workload_id: ?[32]u8 = null,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const options = parseOptions(arguments) catch |err| {
        try usage(std.fs.File.stderr().deprecatedWriter());
        return err;
    };
    try output_transaction.prepare(options.artifact_out, options.attempt_out);

    var failure_context: FailureContext = .{};
    run(allocator, options, &failure_context) catch |err| {
        report.failure(
            allocator,
            options.request_path,
            options.artifact_out,
            options.attempt_out,
            failure_context,
            err,
        ) catch |report_err| {
            std.log.err(
                "recursive CSP attempt failed with {s}; failure report failed with {s}",
                .{ @errorName(err), @errorName(report_err) },
            );
            return report_err;
        };
        return err;
    };
}

fn run(
    allocator: std.mem.Allocator,
    options: Options,
    failure: *FailureContext,
) !void {
    var parsed = try contract.parseRequestFile(allocator, options.request_path);
    defer parsed.deinit(allocator);
    failure.request_sha256 = sha256(parsed.raw);
    failure.plan_digest = try parseDigest(parsed.parsed.value.plan_digest);
    failure.workload_id = try parseDigest(parsed.parsed.value.workload_id);

    var pipeline_stage: pipeline.Stage = .request_validation;
    var produced = pipeline.produce(
        allocator,
        parsed.parsed.value,
        parsed.raw,
        .{
            .commit = build_identity.implementation_commit,
            .dirty = build_identity.implementation_dirty,
        },
        &pipeline_stage,
    ) catch |err| {
        failure.stage = @tagName(pipeline_stage);
        return err;
    };
    defer produced.deinit(allocator);

    failure.stage = "artifact_publication";
    const executable_sha256 = try hashSelf();
    const encoded_report = try report.success(
        allocator,
        options.artifact_out,
        parsed.parsed.value,
        executable_sha256,
        &produced,
    );
    defer allocator.free(encoded_report);

    const artifact_temporary = try atomic_file.temporaryPathAlloc(
        allocator,
        options.artifact_out,
        "recursive-wire",
    );
    defer allocator.free(artifact_temporary);
    defer std.fs.cwd().deleteFile(artifact_temporary) catch {};
    try atomic_file.writeExclusive(allocator, artifact_temporary, produced.payload);
    try output_transaction.publishResult(
        atomic_file,
        allocator,
        artifact_temporary,
        options.artifact_out,
        encoded_report,
        options.attempt_out,
        std.fs.File.stdout().deprecatedWriter(),
    );
}

fn parseOptions(arguments: []const []const u8) !Options {
    var request_path: ?[]const u8 = null;
    var artifact_out: ?[]const u8 = null;
    var attempt_out: ?[]const u8 = null;
    var index: usize = 1;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, "--help") or
            std.mem.eql(u8, argument, "-h"))
        {
            try usage(std.fs.File.stdout().deprecatedWriter());
            std.process.exit(0);
        } else if (std.mem.eql(u8, argument, "--request")) {
            if (request_path != null) return error.DuplicateArgument;
            request_path = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--artifact-out")) {
            if (artifact_out != null) return error.DuplicateArgument;
            artifact_out = try next(arguments, &index);
        } else if (std.mem.eql(u8, argument, "--attempt-out")) {
            if (attempt_out != null) return error.DuplicateArgument;
            attempt_out = try next(arguments, &index);
        } else return error.UnknownArgument;
    }
    const result = Options{
        .request_path = request_path orelse return error.MissingRequest,
        .artifact_out = artifact_out orelse return error.MissingArtifactOutput,
        .attempt_out = attempt_out orelse return error.MissingAttemptOutput,
    };
    if (std.mem.eql(u8, result.request_path, result.artifact_out) or
        std.mem.eql(u8, result.request_path, result.attempt_out) or
        std.mem.eql(u8, result.artifact_out, result.attempt_out))
    {
        return error.PathCollision;
    }
    return result;
}

fn next(arguments: []const []const u8, index: *usize) ![]const u8 {
    if (index.* + 1 >= arguments.len) return error.MissingArgumentValue;
    index.* += 1;
    const value = arguments[index.*];
    if (value.len == 0) return error.MissingArgumentValue;
    return value;
}

fn parseDigest(value: []const u8) ![32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn sha256(value: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &result, .{});
    return result;
}

fn hashSelf() ![32]u8 {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fs.selfExePath(&path_buffer);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0)
        return error.InvalidExecutable;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var measured: u64 = 0;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
        measured = try std.math.add(u64, measured, count);
    }
    const after = try file.stat();
    if (measured != before.size or before.size != after.size or
        before.inode != after.inode or before.mtime != after.mtime)
    {
        return error.ExecutableChangedDuringMeasurement;
    }
    return hash.finalResult();
}

fn usage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: stwo-zig-riscv-recursive-csp-producer
        \\       --request PATH --artifact-out PATH --attempt-out PATH
        \\
        \\Consumes one sealed canonical CSP workload. The attempt report is the
        \\machine-readable control plane; stdout is never parsed for evidence.
        \\
    );
}

test "recursive CSP producer CLI rejects duplicate and colliding paths" {
    const valid = [_][]const u8{
        "producer",
        "--request",
        "request.json",
        "--artifact-out",
        "artifact.bin",
        "--attempt-out",
        "attempt.json",
    };
    const parsed = try parseOptions(&valid);
    try std.testing.expectEqualStrings("request.json", parsed.request_path);

    const duplicate = valid ++ [_][]const u8{ "--request", "second.json" };
    try std.testing.expectError(error.DuplicateArgument, parseOptions(&duplicate));
    var collision = valid;
    collision[6] = "request.json";
    try std.testing.expectError(error.PathCollision, parseOptions(&collision));
}
