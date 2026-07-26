//! Lifecycle and publication boundary for the Cairo CPU/SIMD product.

const std = @import("std");
const stwo = @import("stwo_cairo_cpu");
const capabilities = @import("capabilities.zig");
const cli = @import("cli.zig");
const execution_adapter = @import("execution_adapter.zig");
const identity = @import("identity.zig");
const profile = @import("profile.zig");

const cairo = stwo.frontends.cairo;
const cairo_cpu = stwo.integrations.cairo_cpu;
const atomic_file = stwo.interop.atomic_file;
const bzip2 = stwo.interop.bzip2;
const output_transaction = stwo.interop.output_transaction;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);
    const parsed = cli.parse(process_args[1..]) catch |err| {
        try cli.writeUsage(std.fs.File.stderr().deprecatedWriter(), null);
        return err;
    };
    switch (parsed) {
        .help => |command| try cli.writeUsage(
            std.fs.File.stdout().deprecatedWriter(),
            command,
        ),
        .capabilities => try writeJsonLine(capabilities.write),
        .identity => try writeJsonLine(identity.write),
        .prove => |request| try prove(allocator, request),
        .run_and_prove => |request| try runAndProve(allocator, request),
    }
}

fn prove(allocator: std.mem.Allocator, request: cli.Prove) !void {
    try output_transaction.prepare(request.proof, request.report_out);
    try proveFile(allocator, request, null);
}

fn runAndProve(
    allocator: std.mem.Allocator,
    request: cli.RunAndProve,
) !void {
    try output_transaction.prepare(request.proof, request.report_out);
    const prover_input = try atomic_file.temporaryPathAlloc(
        allocator,
        request.proof,
        "prover-input",
    );
    defer allocator.free(prover_input);
    defer std.fs.cwd().deleteFile(prover_input) catch {};
    const execution = try execution_adapter.run(allocator, .{
        .program = request.program,
        .program_type = request.program_type.name(),
        .arguments = request.arguments,
        .prover_input_out = prover_input,
    });
    try proveFile(allocator, .{
        .prover_input = prover_input,
        .proof = request.proof,
        .params = request.params,
        .report_out = request.report_out,
        .proof_format = request.proof_format,
        .verify = request.verify,
    }, execution);
}

fn proveFile(
    allocator: std.mem.Allocator,
    request: cli.Prove,
    execution: ?execution_adapter.Receipt,
) !void {
    const owned_manifest = if (request.params == null)
        try profile.defaultManifestPath(allocator)
    else
        null;
    defer if (owned_manifest) |path| allocator.free(path);
    const manifest = request.params orelse owned_manifest.?;
    var paths = try profile.load(allocator, manifest);
    defer paths.deinit();

    const input_sha256 = try execution_adapter.fileSha256(
        request.prover_input,
    );
    var input = try cairo.adapter.official_input.readFile(
        allocator,
        request.prover_input,
    );
    defer input.deinit(allocator);
    if (request.proof_format != .json)
        try cairo.proof.cairo_serde.validateInput(&input);
    var programs = try cairo.witness.bundle.Bundle.readFile(
        allocator,
        paths.witness_programs,
    );
    defer programs.deinit();
    var topology = try cairo.witness.feed_topology.readOfficial(
        allocator,
        paths.witness_topology,
    );
    defer topology.deinit();
    var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(
        allocator,
        paths.fixed_tables,
    );
    defer fixed.deinit();
    var relations = try cairo.witness.relation_bundle.Bundle.readFile(
        allocator,
        paths.relation_templates,
    );
    defer relations.deinit();
    var air_templates = try cairo.air.template_library.Library.readFile(
        allocator,
        paths.air_template_library,
    );
    defer air_templates.deinit();
    const started = std.time.Instant.now() catch return error.ClockUnavailable;
    var result = try cairo_cpu.prover.transaction.proveFixture(
        allocator,
        .{
            .input = &input,
            .programs = &programs,
            .topology = topology,
            .fixed = &fixed,
            .relations = &relations,
            .air_templates = &air_templates,
        },
        paths.variant,
    );
    defer result.deinit();
    const proving_ns = (std.time.Instant.now() catch
        return error.ClockUnavailable).since(started);

    const temporary = try atomic_file.temporaryPathAlloc(
        allocator,
        request.proof,
        "proof",
    );
    defer allocator.free(temporary);
    defer std.fs.cwd().deleteFile(temporary) catch {};
    try writeProof(
        allocator,
        temporary,
        &input,
        &result,
        request.proof_format,
    );
    const verification_started = std.time.Instant.now() catch
        return error.ClockUnavailable;
    if (request.verify)
        try cairo_cpu.prover.transaction.verifyAndConsume(&input, &result);
    const verification_ns = if (request.verify)
        (std.time.Instant.now() catch
            return error.ClockUnavailable).since(verification_started)
    else
        0;
    const proof_sha256 = try execution_adapter.fileSha256(temporary);
    const proof_bytes = (try std.fs.cwd().statFile(temporary)).size;
    const report = try renderReport(
        allocator,
        paths.profile,
        input_sha256,
        proof_sha256,
        proof_bytes,
        proving_ns,
        request.verify,
        verification_ns,
        request.proof_format,
        execution,
    );
    defer allocator.free(report);
    try output_transaction.publishResult(
        atomic_file,
        allocator,
        temporary,
        request.proof,
        report,
        request.report_out,
        std.fs.File.stdout().deprecatedWriter(),
    );
}

fn writeProof(
    allocator: std.mem.Allocator,
    path: []const u8,
    input: *const cairo.adapter.ProverInput,
    result: *const cairo_cpu.prover.transaction.Result,
    proof_format: cli.ProofFormat,
) !void {
    const file = try std.fs.cwd().createFile(path, .{
        .exclusive = true,
        .mode = 0o600,
    });
    defer file.close();
    var buffer: [64 * 1024]u8 = undefined;
    var file_writer = file.writer(&buffer);
    switch (proof_format) {
        .json => {
            try std.json.Stringify.value(
                cairo.proof.json.Document(@TypeOf(result.proof.proof)){
                    .input = input,
                    .composition = &result.composition,
                    .claimed_sums = result.claimed_sums,
                    .interaction_pow = result.interaction_pow,
                    .channel_salt = 0,
                    .preprocessed_variant = result.preprocessed_variant,
                    .stark_proof = &result.proof.proof,
                },
                .{},
                &file_writer.interface,
            );
            try file_writer.interface.writeByte('\n');
        },
        .cairo_serde => try cairo.proof.cairo_serde.writeDocument(
            allocator,
            &file_writer.interface,
            input,
            &result.composition,
            result.claimed_sums,
            result.interaction_pow,
            0,
            &result.proof.proof,
        ),
        .binary => {
            var raw = std.ArrayList(u8).empty;
            defer raw.deinit(allocator);
            try cairo.proof.binary.writeDocument(
                raw.writer(allocator),
                input,
                &result.composition,
                result.claimed_sums,
                result.interaction_pow,
                0,
                result.preprocessed_variant,
                &result.proof.proof,
            );
            const compressed = try bzip2.compressAlloc(allocator, raw.items);
            defer allocator.free(compressed);
            try file_writer.interface.writeAll(compressed);
        },
    }
    try file_writer.interface.flush();
    try file.sync();
}

fn renderReport(
    allocator: std.mem.Allocator,
    profile_name: []const u8,
    input_sha256: [32]u8,
    proof_sha256: [32]u8,
    proof_bytes: u64,
    proving_ns: u64,
    verification_requested: bool,
    verification_ns: u64,
    proof_format: cli.ProofFormat,
    execution: ?execution_adapter.Receipt,
) ![]u8 {
    const input_hex = std.fmt.bytesToHex(input_sha256, .lower);
    const proof_hex = std.fmt.bytesToHex(proof_sha256, .lower);
    const ExecutionJson = struct {
        program_type: []const u8,
        program_sha256: []const u8,
        arguments_sha256: ?[]const u8,
        adapter_sha256: []const u8,
        wall_ns: u64,
    };
    var program_hex: [64]u8 = undefined;
    var arguments_hex: [64]u8 = undefined;
    var adapter_hex: [64]u8 = undefined;
    const execution_json: ?ExecutionJson = if (execution) |receipt| blk: {
        program_hex = std.fmt.bytesToHex(receipt.program_sha256, .lower);
        adapter_hex = std.fmt.bytesToHex(receipt.adapter_sha256, .lower);
        const arguments_sha256: ?[]const u8 = if (receipt.arguments_sha256) |digest| args: {
            arguments_hex = std.fmt.bytesToHex(digest, .lower);
            break :args &arguments_hex;
        } else null;
        break :blk .{
            .program_type = receipt.program_type,
            .program_sha256 = &program_hex,
            .arguments_sha256 = arguments_sha256,
            .adapter_sha256 = &adapter_hex,
            .wall_ns = receipt.execution_ns,
        };
    } else null;
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema_version = @as(u32, 2),
        .product = identity.value(),
        .frontend = "cairo",
        .backend = "cpu",
        .profile = profile_name,
        .execution = execution_json,
        .input = .{ .sha256 = &input_hex },
        .proof = .{
            .format = proof_format.name(),
            .bytes = proof_bytes,
            .sha256 = &proof_hex,
        },
        .timing = .{
            .execute_ns = if (execution) |receipt|
                receipt.execution_ns
            else
                0,
            .prove_ns = proving_ns,
            .verify_ns = verification_ns,
        },
        .verification = .{
            .requested = verification_requested,
            .zig = verification_requested,
        },
    }, .{});
}

fn writeJsonLine(comptime render: anytype) !void {
    var buffer: [8192]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    try render(&output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

test "Cairo CPU report binds input, proof, profile, and product" {
    const encoded = try renderReport(
        std.testing.allocator,
        profile.default_profile,
        [_]u8{0x11} ** 32,
        [_]u8{0x22} ** 32,
        1234,
        5678,
        false,
        0,
        .json,
        null,
    );
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        encoded,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "stwo-cairo-cpu",
        parsed.value.object.get("product").?.object.get("name").?.string,
    );
    try std.testing.expectEqual(
        @as(i64, 1234),
        parsed.value.object.get("proof").?.object.get("bytes").?.integer,
    );
}
