//! Shared lifecycle and publication boundary for Cairo proving products.

const std = @import("std");
const cli = @import("cli.zig");
const execution_adapter = @import("execution_adapter.zig");
const profile = @import("profile.zig");

pub const BackendEvidence = struct {
    execution: []const u8,
    classification: []const u8,
    metal_dispatches: u64 = 0,
    cpu_fallbacks: u64 = 0,
    runtime_initializations: u64 = 0,
    runtime_shutdowns: u64 = 0,
};

pub fn run(comptime Product: type) !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);
    const parsed = cli.parse(process_args[1..]) catch |err| {
        try writeUsage(
            Product,
            std.fs.File.stderr().deprecatedWriter(),
            null,
        );
        return err;
    };
    switch (parsed) {
        .help => |command| try writeUsage(
            Product,
            std.fs.File.stdout().deprecatedWriter(),
            command,
        ),
        .capabilities => try writeJsonLine(Product.capabilities.write),
        .identity => try writeJsonLine(Product.identity.write),
        .prove => |request| try prove(Product, allocator, request),
        .run_and_prove => |request| try runAndProve(
            Product,
            allocator,
            request,
        ),
    }
}

fn writeUsage(
    comptime Product: type,
    writer: anytype,
    command: ?cli.Command,
) !void {
    return cli.writeUsage(
        writer,
        command,
        Product.name,
        Product.backend_description,
    );
}

fn prove(
    comptime Product: type,
    allocator: std.mem.Allocator,
    request: cli.Prove,
) !void {
    try Product.stwo.interop.output_transaction.prepare(
        request.proof,
        request.report_out,
    );
    try proveFile(Product, allocator, request, null);
}

fn runAndProve(
    comptime Product: type,
    allocator: std.mem.Allocator,
    request: cli.RunAndProve,
) !void {
    try Product.stwo.interop.output_transaction.prepare(
        request.proof,
        request.report_out,
    );
    const prover_input = try Product.stwo.interop.atomic_file.temporaryPathAlloc(
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
    try proveFile(Product, allocator, .{
        .prover_input = prover_input,
        .proof = request.proof,
        .params = request.params,
        .report_out = request.report_out,
        .stage_profile_out = request.stage_profile_out,
        .proof_format = request.proof_format,
        .verify = request.verify,
    }, execution);
}

fn proveFile(
    comptime Product: type,
    allocator: std.mem.Allocator,
    request: cli.Prove,
    execution: ?execution_adapter.Receipt,
) !void {
    const cairo = Product.stwo.frontends.cairo;
    const transaction = Product.transaction;
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
    var proof_context = try Product.beginProof(allocator);
    var proof_context_owned = true;
    defer if (proof_context_owned) Product.abortProof(&proof_context);
    const stage_profile = Product.stwo.prover.stage_profile;
    var maybe_recorder: ?stage_profile.Recorder =
        if (request.stage_profile_out != null)
            stage_profile.Recorder.init(
                allocator,
                Product.backend_name,
                "cairo",
            )
        else
            null;
    defer if (maybe_recorder) |*recorder| recorder.deinit();
    var result = try transaction.proveFixtureWithRecorder(
        allocator,
        .{
            .input = &input,
            .programs = &programs,
            .generated_executor = Product.witnessExecutor(),
            .interaction_executor = Product.interactionExecutor(&proof_context),
            .topology = topology,
            .fixed = &fixed,
            .relations = &relations,
            .air_templates = &air_templates,
        },
        paths.variant,
        if (maybe_recorder) |*recorder| recorder else null,
    );
    var result_owned = true;
    defer if (result_owned) result.deinit();
    const proving_ns = (std.time.Instant.now() catch
        return error.ClockUnavailable).since(started);
    if (request.stage_profile_out) |path|
        try writeStageProfile(
            Product,
            allocator,
            &maybe_recorder.?,
            path,
        );

    const temporary = try Product.stwo.interop.atomic_file.temporaryPathAlloc(
        allocator,
        request.proof,
        "proof",
    );
    defer allocator.free(temporary);
    defer std.fs.cwd().deleteFile(temporary) catch {};
    try writeProof(
        Product,
        allocator,
        temporary,
        &input,
        &result,
        request.proof_format,
    );
    const verification_started = std.time.Instant.now() catch
        return error.ClockUnavailable;
    if (request.verify)
        try transaction.verifyAndConsume(&input, &result);
    const verification_ns = if (request.verify)
        (std.time.Instant.now() catch
            return error.ClockUnavailable).since(verification_started)
    else
        0;
    const proof_sha256 = try execution_adapter.fileSha256(temporary);
    const proof_bytes = (try std.fs.cwd().statFile(temporary)).size;
    var backend_evidence = try Product.finishProof(&proof_context);
    result.deinit();
    result_owned = false;
    backend_evidence = try Product.endProof(
        &proof_context,
        backend_evidence,
    );
    proof_context_owned = false;
    const report = try renderReport(
        Product,
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
        backend_evidence,
    );
    defer allocator.free(report);
    try Product.stwo.interop.output_transaction.publishResult(
        Product.stwo.interop.atomic_file,
        allocator,
        temporary,
        request.proof,
        report,
        request.report_out,
        std.fs.File.stdout().deprecatedWriter(),
    );
}

fn writeStageProfile(
    comptime Product: type,
    allocator: std.mem.Allocator,
    recorder: *Product.stwo.prover.stage_profile.Recorder,
    path: []const u8,
) !void {
    var stage_snapshot = try recorder.snapshot(allocator);
    defer stage_snapshot.deinit(allocator);
    const rendered = try std.json.Stringify.valueAlloc(
        allocator,
        stage_snapshot,
        .{},
    );
    defer allocator.free(rendered);
    try std.fs.cwd().writeFile(.{
        .sub_path = path,
        .data = rendered,
    });
}

fn writeProof(
    comptime Product: type,
    allocator: std.mem.Allocator,
    path: []const u8,
    input: *const Product.stwo.frontends.cairo.adapter.ProverInput,
    result: *const Product.transaction.Result,
    proof_format: cli.ProofFormat,
) !void {
    const cairo = Product.stwo.frontends.cairo;
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
            const compressed = try Product.stwo.interop.bzip2.compressAlloc(
                allocator,
                raw.items,
            );
            defer allocator.free(compressed);
            try file_writer.interface.writeAll(compressed);
        },
    }
    try file_writer.interface.flush();
    try file.sync();
}

fn renderReport(
    comptime Product: type,
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
    backend_evidence: anytype,
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
        .product = Product.identity.value(),
        .frontend = "cairo",
        .backend = Product.backend_name,
        .backend_evidence = backend_evidence,
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
