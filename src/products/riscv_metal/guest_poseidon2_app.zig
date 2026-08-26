//! Product transaction for the one admitted guest-Poseidon2 profile.
//!
//! Proving executes the profile-labelled ELF, constructs the exact extension
//! statement, proves through the authenticated profile engine, checks the
//! zero-fallback telemetry again at the publication boundary, independently
//! verifies, shuts the Metal runtime down, and only then atomically publishes
//! the bounded binary artifact. Verification decodes against a caller-selected
//! PCS policy and needs no proving device.

const std = @import("std");
const capabilities = @import("riscv_capabilities");
const cli = @import("cli.zig");
const output_transaction = @import("output_transaction");
const product_identity = @import("product_identity");
const runtime_admission = @import("runtime_admission.zig");
const stwo = @import("stwo_riscv_metal");

const frontend = stwo.frontends.riscv;
const integration = stwo.integrations.riscv_metal;
const profile = integration.guest_precompile;
const Engine = profile.AuthenticatedProfileEngine;
const public_data = frontend.air.public_data;
const proof_artifact = frontend.prover_mod.guest_precompile.proof_artifact;
const atomic_file = stwo.interop.atomic_file;

const maximum_elf_bytes = 16 * 1024 * 1024;
const maximum_input_bytes = 16 * 1024 * 1024;
const artifact_limits: proof_artifact.Limits = .{
    .max_artifact_bytes = 256 * 1024 * 1024,
    .max_proof_bytes = 128 * 1024 * 1024,
    .max_input_bytes = maximum_input_bytes,
    .max_output_bytes = 16 * 1024 * 1024,
    .max_queries = 1024,
    .max_pow_bits = 128,
};

const functional_config = stwo.core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
    .lifting_log_size = null,
};

pub fn run(allocator: std.mem.Allocator, parsed: cli.GuestParsed) !void {
    return switch (parsed) {
        .prove => |request| prove(allocator, request),
        .verify => |request| verify(allocator, request),
        .help => |command| cli.writeGuestUsage(
            std.fs.File.stdout().deprecatedWriter(),
            command,
        ),
    };
}

fn prove(allocator: std.mem.Allocator, request: cli.GuestProve) !void {
    try output_transaction.prepare(request.output, request.report_out);

    var runtime = try runtime_admission.Guard(Engine).init(allocator);
    defer runtime.deinit();

    const elf = try readFileBounded(allocator, request.elf_path, maximum_elf_bytes);
    defer allocator.free(elf);
    const input = if (request.input_path) |path|
        try readFileBounded(allocator, path, maximum_input_bytes)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(input);

    var execution = try frontend.runner.runPoseidon2ExtensionWithInput(
        allocator,
        elf,
        input,
        request.max_steps,
    );
    defer execution.deinit();
    try frontend.prover_mod.admitRunForProving(&execution.base);
    if (execution.calls.len() == 0) return error.GuestProfileCallRequired;
    if (execution.calls.len() != execution.execution_rows.rows().len)
        return error.GuestProfileExecutionAuthorityMismatch;

    var owned_public = try OwnedPublicData.init(allocator, &execution.base);
    defer owned_public.deinit(allocator);
    const config = pcsConfig(request.protocol);
    const telemetry_before = try Engine.telemetrySnapshot();
    var proving_timer = try std.time.Timer.start();
    var output = try profile.provePoseidon2WithPublicData(
        allocator,
        config,
        &execution.base.execution_trace,
        &execution.calls,
        &execution.execution_rows,
        &execution.base.state_chain_tracker,
        &execution.base.rw_memory,
        null,
        owned_public.value,
    );
    const proving_ns = proving_timer.read();
    var proof_moved = false;
    var output_released = false;
    defer if (!output_released) {
        if (proof_moved)
            output.deinitAfterProofMoved(allocator)
        else
            output.deinit(allocator);
    };

    const telemetry_after = try Engine.telemetrySnapshot();
    const delta = telemetry_after.delta(telemetry_before);
    try profile.validateTransactionDelta(delta);
    const lifecycle = Engine.runtimeLifecycleSnapshot();
    try profile.validateRuntimeLifecycle(lifecycle);
    const runtime_identity = lifecycle.identity.?;

    const encoded = try proof_artifact.encodeAllocWithLimits(allocator, .{
        .pcs_config = config,
        .statement = &output.statement,
        .extension = &output.extension,
        .artifact = output.artifact,
        .interaction_claim = output.interaction_claim,
        .proof = &output.proof,
    }, artifact_limits);
    defer allocator.free(encoded);

    var proof_digest: [32]u8 = undefined;
    var elf_digest: [32]u8 = undefined;
    var input_digest: [32]u8 = undefined;
    var output_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &proof_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(elf, &elf_digest, .{});
    std.crypto.hash.sha2.Sha256.hash(input, &input_digest, .{});
    const guest_output = execution.base.output orelse if (execution.base.output_len == 0)
        &[_]u8{}
    else
        return error.MissingGuestOutput;
    std.crypto.hash.sha2.Sha256.hash(guest_output, &output_digest, .{});

    var verification_timer = try std.time.Timer.start();
    proof_moved = true;
    try profile.verifyPoseidon2(
        allocator,
        config,
        output.statement,
        output.extension,
        output.artifact,
        output.proof,
        output.interaction_claim,
    );
    const verification_ns = verification_timer.read();

    const manifest_digest = runtime_identity.manifest_sha256.?;
    const metallib_digest = runtime_identity.metallib_sha256.?;
    const proof_hex = std.fmt.bytesToHex(proof_digest, .lower);
    const elf_hex = std.fmt.bytesToHex(elf_digest, .lower);
    const input_hex = std.fmt.bytesToHex(input_digest, .lower);
    const output_hex = std.fmt.bytesToHex(output_digest, .lower);
    const manifest_hex = std.fmt.bytesToHex(manifest_digest, .lower);
    const metallib_hex = std.fmt.bytesToHex(metallib_digest, .lower);
    const statement_hex = std.fmt.bytesToHex(
        output.artifact.statement_digest,
        .lower,
    );
    const counters = delta.counters;
    const report = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = "stwo.riscv-metal.guest-poseidon2.prove.v1",
        .product = .{
            .name = product_identity.product,
            .identity_sha256 = product_identity.identity_sha256,
            .implementation_commit = product_identity.implementation_commit,
            .implementation_dirty = product_identity.implementation_dirty,
        },
        .profile = profileReceipt(),
        .security = protocolName(request.protocol),
        .pcs = pcsReceipt(config),
        .source = .{
            .elf_sha256 = &elf_hex,
            .input_sha256 = &input_hex,
            .output_sha256 = &output_hex,
        },
        .proof = .{
            .artifact_format = proof_artifact.format_version,
            .artifact_bytes = encoded.len,
            .artifact_sha256 = &proof_hex,
            .statement_sha256 = &statement_hex,
            .verified_before_publication = true,
            .output_path = request.output,
        },
        .execution = .{
            .steps = execution.base.step_count,
            .calls = execution.calls.len(),
            .proving_ns = proving_ns,
            .verification_ns = verification_ns,
        },
        .runtime = .{
            .origin = @tagName(runtime_identity.origin),
            .requirement = profile.runtime_requirement,
            .manifest_sha256 = &manifest_hex,
            .metallib_sha256 = &metallib_hex,
            .metallib_bytes = runtime_identity.metallib_bytes.?,
            .shutdown_before_publication = true,
        },
        .telemetry = .{
            .classification = @tagName(delta.classification()),
            .metal_dispatches = counters.metalDispatchTotal(),
            .cpu_fallbacks = counters.cpuFallbackTotal(),
            .zero_backend_fallbacks = counters.cpuFallbackTotal() == 0,
            .resident_merkle_commits = counters.resident_merkle_commits,
            .eligible_base_components = counters.riscv_base_polynomial_eligible_components,
            .eligible_lookup_components = counters.riscv_lookup_polynomial_eligible_components,
            .base_batch_dispatches = counters.metal_riscv_base_polynomial_batch_dispatches,
            .lookup_batch_dispatches = counters.metal_riscv_lookup_polynomial_batch_dispatches,
            .host_merkle_commits = counters.host_merkle_commits,
            .cpu_small_merkle_commits = counters.cpu_small_merkle_commits,
            .cpu_streaming_merkle_commits = counters.cpu_streaming_merkle_commits,
            .cpu_sampled_value_evaluations = counters.cpu_sampled_value_evaluations,
            .cpu_small_circle_interpolations = counters.cpu_small_circle_interpolations,
            .cpu_small_circle_evaluations = counters.cpu_small_circle_evaluations,
            .cpu_small_circle_ldes = counters.cpu_small_circle_ldes,
            .cpu_composition_evaluations = counters.cpu_composition_evaluations,
            .cpu_riscv_polynomial_composition_declines = counters.cpu_riscv_polynomial_composition_declines,
        },
    }, .{});
    defer allocator.free(report);

    output.deinitAfterProofMoved(allocator);
    output_released = true;
    try runtime.finish();

    const temporary = try atomic_file.temporaryPathAlloc(
        allocator,
        request.output,
        "guest-poseidon2-proof",
    );
    defer allocator.free(temporary);
    defer std.fs.cwd().deleteFile(temporary) catch {};
    try atomic_file.writeExclusive(allocator, temporary, encoded);
    try output_transaction.publishResult(
        atomic_file,
        allocator,
        temporary,
        request.output,
        report,
        request.report_out,
        std.fs.File.stdout().deprecatedWriter(),
    );
}

fn verify(allocator: std.mem.Allocator, request: cli.GuestVerify) !void {
    const encoded = try readFileBounded(
        allocator,
        request.artifact,
        artifact_limits.max_artifact_bytes,
    );
    defer allocator.free(encoded);
    const config = pcsConfig(request.protocol);
    var decoded = try proof_artifact.decodeAllocForConfig(
        allocator,
        encoded,
        config,
        artifact_limits,
    );
    var proof_moved = false;
    defer if (proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);

    var artifact_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &artifact_digest, .{});
    const artifact_hex = std.fmt.bytesToHex(artifact_digest, .lower);
    const statement_hex = std.fmt.bytesToHex(
        decoded.artifact.statement_digest,
        .lower,
    );
    proof_moved = true;
    try profile.verifyPoseidon2(
        allocator,
        config,
        decoded.statement,
        decoded.extension,
        decoded.artifact,
        decoded.proof,
        decoded.interaction_claim,
    );

    const receipt = try std.json.Stringify.valueAlloc(allocator, .{
        .schema = "stwo.riscv-metal.guest-poseidon2.verify.v1",
        .product = product_identity.product,
        .profile = profileReceipt(),
        .security = protocolName(request.protocol),
        .artifact_sha256 = &artifact_hex,
        .statement_sha256 = &statement_hex,
        .verified = true,
        .verification_requires_metal_device = false,
    }, .{});
    defer allocator.free(receipt);
    try std.fs.File.stdout().deprecatedWriter().print("{s}\n", .{receipt});
}

fn profileReceipt() @TypeOf(.{
    .identity = profile.profile_identity,
    .version = profile.profile_version,
    .capability = profile.capability_identity,
    .manifest_sha256 = capabilities.guest_poseidon2.manifest_sha256,
    .caller_component = profile.caller_component_identity,
    .provider_component = profile.provider_component_identity,
    .execution_placement = profile.execution_placement,
    .backend_fallback_allowed = profile.backend_fallback_allowed,
}) {
    return .{
        .identity = profile.profile_identity,
        .version = profile.profile_version,
        .capability = profile.capability_identity,
        .manifest_sha256 = capabilities.guest_poseidon2.manifest_sha256,
        .caller_component = profile.caller_component_identity,
        .provider_component = profile.provider_component_identity,
        .execution_placement = profile.execution_placement,
        .backend_fallback_allowed = profile.backend_fallback_allowed,
    };
}

fn pcsConfig(protocol: cli.Protocol) stwo.core.pcs.PcsConfig {
    return switch (protocol) {
        .secure => frontend.prover_mod.SECURE_PCS_CONFIG,
        .functional => functional_config,
        .smoke => unreachable,
    };
}

fn protocolName(protocol: cli.Protocol) []const u8 {
    return switch (protocol) {
        .secure => "secure",
        .functional => "functional-development",
        .smoke => unreachable,
    };
}

fn pcsReceipt(config: stwo.core.pcs.PcsConfig) @TypeOf(.{
    .pow_bits = config.pow_bits,
    .log_blowup_factor = config.fri_config.log_blowup_factor,
    .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
    .n_queries = config.fri_config.n_queries,
    .fold_step = config.fri_config.fold_step,
    .lifting_log_size = config.lifting_log_size,
}) {
    return .{
        .pow_bits = config.pow_bits,
        .log_blowup_factor = config.fri_config.log_blowup_factor,
        .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
        .n_queries = config.fri_config.n_queries,
        .fold_step = config.fri_config.fold_step,
        .lifting_log_size = config.lifting_log_size,
    };
}

fn readFileBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    if (path.len == 0) return error.InvalidPath;
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size > maximum_bytes)
        return error.InputResourceLimitExceeded;
    const length = std.math.cast(usize, stat.size) orelse
        return error.InputResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.UnexpectedEndOfFile;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.InputChangedDuringRead;
    return bytes;
}

const OwnedPublicData = struct {
    input_words: []u32,
    output_words: []public_data.OutputWord,
    value: public_data.PublicData,

    fn init(
        allocator: std.mem.Allocator,
        execution: *const frontend.runner.RunResult,
    ) !OwnedPublicData {
        const input_words = try public_data.packInputWords(allocator, execution.input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(
            public_data.OutputWord,
            execution.output_words.len,
        );
        errdefer allocator.free(output_words);
        for (output_words, execution.output_words) |*destination, source| {
            destination.* = .{
                .addr = source.addr,
                .value = source.value,
                .clock = source.clock,
            };
        }
        return .{
            .input_words = input_words,
            .output_words = output_words,
            .value = .{
                .initial_pc = execution.initial_pc,
                .final_pc = execution.final_pc,
                .clock = std.math.cast(u32, execution.step_count) orelse
                    return error.ExecutionClockOutOfRange,
                .initial_regs = execution.initial_regs,
                .final_regs = execution.final_regs,
                .reg_last_clock = execution.state_chain_tracker.reg_last_clk,
                .program_root = null,
                .initial_rw_root = null,
                .final_rw_root = null,
                .completion = try public_data.completionFromRun(execution.*),
                .io_entries = .{
                    .input_start = execution.input_start,
                    .input_len = std.math.cast(u32, execution.input.len) orelse
                        return error.InputLengthOutOfRange,
                    .input_words = input_words,
                    .output_len = execution.output_len,
                    .output_len_addr = execution.output_len_addr,
                    .output_data_addr = execution.output_data_addr,
                    .output_words = output_words,
                },
            },
        };
    }

    fn deinit(self: *OwnedPublicData, allocator: std.mem.Allocator) void {
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        self.* = undefined;
    }
};

test "guest product identity matches the admitted integration profile" {
    try std.testing.expectEqualStrings(
        capabilities.guest_poseidon2.profile,
        profile.profile_identity,
    );
    try std.testing.expectEqual(
        capabilities.guest_poseidon2.version,
        profile.profile_version,
    );
    try std.testing.expectEqualStrings(
        capabilities.guest_poseidon2.capability,
        profile.capability_identity,
    );
    try std.testing.expectEqualStrings(
        capabilities.guest_poseidon2.execution_placement,
        profile.execution_placement,
    );
    try std.testing.expectEqual(
        capabilities.guest_poseidon2.backend_fallback_allowed,
        profile.backend_fallback_allowed,
    );
}

test "guest product defaults secure and labels functional evidence" {
    try std.testing.expectEqual(
        frontend.prover_mod.SECURE_PCS_CONFIG,
        pcsConfig(.secure),
    );
    try std.testing.expectEqual(functional_config, pcsConfig(.functional));
    try std.testing.expectEqualStrings("secure", protocolName(.secure));
    try std.testing.expectEqualStrings(
        "functional-development",
        protocolName(.functional),
    );
}
