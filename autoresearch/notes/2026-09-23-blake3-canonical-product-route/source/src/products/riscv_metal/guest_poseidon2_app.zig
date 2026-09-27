//! Historical guest-Poseidon artifact verification. Proving uses the shared BLAKE3 CLI.

const std = @import("std");
const capabilities = @import("riscv_capabilities");
const cli = @import("cli.zig");
const product_identity = @import("product_identity");
const stwo = @import("stwo_riscv_metal");

const frontend = stwo.frontends.riscv;
const integration = stwo.integrations.riscv_metal;
const profile = integration.guest_precompile;
const proof_artifact = frontend.prover_mod.guest_precompile.proof_artifact;

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
        .prove => error.LegacyProofGenerationRemoved,
        .verify => |request| verify(allocator, request),
        .help => |command| cli.writeGuestUsage(
            std.fs.File.stdout().deprecatedWriter(),
            command,
        ),
    };
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
