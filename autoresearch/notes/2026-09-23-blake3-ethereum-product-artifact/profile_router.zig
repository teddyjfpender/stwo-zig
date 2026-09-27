//! Exact wire/profile routing kept outside the base adapter transaction.

const std = @import("std");
const stwo = @import("stwo");
const artifact_validation = @import("artifact_validation.zig");
const artifact_verifier = @import("artifact_verifier.zig");
const guest_profile = @import("guest_profile.zig");
const guest_profile_verifier = @import("guest_profile_verifier.zig");
const blake3_execution_verifier = @import("blake3_execution_verifier.zig");
const pcs_profile = @import("pcs_profile.zig");

pub fn runIfSelected(
    comptime Engine: type,
    comptime backend: anytype,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: anytype,
    process_identity: artifact_validation.ProcessIdentity,
) !?[]u8 {
    const requested = try requestedExecutionProfile(allocator, elf_path);
    if (requested == .rv32im_zkvm_v1) {
        if (comptime Engine.Hasher == stwo.core.proof_suites.Blake3.Hasher) {
            return try @import("blake3_execution_product.zig").run(Engine, backend, false, allocator, elf_path, input_path, options, process_identity);
        }
        return null;
    }
    if (comptime Engine.Hasher == stwo.core.proof_suites.Blake3.Hasher) {
        if (requested == .rv32im_zkvm_ethereum_v1)
            return try @import("blake3_execution_product.zig").run(Engine, backend, true, allocator, elf_path, input_path, options, process_identity);
    }
    return try guest_profile.run(
        Engine,
        backend,
        allocator,
        elf_path,
        input_path,
        options,
        process_identity,
    );
}

/// Routes by exact wire identity. Full-width BLAKE3 admission is separate from
/// legacy JSON and guest-profile envelopes.
pub fn verifyPath(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    artifact_path: []const u8,
    requested_policy: pcs_profile.Protocol,
    expected_statement_digest: [32]u8,
    elf_path: []const u8,
    input_path: ?[]const u8,
) !void {
    var file = if (std.fs.path.isAbsolute(artifact_path))
        try std.fs.openFileAbsolute(artifact_path, .{})
    else
        try std.fs.cwd().openFile(artifact_path, .{});
    defer file.close();
    var prefix: [8]u8 = undefined;
    const prefix_len = try file.readAll(&prefix);
    if (stwo.frontends.riscv.prover_mod.blake3_ethereum_artifact.hasMagic(prefix[0..prefix_len])) {
        return blake3_execution_verifier.verifyProfile(Engine, true, allocator, artifact_path, requested_policy, expected_statement_digest, elf_path, input_path);
    }
    if (blake3_execution_verifier.hasMagic(prefix[0..prefix_len])) {
        return blake3_execution_verifier.verifyPath(Engine, allocator, artifact_path, requested_policy, expected_statement_digest, elf_path, input_path);
    }
    if (guest_profile_verifier.hasMagic(prefix[0..prefix_len])) {
        return guest_profile_verifier.verifyPath(
            Engine,
            allocator,
            artifact_path,
            requested_policy,
            expected_statement_digest,
            elf_path,
            input_path,
        );
    }
    if (input_path != null) return error.IrrelevantInputBinding;
    var classified = try stwo.interop.riscv_artifact.classifyPath(
        allocator,
        artifact_path,
    );
    defer classified.deinit(allocator);
    return switch (classified) {
        .riscv => |parsed| artifact_verifier.verify(
            Engine,
            allocator,
            parsed.value,
            requested_policy,
            expected_statement_digest,
            elf_path,
        ),
        .other => error.UnsupportedArtifactKind,
    };
}

fn requestedExecutionProfile(
    allocator: std.mem.Allocator,
    elf_path: []const u8,
) !stwo.frontends.riscv.isa.execution_profile.ExecutionProfile {
    const bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        elf_path,
        64 * 1024 * 1024,
    );
    defer allocator.free(bytes);
    return stwo.frontends.riscv.runner.elf_loader.requestedExecutionProfile(bytes);
}
