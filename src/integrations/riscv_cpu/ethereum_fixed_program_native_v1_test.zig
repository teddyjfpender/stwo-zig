//! Real selected-profile gate: one independent program admission reused for
//! both adjacent native leaves; cold verification reconstructs it from ELF.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const admission = @import("ethereum_fixed_program_admission_v1.zig");
const fixture = @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig");
const input_mod = @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const Engine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
const Input = input_mod.FreshInputV4(Engine);
const runtime = @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");
fn sha(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
test "Ethereum fixed program native leaves destroy producer and freshly verify admitted ELF" {
    const allocator = std.testing.allocator;
    const elf = fixture.programElf();
    var artifacts = blk: {
        const program = try admission.OwnedV1.createFromElf(allocator, &elf, sha(&elf));
        defer program.deinit();
        break :blk try fixture.buildArtifactsWithFixedProgramV1(Engine, allocator, program);
    };
    defer artifacts.deinit();
    // Save bytes before cold verification so a genuine failure remains a
    // reproducible input. Export grants custody only, not proof authority.
    try retainNativePair(allocator, &artifacts, &elf);
    // No prepared program, trace, PCS scheme or execution session survives.
    const program = try admission.OwnedV1.createFromElf(allocator, &elf, sha(&elf));
    defer program.deinit();
    const extended = try allocator.alloc(u8, elf.len + 1);
    defer allocator.free(extended);
    @memcpy(extended[0..elf.len], &elf);
    extended[elf.len] = 0x5a;
    const wrong_program = try admission.OwnedV1.createFromElf(allocator, extended, sha(extended));
    defer wrong_program.deinit();
    try std.testing.expectEqual(program.descriptor().compatibility_root, wrong_program.descriptor().compatibility_root);
    for (artifacts.bytes, 0..) |bytes, index| {
        const coordinate = try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, @intCast(index));
        try std.testing.expectError(error.EthereumFixedProgramAdmissionRequired, Input.coldOpen(allocator, bytes, coordinate, .{}));
        try std.testing.expectError(error.EthereumFixedProgramAdmissionMismatch, Input.coldOpenWithProgramAdmission(allocator, bytes, coordinate, .{}, wrong_program));
        var fresh = try Input.coldOpenWithProgramAdmission(allocator, bytes, coordinate, .{}, program);
        defer fresh.deinit();
        try fresh.admitGlobalMetadata(&artifacts.global_metadata[index]);
        try fresh.validate();
        try std.testing.expectEqual(@as(u16, 5), fresh.stage101.profile.schema_version);
        try std.testing.expectEqualDeep(program.descriptor(), fresh.stage101.profile.fixed_program.?);
        try std.testing.expectEqual(@as(u16, 2), fresh.stage101.public_sums.schema_version);
    }
    std.debug.print("ETHEREUM_FIXED_PROGRAM_NATIVE profile=5 leaves=2 producer_destroyed=true independent_elf_reconstructed=true fresh_native_verified=true legacy_entry_rejected=true same_table_wrong_elf_rejected=true\n", .{});
}

fn retainNativePair(allocator: std.mem.Allocator, artifacts: *const fixture.OwnedArtifactsV4(Engine), elf: []const u8) !void {
    const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(corpus);
    const directory = try std.fs.path.join(allocator, &.{ corpus, "fixed-program-narrow-v5" });
    defer allocator.free(directory);
    try runtime.exportStage101ToDirectory(allocator, directory, &artifacts.bytes);
    try runtime.exportProgramElf(directory, elf);
    const metadata = try std.json.Stringify.valueAlloc(allocator, runtime.GlobalReplayMetadataV1{ .leaves = artifacts.global_metadata }, .{});
    defer allocator.free(metadata);
    const manifest = try std.json.Stringify.valueAlloc(allocator, runtime.NativeReplayManifestV1{
        .claim_admission = .fixed_program_narrow_v5,
        .native_sha256 = .{ sha(artifacts.bytes[0]), sha(artifacts.bytes[1]) },
        .program_sha256 = sha(elf),
        .global_metadata_sha256 = sha(metadata),
    }, .{});
    defer allocator.free(manifest);
    try runtime.exportNativeReplayManifest(directory, manifest, metadata);
    std.debug.print("ETHEREUM_FIXED_PROGRAM_NATIVE_CORPUS path={s} manifest_sha256={x} custody_only=true\n", .{ directory, sha(manifest) });
}
