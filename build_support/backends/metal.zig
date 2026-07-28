//! Metal toolchain, runtime source, and link ownership.

const std = @import("std");
const construction_observer = @import("../graph/construction_observer.zig");
const graph_identity = @import("../graph/identity.zig");

pub const runtime_source = "src/backends/metal/runtime.m";
pub const shader_manifest_source = "src/backends/metal/shader_manifest.zig";
pub const runtime_modes = "source-jit";

const runtime_source_units = [_][]const u8{
    runtime_source,
    "src/backends/metal/runtime_profile.m",
    "src/backends/metal/runtime/compile_options.h",
    "src/backends/metal/runtime/abi.h",
    "src/backends/metal/runtime/initialization.m",
    "src/backends/metal/runtime/runtime_queries.m",
    "src/backends/metal/runtime/fri_fold_commit.m",
    "src/backends/metal/runtime/fri_plans.m",
    "src/backends/metal/runtime/transcript_decommitment.m",
    "src/backends/metal/runtime/witness_primitives.m",
    "src/backends/metal/runtime/resource_plans.m",
    "src/backends/metal/runtime/circle_plans.m",
    "src/backends/metal/runtime/merkle_epochs.m",
    "src/backends/metal/runtime/auxiliary_plans.m",
    "src/backends/metal/runtime/cache_identity.m",
    "src/backends/metal/runtime/archive_store.m",
    "src/backends/metal/runtime/dynamic_evaluation.m",
    "src/backends/metal/runtime/composition.m",
    "src/backends/metal/runtime/prepared_auxiliary.m",
    "src/backends/metal/runtime/circle_legacy.m",
    "src/backends/metal/runtime/circle_commit_epoch.m",
    "src/backends/metal/runtime/polynomial_evaluation.m",
    "src/backends/metal/runtime/quotients.m",
    "src/backends/metal/runtime/lifecycle_and_tree.m",
};

pub fn sourceJitIdentity(b: *std.Build) graph_identity.RuntimeHooks {
    const shader_digest = nativeShaderDigest(b);
    const runtime_digest = runtimeSourceDigest(b);
    const profile = "sdk=macosx;language=metal3.1;math=safe;warnings-as-errors=true";
    var profile_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(profile, &profile_digest, .{});
    const profile_hex = std.fmt.bytesToHex(profile_digest, .lower);
    const sdk_path = commandOutput(b, &.{ "xcrun", "--sdk", "macosx", "--show-sdk-path" });
    const sdk_version = commandOutput(b, &.{ "xcrun", "--sdk", "macosx", "--show-sdk-version" });
    const sdk_build = commandOutput(b, &.{ "xcrun", "--sdk", "macosx", "--show-sdk-build-version" });
    const compiler_path = commandOutput(b, &.{ "xcrun", "--find", "clang" });
    const compiler_version = commandOutput(b, &.{ "xcrun", "clang", "--version" });
    const compiler_digest = digestBytes(compiler_version);
    return .{
        .runtime_manifest = b.fmt(
            "metal-runtime-v2:mode=source-jit;shader-amalgamation-sha256={s};runtime-objc-sha256={s}",
            .{ shader_digest, runtime_digest },
        ),
        .sdk_manifest = b.fmt(
            "apple-metal-sdk-v2:sdk-path={s};sdk-version={s};sdk-build={s};objc-compiler={s};objc-compiler-version-sha256={s};compile-profile-sha256={s}",
            .{ sdk_path, sdk_version, sdk_build, compiler_path, compiler_digest, &profile_hex },
        ),
        .aot_manifest = "none",
    };
}

pub fn authenticatedAotIdentity(
    b: *std.Build,
    manifest_sha256: []const u8,
) graph_identity.RuntimeHooks {
    if (manifest_sha256.len != 64)
        @panic("Metal core AOT manifest digest must be lowercase SHA-256");
    const shader_digest = nativeShaderDigest(b);
    const runtime_digest = runtimeSourceDigest(b);
    return .{
        .runtime_manifest = b.fmt(
            "metal-runtime-v2:mode=authenticated-aot;shader-amalgamation-sha256={s};runtime-objc-sha256={s};core-aot-manifest-sha256={s}",
            .{ shader_digest, runtime_digest, manifest_sha256 },
        ),
        .sdk_manifest = b.fmt(
            "apple-metal-sdk-v2:bound-by-core-aot-manifest-sha256={s}",
            .{manifest_sha256},
        ),
        .aot_manifest = b.fmt(
            "stwo-zig-metal-core-aot-v2:manifest-sha256={s}",
            .{manifest_sha256},
        ),
    };
}

fn runtimeSourceDigest(b: *std.Build) []const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (runtime_source_units) |path| {
        hasher.update(path);
        hasher.update(&.{0});
        const bytes = b.build_root.handle.readFileAlloc(
            b.allocator,
            path,
            16 * 1024 * 1024,
        ) catch std.debug.panic("cannot hash Metal runtime source: {s}", .{path});
        hasher.update(bytes);
    }
    const digest = std.fmt.bytesToHex(hasher.finalResult(), .lower);
    return b.dupe(&digest);
}

fn digestBytes(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn commandOutput(b: *std.Build, argv: []const []const u8) []const u8 {
    construction_observer.recordConfigureTool(b, argv[0]);
    const result = std.process.Child.run(.{
        .allocator = b.allocator,
        .argv = argv,
    }) catch |err| std.debug.panic(
        "cannot resolve Metal SDK identity with {s}: {s}",
        .{ argv[0], @errorName(err) },
    );
    switch (result.term) {
        .Exited => |code| if (code != 0) std.debug.panic(
            "Metal SDK identity command failed ({d}): {s}",
            .{ code, std.mem.trim(u8, result.stderr, " \t\r\n") },
        ),
        else => std.debug.panic("Metal SDK identity command terminated unexpectedly: {s}", .{argv[0]}),
    }
    return b.dupe(std.mem.trim(u8, result.stdout, " \t\r\n"));
}

fn nativeShaderDigest(b: *std.Build) []const u8 {
    const Unit = struct { header: []const u8, path: []const u8 };
    const units = [_]Unit{
        .{ .header = "#define STWO_ZIG_AMALGAMATED 1\n#line 1 \"src/backends/metal/shaders/include/base.metal\"\n", .path = "src/backends/metal/shaders/include/base.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/include/blake2s.metal\"\n", .path = "src/backends/metal/shaders/include/blake2s.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/include/merkle.metal\"\n", .path = "src/backends/metal/shaders/include/merkle.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/include/decommit.metal\"\n", .path = "src/backends/metal/shaders/include/decommit.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/include/m31.metal\"\n", .path = "src/backends/metal/shaders/include/m31.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/include/extension_fields.metal\"\n", .path = "src/backends/metal/shaders/include/extension_fields.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/include/circle.metal\"\n", .path = "src/backends/metal/shaders/include/circle.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/include/abi_types.metal\"\n", .path = "src/backends/metal/shaders/include/abi_types.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/commitments.metal\"\n", .path = "src/backends/metal/shaders/core/commitments.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/kernels.metal\"\n", .path = "src/backends/metal/kernels.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/circle_transform.metal\"\n", .path = "src/backends/metal/shaders/core/circle_transform.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/circle_transform_wide.metal\"\n", .path = "src/backends/metal/shaders/core/circle_transform_wide.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/arena_ops.metal\"\n", .path = "src/backends/metal/shaders/core/arena_ops.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/transcript.metal\"\n", .path = "src/backends/metal/shaders/core/transcript.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/composition.metal\"\n", .path = "src/backends/metal/shaders/core/composition.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/relation.metal\"\n", .path = "src/backends/metal/shaders/core/relation.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/decommit.metal\"\n", .path = "src/backends/metal/shaders/core/decommit.metal" },
        .{ .header = "\n#line 1 \"src/backends/metal/shaders/core/polynomial_eval.metal\"\n", .path = "src/backends/metal/shaders/core/polynomial_eval.metal" },
    };
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (units) |unit| {
        hasher.update(unit.header);
        const bytes = b.build_root.handle.readFileAlloc(b.allocator, unit.path, 16 * 1024 * 1024) catch
            std.debug.panic("cannot hash Metal shader source: {s}", .{unit.path});
        hasher.update(bytes);
    }
    const digest = std.fmt.bytesToHex(hasher.finalResult(), .lower);
    return b.dupe(&digest);
}

pub fn supports(os: std.Target.Os.Tag) bool {
    return os == .macos;
}

pub fn requireTarget(target: std.Target) !void {
    if (!supports(target.os.tag)) return error.MetalRequiresMacOS;
}

pub fn linkRuntime(b: *std.Build, artifact: *std.Build.Step.Compile) void {
    requireTarget(artifact.root_module.resolved_target.?.result) catch |err| std.debug.panic(
        "cannot link Metal runtime for {s}: {s}",
        .{ artifact.name, @errorName(err) },
    );
    artifact.addCSourceFile(.{
        .file = b.path(runtime_source),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    linkFrameworks(artifact);
}

pub fn linkFrameworks(artifact: *std.Build.Step.Compile) void {
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}

test "Metal target policy is explicit" {
    try std.testing.expect(supports(.macos));
    try std.testing.expect(!supports(.linux));
}
