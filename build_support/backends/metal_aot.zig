const std = @import("std");

pub const install_subdir = "share/stwo-zig/metal/core";
pub const manifest_filename = "stwo_zig_core.manifest.json";
pub const manifest_digest_filename = "stwo_zig_core.manifest.sha256";
pub const air_filename = "stwo_zig_core.air";
pub const metallib_filename = "stwo_zig_core.metallib";

pub const Context = struct {
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    shader_manifest_module: *std.Build.Module,
};

/// One already-built core library admitted as an immutable build input.
///
/// The product identity binds `manifest_sha256`; the runtime then remeasures
/// the manifest and every artifact named by it before Metal sees any bytes.
/// A path is configuration, never authority.
pub const ExternalBundle = struct {
    directory: std.Build.LazyPath,
    absolute_path: []const u8,
    manifest_sha256: [32]u8,
    manifest_sha256_hex: [64]u8,

    pub fn addOptions(
        self: ExternalBundle,
        b: *std.Build,
    ) *std.Build.Step.Options {
        const options = b.addOptions();
        options.addOption(
            [32]u8,
            "manifest_sha256",
            self.manifest_sha256,
        );
        options.addOption(
            []const u8,
            "manifest_sha256_hex",
            b.dupe(&self.manifest_sha256_hex),
        );
        options.addOption([]const u8, "install_subdir", install_subdir);
        return options;
    }

    pub fn install(
        self: ExternalBundle,
        b: *std.Build,
        owner: *std.Build.Step,
    ) void {
        const destination = b.getInstallPath(.prefix, install_subdir);
        if (std.mem.eql(u8, self.absolute_path, destination)) return;
        const install_bundle = b.addInstallDirectory(.{
            .source_dir = self.directory,
            .install_dir = .prefix,
            .install_subdir = install_subdir,
        });
        owner.dependOn(&install_bundle.step);
    }
};

/// Load and authenticate the canonical manifest trust anchor at configure
/// time. Full semantic and artifact admission remains the runtime
/// responsibility of `core_aot.admit`, so later substitution fails closed.
pub fn loadExternalBundle(
    b: *std.Build,
    configured_path: []const u8,
) ExternalBundle {
    if (configured_path.len == 0)
        @panic("Metal core AOT bundle path cannot be empty");
    const unresolved = if (std.fs.path.isAbsolute(configured_path))
        configured_path
    else
        b.pathFromRoot(configured_path);
    const absolute_path = std.fs.cwd().realpathAlloc(
        b.allocator,
        unresolved,
    ) catch |err| std.debug.panic(
        "cannot resolve Metal core AOT bundle {s}: {s}",
        .{ unresolved, @errorName(err) },
    );
    var directory = std.fs.openDirAbsolute(absolute_path, .{}) catch |err|
        std.debug.panic(
            "cannot open Metal core AOT bundle {s}: {s}",
            .{ absolute_path, @errorName(err) },
        );
    defer directory.close();

    const manifest = directory.readFileAlloc(
        b.allocator,
        manifest_filename,
        1024 * 1024,
    ) catch |err| std.debug.panic(
        "cannot read Metal core AOT manifest: {s}",
        .{@errorName(err)},
    );
    const anchor = directory.readFileAlloc(
        b.allocator,
        manifest_digest_filename,
        1024,
    ) catch |err| std.debug.panic(
        "cannot read Metal core AOT trust anchor: {s}",
        .{@errorName(err)},
    );
    const expected = parseTrustAnchor(anchor) catch |err| std.debug.panic(
        "invalid Metal core AOT trust anchor: {s}",
        .{@errorName(err)},
    );
    var measured: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(manifest, &measured, .{});
    if (!std.mem.eql(u8, &expected, &measured))
        @panic("Metal core AOT manifest does not match its trust anchor");
    inline for (.{ air_filename, metallib_filename }) |filename| {
        const stat = directory.statFile(filename) catch |err|
            std.debug.panic(
                "missing Metal core AOT artifact {s}: {s}",
                .{ filename, @errorName(err) },
            );
        if (stat.kind != .file or stat.size == 0)
            std.debug.panic(
                "Metal core AOT artifact {s} is not a non-empty file",
                .{filename},
            );
    }
    return .{
        .directory = .{ .cwd_relative = absolute_path },
        .absolute_path = absolute_path,
        .manifest_sha256 = measured,
        .manifest_sha256_hex = std.fmt.bytesToHex(measured, .lower),
    };
}

pub fn addProducts(context: Context) void {
    const b = context.b;
    const tool_module = b.createModule(.{
        .root_source_file = b.path("src/tools/metal_core_aot/main.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    tool_module.addImport("shader_manifest", context.shader_manifest_module);
    // The catalog's platform-blind construction contract declares one
    // generated options root for the metal_tools scope; keep it observable on
    // every host by recording the acceptance partition itself as build options.
    const platform_options = b.addOptions();
    platform_options.addOption(
        bool,
        "hosted_acceptance_available",
        context.target.result.os.tag == .macos,
    );
    tool_module.addOptions("aot_platform", platform_options);
    const tool = b.addExecutable(.{
        .name = "metal-core-aot",
        .root_module = tool_module,
    });
    const install_tool = b.addInstallArtifact(tool, .{});
    const tool_step = b.step(
        "metal-core-aot",
        "Build the deterministic, fail-closed core Metal AOT tool",
    );
    tool_step.dependOn(&install_tool.step);

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/tools/metal_core_aot/main.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    test_module.addImport("shader_manifest", context.shader_manifest_module);
    const tests = b.addTest(.{ .root_module = test_module });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step(
        "test-metal-core-aot",
        "Run deterministic core Metal AOT tooling tests without compiling shaders",
    );
    test_step.dependOn(&run_tests.step);

    if (context.target.result.os.tag != .macos) {
        addUnavailableAcceptance(b);
        return;
    }
    addHostedAcceptance(context, tool);
}

fn parseTrustAnchor(encoded: []const u8) ![32]u8 {
    const suffix = "  " ++ manifest_filename ++ "\n";
    if (encoded.len != 64 + suffix.len or
        !std.mem.eql(u8, encoded[64..], suffix))
        return error.NonCanonicalTrustAnchor;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded[0..64]) catch
        return error.NonCanonicalTrustAnchor;
    for (encoded[0..64]) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.NonCanonicalTrustAnchor;
    }
    return result;
}

test "external bundle trust anchors are canonical" {
    const digest = try parseTrustAnchor(
        "ab" ** 32 ++ "  " ++ manifest_filename ++ "\n",
    );
    try std.testing.expectEqual([_]u8{0xab} ** 32, digest);
    try std.testing.expectError(
        error.NonCanonicalTrustAnchor,
        parseTrustAnchor("AB" ** 32 ++ "  " ++ manifest_filename ++ "\n"),
    );
}

/// Fail-closed stubs so the platform-blind product catalog's configure
/// closure holds on every host: the step names exist everywhere, and
/// invoking one off macOS fails with the real reason (mirrors
/// build_support/benchmarks/metal.zig's convention).
fn addUnavailableAcceptance(b: *std.Build) void {
    const reason = "Native core metallib probe and acceptance require a macOS host with Metal";
    const failure = b.addFail(reason);
    inline for (.{
        "metal-core-aot-probe",
        "test-metal-core-aot-probe",
        "metal-core-aot-acceptance",
    }) |name| {
        b.step(name, reason).dependOn(&failure.step);
    }
}

fn addHostedAcceptance(context: Context, tool: *std.Build.Step.Compile) void {
    const b = context.b;
    const host_transcript_module = b.createModule(.{
        .root_source_file = b.path("src/tools/metal_core_aot/host_transcript.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    const probe_module = b.createModule(.{
        .root_source_file = b.path("src/tools/metal_core_aot/probe.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    probe_module.addImport("shader_manifest", context.shader_manifest_module);
    probe_module.addImport("host_transcript", host_transcript_module);
    const probe = b.addExecutable(.{
        .name = "metal-core-aot-probe",
        .root_module = probe_module,
    });
    linkProbe(b, probe);
    const install_probe = b.addInstallArtifact(probe, .{});
    const probe_step = b.step(
        "metal-core-aot-probe",
        "Build the authenticated Native core metallib acceptance probe",
    );
    probe_step.dependOn(&install_probe.step);

    const probe_test_module = b.createModule(.{
        .root_source_file = b.path("src/tools/metal_core_aot/probe.zig"),
        .target = context.target,
        .optimize = context.optimize,
    });
    probe_test_module.addImport("shader_manifest", context.shader_manifest_module);
    probe_test_module.addImport("host_transcript", host_transcript_module);
    const probe_tests = b.addTest(.{ .root_module = probe_test_module });
    linkProbe(b, probe_tests);
    const run_probe_tests = b.addRunArtifact(probe_tests);
    const probe_test_step = b.step(
        "test-metal-core-aot-probe",
        "Run Native core metallib probe contract tests without compiling shaders",
    );
    probe_test_step.dependOn(&run_probe_tests.step);

    const build_bundle = b.addRunArtifact(tool);
    build_bundle.addArgs(&.{ "build", "--output-dir" });
    const bundle = build_bundle.addOutputDirectoryArg("native-metal-core-aot");

    const run_probe = b.addRunArtifact(probe);
    run_probe.addArg("--bundle-dir");
    run_probe.addDirectoryArg(bundle);
    run_probe.addArg("--trust-anchor");
    run_probe.addFileArg(bundle.path(b, "stwo_zig_core.manifest.sha256"));
    const install_bundle = b.addInstallDirectory(.{
        .source_dir = bundle,
        .install_dir = .prefix,
        .install_subdir = install_subdir,
    });

    const acceptance_step = b.step(
        "metal-core-aot-acceptance",
        "Build, authenticate, and inspect the linked Native core metallib",
    );
    acceptance_step.dependOn(&run_probe.step);
    acceptance_step.dependOn(&install_bundle.step);
}

fn linkProbe(b: *std.Build, artifact: *std.Build.Step.Compile) void {
    artifact.addCSourceFile(.{
        .file = b.path("src/tools/metal_core_aot/probe.m"),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
}
