const builtin = @import("builtin");
const std = @import("std");
const artifact = @import("artifact.zig");
const shader_manifest = @import("shader_manifest");

pub const full_xcode_message =
    "full Xcode is required: install Xcode, select Xcode.app/Contents/Developer " ++
    "with xcode-select, and ensure xcrun resolves both metal and metallib";

const xcode_select = "/usr/bin/xcode-select";
const xcrun = "/usr/bin/xcrun";
const language_flag = "-std=" ++ shader_manifest.compile_profile.language_standard;
const deployment_flag = "-mmacosx-version-min=" ++
    shader_manifest.build_contract.target_policy.minimum_deployment_target;
const math_flag = if (std.mem.eql(u8, shader_manifest.compile_profile.math_mode, "safe"))
    "-fno-fast-math"
else
    @compileError("unsupported core Metal math mode");
const warning_flag = if (shader_manifest.compile_profile.warnings_as_errors)
    "-Werror"
else
    @compileError("core AOT builds must fail on Metal warnings");

pub const metal_argv = [_][]const u8{
    xcrun,
    "--sdk",
    shader_manifest.compile_profile.sdk,
    "metal",
    deployment_flag,
    language_flag,
    math_flag,
    warning_flag,
    "-c",
    artifact.source_filename,
    "-o",
    artifact.air_filename,
};

pub const metallib_argv = [_][]const u8{
    xcrun,
    "--sdk",
    shader_manifest.compile_profile.sdk,
    "metallib",
    artifact.air_filename,
    "-o",
    artifact.metallib_filename,
};

pub fn build(allocator: std.mem.Allocator, output_dir: []const u8) !void {
    return buildForProfile(allocator, output_dir, .core_v2);
}

pub fn buildForProfile(allocator: std.mem.Allocator, output_dir: []const u8, profile: artifact.Profile) !void {
    try requireFullXcode(allocator);
    var toolchain = try measureToolchainIdentity(allocator);
    defer toolchain.deinit();
    try artifact.emitForProfile(allocator, output_dir, profile);

    var directory = try std.fs.cwd().openDir(output_dir, .{});
    defer directory.close();
    try deleteOutput(directory, artifact.air_filename);
    try deleteOutput(directory, artifact.metallib_filename);

    try runCompiler(allocator, metal_argv[0..], output_dir);
    try requireNonempty(directory, artifact.air_filename);

    try runCompiler(allocator, metallib_argv[0..], output_dir);
    try requireNonempty(directory, artifact.metallib_filename);
    _ = try artifact.finalizeBuildForProfile(allocator, output_dir, toolchain.view(), profile);
}

const OwnedTool = struct {
    allocator: std.mem.Allocator,
    version: []u8,
    sha256: []u8,
    bytes: u64,

    fn deinit(self: *OwnedTool) void {
        self.allocator.free(self.version);
        self.allocator.free(self.sha256);
        self.* = undefined;
    }

    fn view(self: *const OwnedTool) shader_manifest.build_contract.ToolIdentity {
        return .{ .version = self.version, .sha256 = self.sha256, .bytes = self.bytes };
    }
};

const OwnedToolchainIdentity = struct {
    allocator: std.mem.Allocator,
    xcode_version: []u8,
    xcode_build: []u8,
    sdk_version: []u8,
    sdk_build: []u8,
    metal_toolchain_component: []u8,
    metal: OwnedTool,
    metallib: OwnedTool,

    fn deinit(self: *OwnedToolchainIdentity) void {
        self.allocator.free(self.xcode_version);
        self.allocator.free(self.xcode_build);
        self.allocator.free(self.sdk_version);
        self.allocator.free(self.sdk_build);
        self.allocator.free(self.metal_toolchain_component);
        self.metal.deinit();
        self.metallib.deinit();
        self.* = undefined;
    }

    fn view(self: *const OwnedToolchainIdentity) shader_manifest.build_contract.ToolchainIdentity {
        return .{
            .xcode_version = self.xcode_version,
            .xcode_build = self.xcode_build,
            .sdk_version = self.sdk_version,
            .sdk_build = self.sdk_build,
            .metal_toolchain_component = self.metal_toolchain_component,
            .metal = self.metal.view(),
            .metallib = self.metallib.view(),
        };
    }
};

fn measureToolchainIdentity(allocator: std.mem.Allocator) !OwnedToolchainIdentity {
    const xcode_output = try commandOutput(allocator, &.{ "/usr/bin/xcodebuild", "-version" });
    defer allocator.free(xcode_output);
    const xcode_version = try prefixedLine(allocator, xcode_output, "Xcode ");
    errdefer allocator.free(xcode_version);
    const xcode_build = try prefixedLine(allocator, xcode_output, "Build version ");
    errdefer allocator.free(xcode_build);
    const sdk_version = try commandOutput(allocator, &.{
        xcrun, "--sdk", shader_manifest.compile_profile.sdk, "--show-sdk-version",
    });
    errdefer allocator.free(sdk_version);
    const sdk_build = try commandOutput(allocator, &.{
        xcrun, "--sdk", shader_manifest.compile_profile.sdk, "--show-sdk-build-version",
    });
    errdefer allocator.free(sdk_build);
    const metal_toolchain_component = commandOutput(allocator, &.{
        "/usr/bin/xcodebuild", "-showComponent", "MetalToolchain", "-json",
    }) catch try allocator.dupe(
        u8,
        "component-metadata-unavailable;selected-by-xcrun;tool-binaries-digest-bound",
    );
    errdefer allocator.free(metal_toolchain_component);
    var metal = try measureTool(allocator, "metal", true);
    errdefer metal.deinit();
    var metallib = try measureTool(allocator, "metallib", false);
    errdefer metallib.deinit();
    return .{
        .allocator = allocator,
        .xcode_version = xcode_version,
        .xcode_build = xcode_build,
        .sdk_version = sdk_version,
        .sdk_build = sdk_build,
        .metal_toolchain_component = metal_toolchain_component,
        .metal = metal,
        .metallib = metallib,
    };
}

fn measureTool(allocator: std.mem.Allocator, name: []const u8, require_version: bool) !OwnedTool {
    const path = try commandOutput(allocator, &.{
        xcrun, "--sdk", shader_manifest.compile_profile.sdk, "--find", name,
    });
    defer allocator.free(path);
    const version = commandOutput(allocator, &.{ path, "--version" }) catch |err| fallback: {
        if (require_version) return err;
        break :fallback try allocator.dupe(u8, "not-reported;identity-by-binary-digest");
    };
    errdefer allocator.free(version);
    const measurement = try measurePath(path);
    const digest = std.fmt.bytesToHex(measurement.sha256, .lower);
    const digest_copy = try allocator.dupe(u8, &digest);
    return .{
        .allocator = allocator,
        .version = version,
        .sha256 = digest_copy,
        .bytes = measurement.bytes,
    };
}

fn measurePath(path: []const u8) !artifact.Measurement {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0) return error.InvalidMetalTool;
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var bytes: u64 = 0;
    var buffer: [256 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        digest.update(buffer[0..count]);
        bytes = std.math.add(u64, bytes, count) catch return error.MetalToolTooLarge;
    }
    const after = try file.stat();
    if (after.kind != .file or after.size != before.size or bytes != before.size)
        return error.MetalToolChangedDuringMeasurement;
    return .{ .sha256 = digest.finalResult(), .bytes = bytes };
}

fn prefixedLine(allocator: std.mem.Allocator, output: []const u8, prefix: []const u8) ![]u8 {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const value = std.mem.trim(u8, line[prefix.len..], " \t\r");
        if (value.len == 0) break;
        return allocator.dupe(u8, value);
    }
    return error.InvalidXcodeVersionOutput;
}

pub fn isFullXcodeDeveloperDir(path: []const u8) bool {
    const suffix = ".app/Contents/Developer";
    return std.mem.endsWith(u8, path, suffix) and
        !std.mem.endsWith(u8, path, "/CommandLineTools");
}

fn requireFullXcode(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .macos) return error.FullXcodeRequired;
    const developer_dir = commandOutput(allocator, &.{ xcode_select, "-p" }) catch
        return error.FullXcodeRequired;
    defer allocator.free(developer_dir);
    if (!isFullXcodeDeveloperDir(developer_dir)) return error.FullXcodeRequired;

    inline for (.{ "metal", "metallib" }) |tool| {
        const tool_path = commandOutput(allocator, &.{
            xcrun,
            "--sdk",
            shader_manifest.compile_profile.sdk,
            "--find",
            tool,
        }) catch return error.FullXcodeRequired;
        defer allocator.free(tool_path);
        if (!std.fs.path.isAbsolute(tool_path)) return error.FullXcodeRequired;
        const stat = std.fs.cwd().statFile(tool_path) catch return error.FullXcodeRequired;
        if (stat.kind != .file or stat.size == 0) return error.FullXcodeRequired;
    }
}

fn commandOutput(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 16 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try requireSuccess(result.term);
    const stdout = std.mem.trim(u8, result.stdout, " \t\r\n");
    const stderr = std.mem.trim(u8, result.stderr, " \t\r\n");
    const trimmed = if (stdout.len != 0) stdout else stderr;
    if (trimmed.len == 0) return error.EmptyToolOutput;
    return allocator.dupe(u8, trimmed);
}

fn runCompiler(allocator: std.mem.Allocator, argv: []const []const u8, cwd: []const u8) !void {
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .cwd = cwd,
        .max_output_bytes = 1024 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    requireSuccess(result.term) catch {
        std.debug.print("Metal compiler failed: {s}\n", .{std.mem.trim(u8, result.stderr, " \t\r\n")});
        return error.MetalCompilerFailed;
    };
}

fn requireSuccess(term: std.process.Child.Term) !void {
    switch (term) {
        .Exited => |code| if (code == 0) return,
        else => {},
    }
    return error.CommandFailed;
}

fn requireNonempty(directory: std.fs.Dir, filename: []const u8) !void {
    const stat = try directory.statFile(filename);
    if (stat.kind != .file or stat.size == 0) return error.EmptyCompilerArtifact;
}

fn deleteOutput(directory: std.fs.Dir, filename: []const u8) !void {
    directory.deleteFile(filename) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

test "full Xcode recognition rejects Command Line Tools" {
    try std.testing.expect(isFullXcodeDeveloperDir("/Applications/Xcode.app/Contents/Developer"));
    try std.testing.expect(isFullXcodeDeveloperDir("/Applications/Xcode-beta.app/Contents/Developer"));
    try std.testing.expect(!isFullXcodeDeveloperDir("/Library/Developer/CommandLineTools"));
    try std.testing.expect(!isFullXcodeDeveloperDir("/Applications/Xcode.app"));
}

test "compiler contract pins safe math and exact artifact names" {
    try std.testing.expectEqualStrings("safe", shader_manifest.compile_profile.math_mode);
    try std.testing.expectEqualSlices([]const u8, &.{
        "/usr/bin/xcrun",
        "--sdk",
        "macosx",
        "metal",
        "-mmacosx-version-min=14.0",
        "-std=metal3.1",
        "-fno-fast-math",
        "-Werror",
        "-c",
        "stwo_zig_core.metal",
        "-o",
        "stwo_zig_core.air",
    }, metal_argv[0..]);
    try std.testing.expectEqualSlices([]const u8, &.{
        "/usr/bin/xcrun",
        "--sdk",
        "macosx",
        "metallib",
        "stwo_zig_core.air",
        "-o",
        "stwo_zig_core.metallib",
    }, metallib_argv[0..]);
}
