const std = @import("std");
const shader_manifest = @import("shader_manifest");
const core_aot = shader_manifest.core_aot;

pub const format = core_aot.format;
pub const source_filename = core_aot.source_filename;
pub const manifest_filename = core_aot.manifest_filename;
pub const manifest_digest_filename = core_aot.manifest_digest_filename;
pub const air_filename = core_aot.air_filename;
pub const metallib_filename = core_aot.metallib_filename;
pub const Measurement = core_aot.Measurement;
pub const BuildMeasurements = core_aot.BuildMeasurements;
pub const BuildEvidence = core_aot.BuildEvidence;

pub fn source() []const u8 {
    return core_aot.source();
}

pub fn renderManifest(allocator: std.mem.Allocator, evidence: ?BuildEvidence) ![]u8 {
    return core_aot.renderManifest(allocator, evidence);
}

pub fn emit(allocator: std.mem.Allocator, output_dir: []const u8) !void {
    try verifyAuthority();
    const manifest_bytes = try renderManifest(allocator, null);
    defer allocator.free(manifest_bytes);

    var directory = try std.fs.cwd().makeOpenPath(output_dir, .{});
    defer directory.close();
    try writeAtomic(directory, source_filename, source());
    try writeAtomic(directory, manifest_filename, manifest_bytes);
}

pub fn finalizeBuild(
    allocator: std.mem.Allocator,
    output_dir: []const u8,
    toolchain: shader_manifest.build_contract.ToolchainIdentity,
) !BuildMeasurements {
    var directory = try std.fs.cwd().openDir(output_dir, .{});
    defer directory.close();
    const measurements: BuildMeasurements = .{
        .air = try measure(directory, air_filename),
        .metallib = try measure(directory, metallib_filename),
    };
    const manifest_bytes = try renderManifest(allocator, .{
        .measurements = measurements,
        .toolchain = toolchain,
    });
    defer allocator.free(manifest_bytes);
    const trust_anchor = try core_aot.renderManifestTrustAnchor(allocator, manifest_bytes);
    defer allocator.free(trust_anchor);
    try writeAtomic(directory, manifest_filename, manifest_bytes);
    try writeAtomic(directory, manifest_digest_filename, trust_anchor);
    return measurements;
}

fn sourceDigest() [32]u8 {
    return core_aot.sourceDigest();
}

fn verifyAuthority() !void {
    try core_aot.verifyAuthority();
}

fn writeAtomic(directory: std.fs.Dir, filename: []const u8, bytes: []const u8) !void {
    var write_buffer: [64 * 1024]u8 = undefined;
    var file = try directory.atomicFile(filename, .{ .write_buffer = &write_buffer });
    defer file.deinit();
    try file.file_writer.interface.writeAll(bytes);
    try file.finish();
}

fn measure(directory: std.fs.Dir, filename: []const u8) !Measurement {
    return core_aot.measure(directory, filename);
}

test "AOT manifest is deterministic and binds the shader authority" {
    const first = try renderManifest(std.testing.allocator, null);
    defer std.testing.allocator.free(first);
    const second = try renderManifest(std.testing.allocator, null);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    try std.testing.expectEqual(@as(u8, '\n'), first[first.len - 1]);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, first, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings(format, root.get("format").?.string);
    try std.testing.expectEqual(@as(i64, shader_manifest.core_shader_abi), root.get("core_shader_abi").?.integer);
    try std.testing.expectEqual(shader_manifest.native_exports.len, root.get("exports").?.array.items.len);
    try std.testing.expectEqual(
        shader_manifest.abi_contract.native_kernel_abi.len,
        root.get("kernel_abi").?.array.items.len,
    );
    try std.testing.expect(root.get("toolchain").? == .null);

    const source_json = root.get("source").?.object;
    const digest_hex = std.fmt.bytesToHex(sourceDigest(), .lower);
    try std.testing.expectEqualStrings(digest_hex[0..], source_json.get("sha256").?.string);
    try std.testing.expectEqual(@as(i64, @intCast(source().len)), source_json.get("bytes").?.integer);

    const profile = root.get("compile_profile").?.object;
    try std.testing.expectEqualStrings(shader_manifest.compile_profile.sdk, profile.get("sdk").?.string);
    try std.testing.expectEqualStrings(
        shader_manifest.compile_profile.language_standard,
        profile.get("language_standard").?.string,
    );
    try std.testing.expectEqualStrings(shader_manifest.compile_profile.math_mode, profile.get("math_mode").?.string);
    try std.testing.expect(profile.get("warnings_as_errors").?.bool);

    const artifacts = root.get("artifacts").?.object;
    try std.testing.expect(artifacts.get("air").?.object.get("sha256").? == .null);
    try std.testing.expect(artifacts.get("metallib").?.object.get("bytes").? == .null);
}

test "built manifest authenticates synthetic compiler outputs" {
    const measurements: BuildMeasurements = .{
        .air = .{ .sha256 = .{0x31} ** 32, .bytes = 1234 },
        .metallib = .{ .sha256 = .{0xa7} ** 32, .bytes = 5678 },
    };
    const tool = shader_manifest.build_contract.ToolIdentity{
        .version = "metal tool 1",
        .sha256 = "ab" ** 32,
        .bytes = 1024,
    };
    const rendered = try renderManifest(std.testing.allocator, .{
        .measurements = measurements,
        .toolchain = .{
            .xcode_version = "16.0",
            .xcode_build = "16A000",
            .sdk_version = "15.0",
            .sdk_build = "24A000",
            .metal_toolchain_component = "com.apple.MetalToolchain 16A000",
            .metal = tool,
            .metallib = tool,
        },
    });
    defer std.testing.allocator.free(rendered);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, rendered, .{});
    defer parsed.deinit();
    const artifacts = parsed.value.object.get("artifacts").?.object;
    const air = artifacts.get("air").?.object;
    const metallib = artifacts.get("metallib").?.object;
    try std.testing.expectEqualStrings("31" ** 32, air.get("sha256").?.string);
    try std.testing.expectEqual(@as(i64, 1234), air.get("bytes").?.integer);
    try std.testing.expectEqualStrings("a7" ** 32, metallib.get("sha256").?.string);
    try std.testing.expectEqual(@as(i64, 5678), metallib.get("bytes").?.integer);
    try std.testing.expectEqualStrings("16A000", parsed.value.object.get("toolchain").?.object.get("xcode_build").?.string);
}

test "emission writes the exact sentinel-free amalgamated source" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const output_dir = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(output_dir);

    try emit(std.testing.allocator, output_dir);
    const emitted = try temporary.dir.readFileAlloc(std.testing.allocator, source_filename, source().len + 1);
    defer std.testing.allocator.free(emitted);
    try std.testing.expectEqualStrings(source(), emitted);
    try std.testing.expect(emitted.len == 0 or emitted[emitted.len - 1] != 0);
}

test "finalization publishes a canonical manifest trust anchor" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = air_filename, .data = "synthetic-air" });
    try temporary.dir.writeFile(.{ .sub_path = metallib_filename, .data = "synthetic-metallib" });
    const output_dir = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(output_dir);
    const tool = shader_manifest.build_contract.ToolIdentity{
        .version = "metal tool 1",
        .sha256 = "ab" ** 32,
        .bytes = 1024,
    };
    _ = try finalizeBuild(std.testing.allocator, output_dir, .{
        .xcode_version = "16.0",
        .xcode_build = "16A000",
        .sdk_version = "15.0",
        .sdk_build = "24A000",
        .metal_toolchain_component = "com.apple.MetalToolchain 16A000",
        .metal = tool,
        .metallib = tool,
    });
    const manifest = try temporary.dir.readFileAlloc(std.testing.allocator, manifest_filename, 1024 * 1024);
    defer std.testing.allocator.free(manifest);
    const anchor = try temporary.dir.readFileAlloc(std.testing.allocator, manifest_digest_filename, 1024);
    defer std.testing.allocator.free(anchor);
    const expected = try core_aot.renderManifestTrustAnchor(std.testing.allocator, manifest);
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, anchor);
}
