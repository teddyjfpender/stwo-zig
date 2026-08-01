//! Authenticated bundle format shared by the core Metal AOT producer and runtime.

const std = @import("std");
const abi_contract = @import("shaders/abi_contract.zig");
const build_contract = @import("shaders/build_contract.zig");
const shader_manifest = @import("shaders/manifest.zig");

pub const format = "stwo-zig-metal-core-aot-v2";
pub const source_filename = "stwo_zig_core.metal";
pub const manifest_filename = "stwo_zig_core.manifest.json";
pub const manifest_digest_filename = "stwo_zig_core.manifest.sha256";
pub const air_filename = "stwo_zig_core.air";
pub const metallib_filename = "stwo_zig_core.metallib";
pub const max_metallib_bytes: u64 = 256 * 1024 * 1024;

pub const SourceIdentity = struct {
    path: []const u8,
    sha256: []const u8,
    bytes: u64,
};

pub const Measurement = struct {
    sha256: [32]u8,
    bytes: u64,
};

pub const BuildMeasurements = struct {
    air: Measurement,
    metallib: Measurement,
};

pub const BuildEvidence = struct {
    measurements: BuildMeasurements,
    toolchain: build_contract.ToolchainIdentity,
};

pub const ArtifactIdentity = struct {
    path: []const u8,
    sha256: ?[]const u8,
    bytes: ?u64,
};

pub const ArtifactIdentities = struct {
    air: ArtifactIdentity,
    metallib: ArtifactIdentity,
};

pub const Manifest = struct {
    format: []const u8,
    core_shader_abi: u32,
    source: SourceIdentity,
    compile_profile: shader_manifest.CompileProfile,
    target_policy: build_contract.TargetPolicy,
    toolchain: ?build_contract.ToolchainIdentity,
    artifacts: ArtifactIdentities,
    exports: []const shader_manifest.Export,
    kernel_abi: []const abi_contract.KernelAbi,
};

pub const Admission = struct {
    allocator: std.mem.Allocator,
    metallib_bytes: []u8,
    metallib: Measurement,

    pub fn deinit(self: *Admission) void {
        self.allocator.free(self.metallib_bytes);
        self.* = undefined;
    }
};

pub fn source() []const u8 {
    return authoritySource()[0 .. authoritySource().len - 1];
}

pub fn sourceDigest() [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source(), &digest, .{});
    return digest;
}

pub fn manifestDigest(encoded: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
    return digest;
}

pub fn renderManifestTrustAnchor(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    const digest = std.fmt.bytesToHex(manifestDigest(encoded), .lower);
    return std.fmt.allocPrint(allocator, "{s}  {s}\n", .{ digest, manifest_filename });
}

pub fn renderManifest(allocator: std.mem.Allocator, evidence: ?BuildEvidence) ![]u8 {
    const source_hex = std.fmt.bytesToHex(sourceDigest(), .lower);
    const air_hex = if (evidence) |value|
        std.fmt.bytesToHex(value.measurements.air.sha256, .lower)
    else
        null;
    const metallib_hex = if (evidence) |value|
        std.fmt.bytesToHex(value.measurements.metallib.sha256, .lower)
    else
        null;
    const body = try std.json.Stringify.valueAlloc(allocator, Manifest{
        .format = format,
        .core_shader_abi = shader_manifest.core_shader_abi,
        .source = .{
            .path = source_filename,
            .sha256 = source_hex[0..],
            .bytes = source().len,
        },
        .compile_profile = shader_manifest.compile_profile,
        .target_policy = build_contract.target_policy,
        .toolchain = if (evidence) |value| value.toolchain else null,
        .artifacts = .{
            .air = .{
                .path = air_filename,
                .sha256 = if (air_hex) |value| value[0..] else null,
                .bytes = if (evidence) |value| value.measurements.air.bytes else null,
            },
            .metallib = .{
                .path = metallib_filename,
                .sha256 = if (metallib_hex) |value| value[0..] else null,
                .bytes = if (evidence) |value| value.measurements.metallib.bytes else null,
            },
        },
        .exports = authorityExports(),
        .kernel_abi = abi_contract.native_kernel_abi[0..],
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(body);
    return std.fmt.allocPrint(allocator, "{s}\n", .{body});
}

pub fn admit(
    allocator: std.mem.Allocator,
    bundle_path: []const u8,
    expected_manifest_sha256: [32]u8,
) !Admission {
    if (bundle_path.len == 0) return error.InvalidBundlePath;
    var directory = try std.fs.cwd().openDir(bundle_path, .{});
    defer directory.close();

    const encoded = try directory.readFileAlloc(allocator, manifest_filename, 1024 * 1024);
    defer allocator.free(encoded);
    if (!std.mem.eql(u8, &manifestDigest(encoded), &expected_manifest_sha256))
        return error.ManifestTrustAnchorMismatch;
    const parsed = std.json.parseFromSlice(Manifest, allocator, encoded, .{
        .ignore_unknown_fields = false,
    }) catch return error.InvalidAotManifest;
    defer parsed.deinit();
    try validateManifest(parsed.value);

    const actual_source = try measure(directory, source_filename);
    const expected_source = Measurement{
        .sha256 = try parseDigest(parsed.value.source.sha256),
        .bytes = parsed.value.source.bytes,
    };
    if (!measurementEql(actual_source, expected_source)) return error.CoreSourceIdentityMismatch;

    const air_identity = parsed.value.artifacts.air;
    const expected_air = try requiredMeasurement(air_identity);
    if (!measurementEql(try measure(directory, air_filename), expected_air))
        return error.AirIdentityMismatch;

    const metallib_identity = parsed.value.artifacts.metallib;
    const expected_metallib = try requiredMeasurement(metallib_identity);
    if (expected_metallib.bytes > max_metallib_bytes) return error.MetallibTooLarge;
    const metallib_bytes = try readAuthenticatedArtifact(
        allocator,
        directory,
        metallib_filename,
        expected_metallib,
        max_metallib_bytes,
    );
    errdefer allocator.free(metallib_bytes);

    return .{
        .allocator = allocator,
        .metallib_bytes = metallib_bytes,
        .metallib = expected_metallib,
    };
}

pub fn verifyAuthority() !void {
    const source_digest = sourceDigest();
    const authority_digest = authoritySourceDigest();
    if (!std.mem.eql(u8, &source_digest, &authority_digest))
        return error.CoreSourceDigestMismatch;
    if (authorityExports().len == 0) return error.EmptyCoreExportInventory;
}

pub fn measure(directory: std.fs.Dir, filename: []const u8) !Measurement {
    const file = try directory.openFile(filename, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0) return error.InvalidCompilerArtifact;
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var bytes: u64 = 0;
    var buffer: [256 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        digest.update(buffer[0..count]);
        bytes = std.math.add(u64, bytes, count) catch return error.CompilerArtifactTooLarge;
    }
    const after = try file.stat();
    if (after.kind != .file or after.size != before.size or bytes != before.size)
        return error.CompilerArtifactChangedDuringMeasurement;
    return .{ .sha256 = digest.finalResult(), .bytes = bytes };
}

fn validateManifest(manifest: Manifest) !void {
    if (!std.mem.eql(u8, manifest.format, format)) return error.UnsupportedAotFormat;
    if (manifest.core_shader_abi != shader_manifest.core_shader_abi)
        return error.CoreShaderAbiMismatch;
    if (!profileEql(manifest.compile_profile, shader_manifest.compile_profile))
        return error.CompileProfileMismatch;
    if (!targetPolicyEql(manifest.target_policy, build_contract.target_policy))
        return error.TargetPolicyMismatch;
    const toolchain = manifest.toolchain orelse return error.MissingToolchainIdentity;
    build_contract.validateToolchainIdentity(toolchain) catch
        return error.InvalidToolchainIdentity;
    if (!std.mem.eql(u8, manifest.source.path, source_filename))
        return error.InvalidSourcePath;
    const expected_source = Measurement{ .sha256 = sourceDigest(), .bytes = source().len };
    const declared_source = Measurement{
        .sha256 = try parseDigest(manifest.source.sha256),
        .bytes = manifest.source.bytes,
    };
    if (!measurementEql(declared_source, expected_source))
        return error.CoreSourceIdentityMismatch;
    if (!std.mem.eql(u8, manifest.artifacts.air.path, air_filename) or
        !std.mem.eql(u8, manifest.artifacts.metallib.path, metallib_filename))
        return error.InvalidArtifactPath;
    _ = try requiredMeasurement(manifest.artifacts.air);
    _ = try requiredMeasurement(manifest.artifacts.metallib);
    if (!exportsEql(manifest.exports, authorityExports()))
        return error.CoreExportInventoryMismatch;
    if (!kernelAbiEql(manifest.kernel_abi, abi_contract.native_kernel_abi[0..]))
        return error.CoreKernelAbiMismatch;
}

fn requiredMeasurement(identity: ArtifactIdentity) !Measurement {
    const encoded = identity.sha256 orelse return error.IncompleteArtifactIdentity;
    const bytes = identity.bytes orelse return error.IncompleteArtifactIdentity;
    if (bytes == 0) return error.IncompleteArtifactIdentity;
    return .{ .sha256 = try parseDigest(encoded), .bytes = bytes };
}

fn parseDigest(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidArtifactDigest;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return error.InvalidArtifactDigest;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidArtifactDigest;
    return digest;
}

fn readAuthenticatedArtifact(
    allocator: std.mem.Allocator,
    directory: std.fs.Dir,
    filename: []const u8,
    expected: Measurement,
    max_bytes: u64,
) ![]u8 {
    if (expected.bytes == 0 or expected.bytes > max_bytes or expected.bytes > std.math.maxInt(usize))
        return error.MetallibTooLarge;
    const file = try directory.openFile(filename, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size != expected.bytes)
        return error.MetallibIdentityMismatch;
    const bytes = try allocator.alloc(u8, @intCast(expected.bytes));
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.MetallibIdentityMismatch;
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.MetallibIdentityMismatch;
    const after = try file.stat();
    if (after.kind != .file or after.size != before.size)
        return error.CompilerArtifactChangedDuringMeasurement;
    if (!measurementEql(measurementOf(bytes), expected)) return error.MetallibIdentityMismatch;
    return bytes;
}

fn profileEql(lhs: shader_manifest.CompileProfile, rhs: shader_manifest.CompileProfile) bool {
    return std.mem.eql(u8, lhs.sdk, rhs.sdk) and
        std.mem.eql(u8, lhs.language_standard, rhs.language_standard) and
        std.mem.eql(u8, lhs.math_mode, rhs.math_mode) and
        lhs.warnings_as_errors == rhs.warnings_as_errors;
}

fn targetPolicyEql(lhs: build_contract.TargetPolicy, rhs: build_contract.TargetPolicy) bool {
    return std.mem.eql(u8, lhs.platform, rhs.platform) and
        std.mem.eql(u8, lhs.sdk, rhs.sdk) and
        std.mem.eql(u8, lhs.minimum_deployment_target, rhs.minimum_deployment_target) and
        std.mem.eql(u8, lhs.gpu_architecture_policy, rhs.gpu_architecture_policy) and
        std.mem.eql(u8, lhs.device_family_policy, rhs.device_family_policy);
}

fn exportsEql(lhs: []const shader_manifest.Export, rhs: []const shader_manifest.Export) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |actual, expected| {
        if (actual.owner != expected.owner or !std.mem.eql(u8, actual.name, expected.name))
            return false;
    }
    return true;
}

fn kernelAbiEql(lhs: []const abi_contract.KernelAbi, rhs: []const abi_contract.KernelAbi) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |actual, expected| {
        if (!std.mem.eql(u8, actual.name, expected.name) or
            actual.owner != expected.owner or
            actual.minimum_core_shader_abi != expected.minimum_core_shader_abi or
            !std.mem.eql(u8, actual.declaration_sha256, expected.declaration_sha256) or
            actual.function_constants.len != expected.function_constants.len)
            return false;
        for (actual.function_constants, expected.function_constants) |actual_constant, expected_constant| {
            if (actual_constant.index != expected_constant.index or
                !std.mem.eql(u8, actual_constant.name, expected_constant.name) or
                !std.mem.eql(u8, actual_constant.msl_type, expected_constant.msl_type) or
                !std.mem.eql(u8, actual_constant.specialization_value, expected_constant.specialization_value))
                return false;
        }
    }
    return true;
}

fn measurementEql(lhs: Measurement, rhs: Measurement) bool {
    return lhs.bytes == rhs.bytes and std.mem.eql(u8, &lhs.sha256, &rhs.sha256);
}

fn authoritySource() [:0]const u8 {
    return shader_manifest.native_amalgamated_source;
}

fn authoritySourceDigest() [32]u8 {
    return shader_manifest.nativeAmalgamatedSourceDigest();
}

fn authorityExports() []const shader_manifest.Export {
    return shader_manifest.native_exports[0..];
}

fn measurementOf(bytes: []const u8) Measurement {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .sha256 = digest, .bytes = bytes.len };
}

const test_air = "synthetic-air";
const test_metallib = "synthetic-metallib";
const test_tool = build_contract.ToolIdentity{
    .version = "metal tool 1",
    .sha256 = "ab" ** 32,
    .bytes = 1024,
};
const test_toolchain = build_contract.ToolchainIdentity{
    .xcode_version = "16.0",
    .xcode_build = "16A000",
    .sdk_version = "15.0",
    .sdk_build = "24A000",
    .metal_toolchain_component = "com.apple.MetalToolchain 16A000",
    .metal = test_tool,
    .metallib = test_tool,
};

fn writeTestBundle(allocator: std.mem.Allocator, directory: std.fs.Dir) ![]u8 {
    try directory.writeFile(.{ .sub_path = source_filename, .data = source() });
    try directory.writeFile(.{ .sub_path = air_filename, .data = test_air });
    try directory.writeFile(.{ .sub_path = metallib_filename, .data = test_metallib });
    const encoded = try renderManifest(allocator, .{
        .measurements = .{
            .air = measurementOf(test_air),
            .metallib = measurementOf(test_metallib),
        },
        .toolchain = test_toolchain,
    });
    try directory.writeFile(.{ .sub_path = manifest_filename, .data = encoded });
    return encoded;
}

fn replaceManifestOnce(
    directory: std.fs.Dir,
    encoded: []u8,
    needle: []const u8,
    replacement: []const u8,
) !void {
    if (needle.len != replacement.len) return error.InvalidTestReplacement;
    const offset = std.mem.indexOf(u8, encoded, needle) orelse return error.MissingTestManifestValue;
    @memcpy(encoded[offset .. offset + replacement.len], replacement);
    try directory.writeFile(.{ .sub_path = manifest_filename, .data = encoded });
}

fn replacedManifestAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    needle: []const u8,
    replacement: []const u8,
) ![]u8 {
    const offset = std.mem.indexOf(u8, encoded, needle) orelse return error.MissingTestManifestValue;
    const result = try allocator.alloc(u8, encoded.len - needle.len + replacement.len);
    @memcpy(result[0..offset], encoded[0..offset]);
    @memcpy(result[offset .. offset + replacement.len], replacement);
    @memcpy(result[offset + replacement.len ..], encoded[offset + needle.len ..]);
    return result;
}

test "Native AOT admission authenticates the generated bundle" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const bundle_path = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(bundle_path);
    const encoded = try writeTestBundle(std.testing.allocator, temporary.dir);
    defer std.testing.allocator.free(encoded);
    const trust_anchor = try renderManifestTrustAnchor(std.testing.allocator, encoded);
    defer std.testing.allocator.free(trust_anchor);
    const digest = std.fmt.bytesToHex(manifestDigest(encoded), .lower);
    const expected_anchor = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}  {s}\n",
        .{ digest, manifest_filename },
    );
    defer std.testing.allocator.free(expected_anchor);
    try std.testing.expectEqualStrings(expected_anchor, trust_anchor);

    var admission = try admit(std.testing.allocator, bundle_path, manifestDigest(encoded));
    defer admission.deinit();
    try std.testing.expectEqualStrings(test_metallib, admission.metallib_bytes);
    try std.testing.expect(measurementEql(measurementOf(test_metallib), admission.metallib));

    try temporary.dir.writeFile(.{ .sub_path = metallib_filename, .data = "synthetic-metallix" });
    try std.testing.expectEqualStrings(test_metallib, admission.metallib_bytes);
}

test "Native AOT admission rejects authority drift" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const bundle_path = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(bundle_path);
    const valid = try writeTestBundle(std.testing.allocator, temporary.dir);
    defer std.testing.allocator.free(valid);
    const candidate = try std.testing.allocator.dupe(u8, valid);
    defer std.testing.allocator.free(candidate);

    try replaceManifestOnce(
        temporary.dir,
        candidate,
        format,
        "stwo-zig-metal-core-aot-v1",
    );
    try std.testing.expectError(
        error.ManifestTrustAnchorMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(valid)),
    );
    try std.testing.expectError(
        error.UnsupportedAotFormat,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    @memcpy(candidate, valid);
    try replaceManifestOnce(temporary.dir, candidate, "\"core_shader_abi\": 12", "\"core_shader_abi\": 13");
    try std.testing.expectError(
        error.CoreShaderAbiMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    @memcpy(candidate, valid);
    try replaceManifestOnce(temporary.dir, candidate, "\"math_mode\": \"safe\"", "\"math_mode\": \"fast\"");
    try std.testing.expectError(
        error.CompileProfileMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    @memcpy(candidate, valid);
    try replaceManifestOnce(temporary.dir, candidate, "\"minimum_deployment_target\": \"14.0\"", "\"minimum_deployment_target\": \"13.0\"");
    try std.testing.expectError(
        error.TargetPolicyMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    @memcpy(candidate, valid);
    const digest = std.fmt.bytesToHex(sourceDigest(), .lower);
    var wrong_digest = digest;
    wrong_digest[0] = if (wrong_digest[0] == '0') '1' else '0';
    try replaceManifestOnce(temporary.dir, candidate, &digest, &wrong_digest);
    try std.testing.expectError(
        error.CoreSourceIdentityMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    @memcpy(candidate, valid);
    const export_name = authorityExports()[0].name;
    const wrong_name = try std.testing.allocator.dupe(u8, export_name);
    defer std.testing.allocator.free(wrong_name);
    wrong_name[wrong_name.len - 1] = if (wrong_name[wrong_name.len - 1] == 'x') 'y' else 'x';
    try replaceManifestOnce(temporary.dir, candidate, export_name, wrong_name);
    try std.testing.expectError(
        error.CoreExportInventoryMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    @memcpy(candidate, valid);
    const declaration_digest = abi_contract.native_kernel_abi[0].declaration_sha256;
    const wrong_declaration_digest = try std.testing.allocator.dupe(u8, declaration_digest);
    defer std.testing.allocator.free(wrong_declaration_digest);
    wrong_declaration_digest[0] = if (wrong_declaration_digest[0] == '0') '1' else '0';
    try replaceManifestOnce(temporary.dir, candidate, declaration_digest, wrong_declaration_digest);
    try std.testing.expectError(
        error.CoreKernelAbiMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    @memcpy(candidate, valid);
    try replaceManifestOnce(temporary.dir, candidate, "\"sha256\": \"ab", "\"sha256\": \"AB");
    try std.testing.expectError(
        error.InvalidToolchainIdentity,
        admit(std.testing.allocator, bundle_path, manifestDigest(candidate)),
    );

    const incomplete = try replacedManifestAlloc(
        std.testing.allocator,
        valid,
        "\"xcode_version\": \"16.0\"",
        "\"xcode_version\": \"\"",
    );
    defer std.testing.allocator.free(incomplete);
    try temporary.dir.writeFile(.{ .sub_path = manifest_filename, .data = incomplete });
    try std.testing.expectError(
        error.InvalidToolchainIdentity,
        admit(std.testing.allocator, bundle_path, manifestDigest(incomplete)),
    );
}

test "Native AOT admission rejects corrupted artifacts and incomplete manifests" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const bundle_path = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(bundle_path);
    const built = try writeTestBundle(std.testing.allocator, temporary.dir);
    defer std.testing.allocator.free(built);

    try temporary.dir.writeFile(.{ .sub_path = source_filename, .data = source()[0 .. source().len - 1] });
    try std.testing.expectError(
        error.CoreSourceIdentityMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(built)),
    );
    try temporary.dir.writeFile(.{ .sub_path = source_filename, .data = source() });

    try temporary.dir.writeFile(.{ .sub_path = air_filename, .data = "synthetic-aix" });
    try std.testing.expectError(
        error.AirIdentityMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(built)),
    );
    try temporary.dir.writeFile(.{ .sub_path = air_filename, .data = test_air });

    try temporary.dir.writeFile(.{ .sub_path = metallib_filename, .data = "synthetic-metallix" });
    try std.testing.expectError(
        error.MetallibIdentityMismatch,
        admit(std.testing.allocator, bundle_path, manifestDigest(built)),
    );
    try temporary.dir.writeFile(.{ .sub_path = metallib_filename, .data = test_metallib });

    const emitted = try renderManifest(std.testing.allocator, null);
    defer std.testing.allocator.free(emitted);
    try temporary.dir.writeFile(.{ .sub_path = manifest_filename, .data = emitted });
    try std.testing.expectError(
        error.MissingToolchainIdentity,
        admit(std.testing.allocator, bundle_path, manifestDigest(emitted)),
    );
}
