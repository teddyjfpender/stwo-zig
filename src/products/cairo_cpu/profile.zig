//! Authenticated file-backed proving profiles for the Cairo CPU product.

const std = @import("std");
const stwo = @import("stwo_cairo_cpu");

const cairo = stwo.frontends.cairo;

pub const schema = "stwo-zig-cairo-proving-profile-v2";
pub const version: u32 = 2;
pub const default_profile = "official-all-opcodes-canonical-small";
const max_manifest_bytes: usize = 64 * 1024;
const max_asset_bytes: usize = 512 * 1024 * 1024;

const Asset = struct {
    path: []const u8,
    sha256: []const u8,
};

const Assets = struct {
    witness_programs: Asset,
    witness_topology: Asset,
    fixed_tables: Asset,
    relation_templates: Asset,
    air_programs: Asset,
};

const Document = struct {
    schema: []const u8,
    version: u32,
    profile: []const u8,
    preprocessed_variant: []const u8,
    assets: Assets,
};

pub const Paths = struct {
    allocator: std.mem.Allocator,
    profile: []u8,
    variant: cairo.preprocessed.trace.Variant,
    witness_programs: []u8,
    witness_topology: []u8,
    fixed_tables: []u8,
    relation_templates: []u8,
    air_programs: []u8,

    pub fn deinit(self: *Paths) void {
        self.allocator.free(self.profile);
        self.allocator.free(self.witness_programs);
        self.allocator.free(self.witness_topology);
        self.allocator.free(self.fixed_tables);
        self.allocator.free(self.relation_templates);
        self.allocator.free(self.air_programs);
        self.* = undefined;
    }
};

pub fn load(allocator: std.mem.Allocator, manifest_path: []const u8) !Paths {
    const encoded = try std.fs.cwd().readFileAlloc(
        allocator,
        manifest_path,
        max_manifest_bytes,
    );
    defer allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(Document, allocator, encoded, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    const document = parsed.value;
    if (!std.mem.eql(u8, document.schema, schema) or
        document.version != version)
        return error.UnsupportedProfileSchema;
    if (!std.mem.eql(u8, document.profile, default_profile))
        return error.UnsupportedProfile;
    const variant = std.meta.stringToEnum(
        cairo.preprocessed.trace.Variant,
        document.preprocessed_variant,
    ) orelse return error.UnsupportedPreprocessedVariant;

    const directory = std.fs.path.dirname(manifest_path) orelse ".";
    var paths = Paths{
        .allocator = allocator,
        .profile = try allocator.dupe(u8, document.profile),
        .variant = variant,
        .witness_programs = try resolveAsset(
            allocator,
            directory,
            document.assets.witness_programs,
        ),
        .witness_topology = undefined,
        .fixed_tables = undefined,
        .relation_templates = undefined,
        .air_programs = undefined,
    };
    errdefer {
        allocator.free(paths.profile);
        allocator.free(paths.witness_programs);
    }
    paths.witness_topology = try resolveAsset(
        allocator,
        directory,
        document.assets.witness_topology,
    );
    errdefer allocator.free(paths.witness_topology);
    paths.fixed_tables = try resolveAsset(
        allocator,
        directory,
        document.assets.fixed_tables,
    );
    errdefer allocator.free(paths.fixed_tables);
    paths.relation_templates = try resolveAsset(
        allocator,
        directory,
        document.assets.relation_templates,
    );
    errdefer allocator.free(paths.relation_templates);
    paths.air_programs = try resolveAsset(
        allocator,
        directory,
        document.assets.air_programs,
    );
    errdefer allocator.free(paths.air_programs);
    return paths;
}

pub fn defaultManifestPath(allocator: std.mem.Allocator) ![]u8 {
    const executable_dir = try std.fs.selfExeDirPathAlloc(allocator);
    defer allocator.free(executable_dir);
    return std.fs.path.resolve(allocator, &.{
        executable_dir,
        "..",
        "share",
        "stwo-zig",
        "cairo",
        "official",
        "all_opcodes.params.json",
    });
}

fn resolveAsset(
    allocator: std.mem.Allocator,
    directory: []const u8,
    asset: Asset,
) ![]u8 {
    if (asset.path.len == 0 or std.fs.path.isAbsolute(asset.path))
        return error.InvalidAssetPath;
    const expected = parseSha256(asset.sha256) catch
        return error.InvalidAssetDigest;
    const path = try std.fs.path.resolve(allocator, &.{ directory, asset.path });
    errdefer allocator.free(path);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size == 0 or stat.size > max_asset_bytes)
        return error.InvalidAsset;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
    }
    const actual = hasher.finalResult();
    if (!std.mem.eql(u8, &actual, &expected))
        return error.AssetDigestMismatch;
    return path;
}

fn parseSha256(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidSha256;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch
        return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical))
        return error.InvalidSha256;
    return digest;
}

test "official Cairo CPU proving profile authenticates every asset" {
    var paths = try load(
        std.testing.allocator,
        "vectors/cairo/official/all_opcodes.params.json",
    );
    defer paths.deinit();
    try std.testing.expectEqualStrings(default_profile, paths.profile);
    try std.testing.expectEqual(
        cairo.preprocessed.trace.Variant.canonical_small,
        paths.variant,
    );
}
