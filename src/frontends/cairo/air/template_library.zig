//! Authenticated all-family Cairo AIR template manifest.

const std = @import("std");
const preprocessed = @import("../preprocessed/trace.zig");
const composition = @import("../witness/composition_bundle.zig");
const registry = @import("official_claim_registry.zig");

const schema = "stwo-zig-cairo-air-template-library-v1";
const version: u32 = 1;
const max_manifest_bytes: usize = 64 * 1024;
const max_bundle_bytes: usize = 512 * 1024 * 1024;

pub const Role = enum { opcodes, canonical, canonical_small };

const AssetDocument = struct {
    path: []const u8,
    bytes: u64,
    sha256: []const u8,
};

const AuthorityDocument = struct {
    stwo_cairo_revision: []const u8,
    stwo_revision: []const u8,
};

pub const SegmentStarts = struct {
    add_mod_builtin: ?u32 = null,
    bitwise_builtin: ?u32 = null,
    mul_mod_builtin: ?u32 = null,
    pedersen_builtin: ?u32 = null,
    pedersen_builtin_narrow_windows: ?u32 = null,
    poseidon_builtin: ?u32 = null,
    range_check96_builtin: ?u32 = null,
    range_check_builtin: ?u32 = null,
    ec_op_builtin: ?u32 = null,

    pub fn get(self: SegmentStarts, label: []const u8) ?u32 {
        inline for (std.meta.fields(SegmentStarts)) |field| {
            if (std.mem.eql(u8, label, field.name))
                return @field(self, field.name);
        }
        return null;
    }
};

const SourceDocument = struct {
    role: []const u8,
    preprocessed_variant: []const u8,
    input_sha256: []const u8,
    bundle: AssetDocument,
    segment_starts: SegmentStarts,
};

const Document = struct {
    schema: []const u8,
    version: u32,
    authority: AuthorityDocument,
    sources: []SourceDocument,
};

pub const Source = struct {
    role: Role,
    variant: preprocessed.Variant,
    segment_starts: SegmentStarts,
    bundle: composition.Bundle,

    pub fn find(self: Source, label: []const u8) ?*const composition.Component {
        for (self.bundle.components) |*component| {
            if (templateLabelMatches(component.label, label))
                return component;
        }
        return null;
    }
};

pub const Library = struct {
    allocator: std.mem.Allocator,
    sources: []Source,

    pub fn readFile(
        allocator: std.mem.Allocator,
        manifest_path: []const u8,
    ) !Library {
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
            document.version != version or
            !std.mem.eql(
                u8,
                document.authority.stwo_cairo_revision,
                registry.source_revision.stwo_cairo,
            ) or
            !std.mem.eql(
                u8,
                document.authority.stwo_revision,
                registry.source_revision.stwo,
            ) or document.sources.len != 3)
            return error.InvalidTemplateManifest;

        const sources = try allocator.alloc(Source, document.sources.len);
        errdefer allocator.free(sources);
        var initialized: usize = 0;
        errdefer for (sources[0..initialized]) |*source| source.bundle.deinit();
        const directory = std.fs.path.dirname(manifest_path) orelse ".";
        for (document.sources, sources) |source_document, *source| {
            const source_role = std.meta.stringToEnum(Role, source_document.role) orelse
                return error.InvalidTemplateRole;
            const variant = std.meta.stringToEnum(
                preprocessed.Variant,
                source_document.preprocessed_variant,
            ) orelse return error.InvalidTemplateVariant;
            _ = try parseSha256(source_document.input_sha256);
            const path = try authenticatedPath(
                allocator,
                directory,
                source_document.bundle,
            );
            defer allocator.free(path);
            source.* = .{
                .role = source_role,
                .variant = variant,
                .segment_starts = source_document.segment_starts,
                .bundle = try composition.Bundle.readFile(allocator, path),
            };
            initialized += 1;
        }
        var library = Library{ .allocator = allocator, .sources = sources };
        errdefer library.deinit();
        try library.validate();
        return library;
    }

    pub fn deinit(self: *Library) void {
        for (self.sources) |*source| source.bundle.deinit();
        self.allocator.free(self.sources);
        self.* = undefined;
    }

    pub fn instantiate(
        self: Library,
        allocator: std.mem.Allocator,
        geometry: *const @import("../claim_generator.zig").OwnedClaimGeometry,
        target_variant: preprocessed.Variant,
        segments: @import("../adapter/mod.zig").BuiltinSegments,
    ) !composition.Bundle {
        return @import("template_binding.zig").instantiate(
            allocator,
            self,
            geometry,
            target_variant,
            segments,
        );
    }

    fn validate(self: Library) !void {
        var roles = [_]bool{false} ** std.meta.fields(Role).len;
        for (self.sources) |source| {
            const role_index = @intFromEnum(source.role);
            if (roles[role_index] or source.bundle.format_version != composition.version)
                return error.InvalidTemplateManifest;
            roles[role_index] = true;
            switch (source.role) {
                .opcodes, .canonical => if (source.variant != .canonical)
                    return error.InvalidTemplateVariant,
                .canonical_small => if (source.variant != .canonical_small)
                    return error.InvalidTemplateVariant,
            }
        }
        for (roles) |present| if (!present)
            return error.MissingTemplateRole;
        for (registry.claim_fields) |field| {
            var found = false;
            for (self.sources) |source| {
                if (source.find(field.name) != null) {
                    found = true;
                    break;
                }
            }
            if (!found) return error.IncompleteTemplateCoverage;
        }
    }

    pub fn sourceFor(
        self: Library,
        label: []const u8,
        trace_log: u32,
        target_variant: preprocessed.Variant,
    ) !*const Source {
        const source_role: Role = switch (target_variant) {
            .canonical, .canonical_without_pedersen => .canonical,
            .canonical_small => .canonical_small,
        };
        const variant_source = self.sourceByRole(source_role);
        const opcode_source = self.sourceByRole(.opcodes);
        if (variant_source.find(label)) |component| {
            if (component.trace_log_size == trace_log) return variant_source;
        }
        if (opcode_source.find(label)) |component| {
            if (component.trace_log_size == trace_log) return opcode_source;
        }
        if (variant_source.find(label) != null) return variant_source;
        if (opcode_source.find(label) != null) return opcode_source;
        return error.MissingAirTemplate;
    }

    fn sourceByRole(self: Library, wanted: Role) *const Source {
        for (self.sources) |*source| if (source.role == wanted) return source;
        unreachable;
    }
};

fn authenticatedPath(
    allocator: std.mem.Allocator,
    directory: []const u8,
    asset: AssetDocument,
) ![]u8 {
    if (asset.path.len == 0 or std.fs.path.isAbsolute(asset.path) or
        asset.bytes == 0 or asset.bytes > max_bundle_bytes)
        return error.InvalidTemplateAsset;
    const expected = try parseSha256(asset.sha256);
    const path = try std.fs.path.resolve(allocator, &.{ directory, asset.path });
    errdefer allocator.free(path);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size != asset.bytes)
        return error.InvalidTemplateAsset;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
    }
    if (!std.mem.eql(u8, &hasher.finalResult(), &expected))
        return error.TemplateAssetDigestMismatch;
    return path;
}

fn parseSha256(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidSha256;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidSha256;
    return digest;
}

fn templateLabelMatches(template: []const u8, live: []const u8) bool {
    if (std.mem.eql(u8, template, live)) return true;
    return std.mem.eql(u8, live, "memory_id_to_big") and
        std.mem.eql(u8, template, "memory_id_to_big[0]");
}

test "official Cairo AIR template library covers all claim fields" {
    var library = try Library.readFile(
        std.testing.allocator,
        "vectors/cairo/official/air_template_library_v1.json",
    );
    defer library.deinit();
    try std.testing.expectEqual(@as(usize, 3), library.sources.len);
    const canonical = library.sourceByRole(.canonical);
    const add_small = canonical.find("add_opcode_small").?;
    try std.testing.expectEqual(
        Role.canonical,
        (try library.sourceFor(
            "add_opcode_small",
            add_small.trace_log_size,
            .canonical,
        )).role,
    );
    const opcodes = library.sourceByRole(.opcodes);
    const blake_compress = opcodes.find("blake_compress_opcode").?;
    try std.testing.expectEqual(
        Role.opcodes,
        (try library.sourceFor(
            "blake_compress_opcode",
            blake_compress.trace_log_size,
            .canonical,
        )).role,
    );
}
