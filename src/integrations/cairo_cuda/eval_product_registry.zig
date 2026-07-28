//! Immutable product-AOT admission for canonical Cairo constraint bodies.

const std = @import("std");
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const cuda_backend = @import("stwo_cuda_backend");
const eval_aot = @import("eval_aot.zig");

const product_manifest =
    cuda_backend.product_aot.cairo_eval_product_manifest;
const expected_body_count = 271;

const WireEntry = struct {
    abi_schema: []const u8,
    cache_key: []const u8,
    catalog_identity: []const u8,
    codegen_version: u32,
    file: []const u8,
    identity_scheme: []const u8,
    kernel_name: []const u8,
    kind: []const u8,
    label: []const u8,
    module_globals: []const u8,
    occurrences: std.json.Value,
    program_identity: []const u8,
    semantic_hash: []const u8,
    source_sha256: []const u8,
};

pub const ResolvedBody = struct {
    cache_key: u64,
    kernel_name: []const u8,
    semantic_hash: u64,
    program_identity: [32]u8,
    source_identity: [32]u8,
    catalog_identity: [32]u8,
};

pub const Registry = struct {
    parsed: std.json.Parsed([]WireEntry),

    pub fn initProduct(allocator: std.mem.Allocator) !Registry {
        var parsed = try std.json.parseFromSlice(
            []WireEntry,
            allocator,
            product_manifest,
            .{},
        );
        errdefer parsed.deinit();
        if (parsed.value.len != expected_body_count)
            return error.InvalidCairoEvalProductInventory;
        for (parsed.value) |entry| {
            if (!validEntry(entry))
                return error.InvalidCairoEvalProductIdentity;
        }
        return .{ .parsed = parsed };
    }

    pub fn deinit(self: *Registry) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn resolve(
        self: Registry,
        body: eval_aot.Body,
    ) ?ResolvedBody {
        if (body.semantic_hash == 0 or body.cache_key == 0 or
            std.mem.allEqual(u8, &body.program_identity, 0) or
            std.mem.allEqual(u8, &body.source_identity, 0) or
            std.mem.allEqual(u8, &body.catalog_identity, 0))
        {
            return null;
        }
        for (self.parsed.value) |entry| {
            const semantic_hash =
                decodeHexInt(u64, entry.semantic_hash) orelse continue;
            const cache_key =
                decodeHexInt(u64, entry.cache_key) orelse continue;
            if (semantic_hash != body.semantic_hash or
                cache_key != body.cache_key or
                !std.mem.eql(u8, entry.kernel_name, body.kernel_name))
            {
                continue;
            }
            const program_identity =
                decodeDigest(entry.program_identity) orelse continue;
            const source_identity =
                decodeDigest(entry.source_sha256) orelse continue;
            const catalog_identity =
                decodeDigest(entry.catalog_identity) orelse continue;
            if (!std.mem.eql(
                u8,
                &program_identity,
                &body.program_identity,
            ) or !std.mem.eql(
                u8,
                &source_identity,
                &body.source_identity,
            ) or !std.mem.eql(
                u8,
                &catalog_identity,
                &body.catalog_identity,
            ) or !derivedNamesMatch(entry, semantic_hash, cache_key)) {
                continue;
            }
            return .{
                .cache_key = cache_key,
                .kernel_name = entry.kernel_name,
                .semantic_hash = semantic_hash,
                .program_identity = program_identity,
                .source_identity = source_identity,
                .catalog_identity = catalog_identity,
            };
        }
        return null;
    }
};

fn validEntry(entry: WireEntry) bool {
    const semantic_hash =
        decodeHexInt(u64, entry.semantic_hash) orelse return false;
    const cache_key =
        decodeHexInt(u64, entry.cache_key) orelse return false;
    return std.mem.eql(u8, entry.abi_schema, eval_aot.abi_schema) and
        std.mem.eql(u8, entry.identity_scheme, eval_aot.identity_scheme) and
        entry.codegen_version == eval_aot.codegen_version and
        std.mem.eql(u8, entry.kind, "constraint") and
        std.mem.eql(u8, entry.module_globals, "none") and
        decodeDigest(entry.program_identity) != null and
        decodeDigest(entry.source_sha256) != null and
        decodeDigest(entry.catalog_identity) != null and
        entry.occurrences == .array and
        entry.occurrences.array.items.len != 0 and
        derivedNamesMatch(entry, semantic_hash, cache_key);
}

fn derivedNamesMatch(
    entry: WireEntry,
    semantic_hash: u64,
    cache_key: u64,
) bool {
    var label_storage: [64]u8 = undefined;
    const label = std.fmt.bufPrint(
        &label_storage,
        "cairo_eval_{x:0>16}",
        .{semantic_hash},
    ) catch return false;
    if (!std.mem.eql(u8, entry.label, label)) return false;
    var file_storage: [128]u8 = undefined;
    const file = std.fmt.bufPrint(
        &file_storage,
        "constraint_{s}_{x:0>16}.cu",
        .{ label, cache_key },
    ) catch return false;
    return std.mem.eql(u8, entry.file, file);
}

fn decodeHexInt(comptime T: type, encoded: []const u8) ?T {
    if (encoded.len != @sizeOf(T) * 2 or !lowerHex(encoded)) return null;
    const value = std.fmt.parseUnsigned(T, encoded, 16) catch return null;
    return if (value == 0) null else value;
}

fn decodeDigest(encoded: []const u8) ?[32]u8 {
    if (encoded.len != 64 or !lowerHex(encoded)) return null;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return null;
    return if (std.mem.allEqual(u8, &digest, 0)) null else digest;
}

fn lowerHex(encoded: []const u8) bool {
    for (encoded) |byte| {
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f'))
            return false;
    }
    return true;
}

test "all 279 SN2 constraint placements resolve to 271 product bodies" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(
        allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
    );
    defer bundle.deinit();
    var product = try eval_aot.build(allocator, bundle);
    defer product.deinit();
    var registry = try Registry.initProduct(allocator);
    defer registry.deinit();

    try std.testing.expectEqual(
        @as(usize, expected_body_count),
        product.bodies.len,
    );
    try std.testing.expectEqual(@as(usize, 279), product.occurrence_count);
    var resolved_occurrences: usize = 0;
    for (product.bodies) |body| {
        const resolved = registry.resolve(body) orelse
            return error.MissingCairoEvalProduct;
        try std.testing.expectEqual(body.cache_key, resolved.cache_key);
        try std.testing.expectEqualStrings(
            body.kernel_name,
            resolved.kernel_name,
        );
        resolved_occurrences += body.occurrences.len;
    }
    try std.testing.expectEqual(
        product.occurrence_count,
        resolved_occurrences,
    );

    var forged = product.bodies[0];
    forged.catalog_identity[0] ^= 1;
    try std.testing.expect(registry.resolve(forged) == null);
}
