//! Immutable product-AOT identities used before CUDA execution.

const std = @import("std");

pub const recorded_witness_identity_scheme =
    "sha256-source-and-blake3-program-v1";

const product_manifest = @embedFile("native/aot_manifest.json");

const Origin = enum {
    authenticated_product,
    copied_reference,
};

const WireEntry = struct {
    abi_schema: []const u8,
    cache_key: []const u8,
    file: []const u8,
    identity_scheme: ?[]const u8 = null,
    kernel_name: []const u8,
    kind: []const u8,
    label: []const u8,
    program_identity: []const u8,
    semantic_contract: ?[]const u8 = null,
    semantic_hash: []const u8,
    source_sha256: ?[]const u8 = null,
};

pub const CanonicalWitness = struct {
    label: []const u8,
    semantic_hash: u64,
    program_identity: [32]u8,
};

pub const RecordedWitness = struct {
    cache_key: u64,
    kernel_name: []const u8,
    semantic_hash: u64,
    program_identity: [32]u8,
};

pub const Registry = struct {
    parsed: std.json.Parsed([]WireEntry),
    origin: Origin,

    pub fn initProduct(allocator: std.mem.Allocator) !Registry {
        return initFromManifest(
            allocator,
            product_manifest,
            .authenticated_product,
        );
    }

    pub fn deinit(self: *Registry) void {
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn admitsRecordedWitness(
        self: Registry,
        canonical: CanonicalWitness,
    ) bool {
        return self.resolveRecordedWitness(canonical) != null;
    }

    /// Resolves only a byte- and identity-authenticated product entry. The
    /// returned kernel name borrows this registry and cannot outlive it.
    pub fn resolveRecordedWitness(
        self: Registry,
        canonical: CanonicalWitness,
    ) ?RecordedWitness {
        if (self.origin != .authenticated_product or
            canonical.label.len == 0 or
            canonical.semantic_hash == 0 or
            std.mem.allEqual(u8, &canonical.program_identity, 0))
        {
            return null;
        }
        for (self.parsed.value) |entry| {
            if (!isProductRecordedWitness(entry) or
                !std.mem.eql(u8, entry.label, canonical.label))
            {
                continue;
            }
            const semantic_hash = decodeHexInt(u64, entry.semantic_hash) orelse
                continue;
            const program_identity = decodeDigest(entry.program_identity) orelse
                continue;
            if (semantic_hash == canonical.semantic_hash and
                std.mem.eql(
                    u8,
                    &program_identity,
                    &canonical.program_identity,
                ))
            {
                return .{
                    .cache_key = decodeHexInt(
                        u64,
                        entry.cache_key,
                    ) orelse continue,
                    .kernel_name = entry.kernel_name,
                    .semantic_hash = semantic_hash,
                    .program_identity = program_identity,
                };
            }
        }
        return null;
    }
};

fn initFromManifest(
    allocator: std.mem.Allocator,
    manifest: []const u8,
    origin: Origin,
) !Registry {
    var parsed = try std.json.parseFromSlice(
        []WireEntry,
        allocator,
        manifest,
        .{},
    );
    errdefer parsed.deinit();
    if (parsed.value.len == 0) return error.EmptyProductAotRegistry;
    if (origin == .authenticated_product) {
        for (parsed.value) |entry| {
            if (std.mem.eql(u8, entry.abi_schema, "recorded_witness_v1") and
                !isProductRecordedWitness(entry))
            {
                return error.InvalidProductRecordedWitnessIdentity;
            }
        }
    }
    return .{ .parsed = parsed, .origin = origin };
}

fn isProductRecordedWitness(entry: WireEntry) bool {
    if (!std.mem.eql(u8, entry.kind, "witness") or
        !std.mem.eql(u8, entry.abi_schema, "recorded_witness_v1") or
        !std.mem.eql(
            u8,
            entry.identity_scheme orelse return false,
            recorded_witness_identity_scheme,
        ) or
        entry.label.len == 0 or
        decodeHexInt(u64, entry.cache_key) == null or
        decodeHexInt(u64, entry.semantic_hash) == null or
        decodeDigest(entry.program_identity) == null or
        decodeDigest(entry.source_sha256 orelse return false) == null)
    {
        return false;
    }
    const expected_prefix = "stwo_jit_witness_";
    return std.mem.startsWith(u8, entry.kernel_name, expected_prefix) and
        entry.kernel_name.len == expected_prefix.len + entry.semantic_hash.len and
        std.mem.eql(
            u8,
            entry.kernel_name[expected_prefix.len..],
            entry.semantic_hash,
        );
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

test "authenticated registry admits only exact synthetic identity" {
    const manifest =
        \\[{
        \\  "abi_schema": "recorded_witness_v1",
        \\  "cache_key": "735903777afd70d2",
        \\  "file": "witness_add_ap_opcode_735903777afd70d2.cu",
        \\  "identity_scheme": "sha256-source-and-blake3-program-v1",
        \\  "kernel_name": "stwo_jit_witness_d94540f2fd219001",
        \\  "kind": "witness",
        \\  "label": "add_ap_opcode",
        \\  "program_identity": "1c87a53a6c6ded98045fb88728f9cbd14f79ad8471cff7a16416139a64737da5",
        \\  "semantic_hash": "d94540f2fd219001",
        \\  "source_sha256": "5d29e553bbb897538c3d9f8f6f94b88b27121877238736dcd7d2c6cfca603ce6"
        \\}]
    ;
    var registry = try initFromManifest(
        std.testing.allocator,
        manifest,
        .authenticated_product,
    );
    defer registry.deinit();
    const canonical = CanonicalWitness{
        .label = "add_ap_opcode",
        .semantic_hash = 0xd94540f2fd219001,
        .program_identity = decodeDigest(
            "1c87a53a6c6ded98045fb88728f9cbd14f79ad8471cff7a16416139a64737da5",
        ).?,
    };
    const resolved = registry.resolveRecordedWitness(canonical) orelse
        return error.MissingSyntheticWitness;
    try std.testing.expectEqual(
        @as(u64, 0x735903777afd70d2),
        resolved.cache_key,
    );
    try std.testing.expectEqualStrings(
        "stwo_jit_witness_d94540f2fd219001",
        resolved.kernel_name,
    );
    try std.testing.expectEqual(
        canonical.semantic_hash,
        resolved.semantic_hash,
    );
    try std.testing.expectEqualSlices(
        u8,
        &canonical.program_identity,
        &resolved.program_identity,
    );
    var mismatched_hash = canonical;
    mismatched_hash.semantic_hash ^= 1;
    try std.testing.expect(!registry.admitsRecordedWitness(mismatched_hash));

    var mismatched_program = canonical;
    mismatched_program.program_identity[0] ^= 1;
    try std.testing.expect(!registry.admitsRecordedWitness(mismatched_program));

    try std.testing.expect(!registry.admitsRecordedWitness(.{
        .label = "jump_opcode_abs",
        .semantic_hash = canonical.semantic_hash,
        .program_identity = canonical.program_identity,
    }));
}

test "copied-reference origin cannot authorize a matching witness" {
    const manifest =
        \\[{
        \\  "abi_schema": "recorded_witness_v1",
        \\  "cache_key": "735903777afd70d2",
        \\  "file": "witness_add_ap_opcode_735903777afd70d2.cu",
        \\  "kernel_name": "stwo_jit_witness_d94540f2fd219001",
        \\  "kind": "witness",
        \\  "label": "add_ap_opcode",
        \\  "program_identity": "1c87a53a6c6ded98045fb88728f9cbd14f79ad8471cff7a16416139a64737da5",
        \\  "semantic_hash": "d94540f2fd219001"
        \\}]
    ;
    var registry = try initFromManifest(
        std.testing.allocator,
        manifest,
        .copied_reference,
    );
    defer registry.deinit();
    try std.testing.expect(!registry.admitsRecordedWitness(.{
        .label = "add_ap_opcode",
        .semantic_hash = 0xd94540f2fd219001,
        .program_identity = [_]u8{1} ** 32,
    }));
}
