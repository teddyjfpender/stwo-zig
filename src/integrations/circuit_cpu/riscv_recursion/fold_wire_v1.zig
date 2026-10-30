//! Thin structural RISC circuit-fold metadata. Source public statements and
//! external checkpoints are supplied separately, not duplicated in every node.
//! Contains no key, expected-root nomination, proof body or successful receipt.
const std = @import("std");
const Fold = @import("circuit_fold_v1.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Registry = @import("registry_v1.zig");
const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
const OriginalAdmission = @import("../riscv_originals_v1/admission.zig");
pub const Record = struct { kind: u32, a: u32, b: u32 = 0 };
pub const Catalog = struct { records: []const Record, root: u32, sources: u32 };
pub const MAX_RECORDS: usize = 4095;
const HEADER: usize = 24;
pub fn validate(catalog: Catalog, actual_sources: usize) !void {
    if (actual_sources == 0 or actual_sources > 2048 or catalog.sources != actual_sources or catalog.records.len != 2 * actual_sources - 1 or catalog.records.len > MAX_RECORDS or catalog.root >= catalog.records.len or catalog.root + 1 != catalog.records.len) return error.InvalidRiscCircuitFoldCatalog;
    var uses: [MAX_RECORDS]u8 = @splat(0);
    var sources: [2048]bool = @splat(false);
    var depths: [MAX_RECORDS]u8 = @splat(0);
    var first_source: [MAX_RECORDS]u32 = @splat(0);
    var source_count: [MAX_RECORDS]u32 = @splat(0);
    var leaves: usize = 0;
    for (catalog.records, 0..) |record, i| switch (record.kind) {
        1, 3 => {
            if (record.b != 0 or record.a >= actual_sources or sources[record.a]) return error.InvalidRiscCircuitFoldCatalog;
            sources[record.a] = true;
            first_source[i] = record.a;
            source_count[i] = 1;
            leaves += 1;
        },
        2 => {
            if (record.a >= i or record.b >= i or record.a == record.b or uses[record.a] != 0 or uses[record.b] != 0) return error.InvalidRiscCircuitFoldCatalog;
            uses[record.a] = 1;
            uses[record.b] = 1;
            if (first_source[record.a] + source_count[record.a] != first_source[record.b]) return error.InvalidRiscCircuitFoldCatalog;
            first_source[i] = first_source[record.a];
            source_count[i] = source_count[record.a] + source_count[record.b];
            depths[i] = 1 + @max(depths[record.a], depths[record.b]);
            if (depths[i] > 16) return error.RiscCircuitFoldResourceLimit;
        },
        else => return error.InvalidRiscCircuitFoldCatalog,
    };
    if (leaves != actual_sources) return error.InvalidRiscCircuitFoldCatalog;
    if (first_source[catalog.root] != 0 or source_count[catalog.root] != actual_sources) return error.InvalidRiscCircuitFoldCatalog;
    for (uses[0..catalog.root]) |used| if (used != 1) return error.InvalidRiscCircuitFoldCatalog;
    if (uses[catalog.root] != 0) return error.InvalidRiscCircuitFoldCatalog;
}
pub fn encode(a: std.mem.Allocator, catalog: Catalog) ![]u8 {
    try validate(catalog, catalog.sources);
    const bytes = try a.alloc(u8, HEADER + 16 * catalog.records.len);
    var direct_originals = false;
    for (catalog.records) |record| if (record.kind == 3) {
        direct_originals = true;
    };
    @memcpy(bytes[0..8], if (direct_originals) "R8CFMD02" else "R8CFMD01");
    put(bytes, 8, if (direct_originals) 2 else 1);
    put(bytes, 12, @intCast(catalog.records.len));
    put(bytes, 16, catalog.root);
    put(bytes, 20, catalog.sources);
    for (catalog.records, 0..) |record, i| {
        const first = HEADER + 16 * i;
        put(bytes, first, record.kind);
        put(bytes, first + 4, record.a);
        put(bytes, first + 8, record.b);
        put(bytes, first + 12, 0);
    }
    return bytes;
}
/// All decoded metadata belongs to the caller's arena. The supplied source
/// statements carry public values/pins, not trusted producer keys; Fold.derive
/// independently reconstructs every one before receiving any outer proof.
pub fn decodeLeaky(a: std.mem.Allocator, bytes: []const u8, sources: []const Upper.Tree) !Fold.Metadata {
    if (sources.len == 0 or sources.len > 2048) return error.InvalidRiscCircuitFoldCatalog;
    const wrapped = try a.alloc(SourceMetadata, sources.len);
    for (wrapped, sources) |*destination, source| destination.* = .{ .leaf = source };
    return decodeSourcesLeaky(a, bytes, wrapped);
}
/// Original metadata does not carry a producer key/receipt. Native-form inputs
/// may contain an old Upper.Leaf.main_root nomination for legacy compatibility;
/// direct OriginalAdmission/window_join authority ignores that nomination and
/// never verifies or constructs a NativeParent proof. Actual ORIGINAL roots
/// inside local statements remain authenticated input variables as required.
pub const SourceMetadata = union(enum) { leaf: Upper.Tree, originals: OriginalAdmission.Metadata };
pub fn decodeSourcesLeaky(a: std.mem.Allocator, bytes: []const u8, sources: []const SourceMetadata) !Fold.Metadata {
    if (bytes.len < HEADER or bytes.len > HEADER + 16 * MAX_RECORDS) return error.InvalidRiscCircuitFoldCatalog;
    const legacy = std.mem.eql(u8, bytes[0..8], "R8CFMD01") and get(bytes, 8) == 1;
    const direct = std.mem.eql(u8, bytes[0..8], "R8CFMD02") and get(bytes, 8) == 2;
    if (!legacy and !direct) return error.InvalidRiscCircuitFoldCatalog;
    const count = get(bytes, 12);
    if (count == 0 or count > MAX_RECORDS or bytes.len != HEADER + 16 * @as(usize, count)) return error.InvalidRiscCircuitFoldCatalog;
    const records = try a.alloc(Record, count);
    var direct_originals = false;
    for (records, 0..) |*record, i| {
        const first = HEADER + 16 * i;
        if (get(bytes, first + 12) != 0) return error.InvalidRiscCircuitFoldCatalog;
        record.* = .{ .kind = get(bytes, first), .a = get(bytes, first + 4), .b = get(bytes, first + 8) };
        if (record.kind == 3) direct_originals = true;
    }
    if (direct != direct_originals) return error.InvalidRiscCircuitFoldCatalog;
    const catalog = Catalog{ .records = records, .root = get(bytes, 16), .sources = get(bytes, 20) };
    try validate(catalog, sources.len);
    const metadata = try a.alloc(Fold.Metadata, count);
    for (metadata, records) |*node, record| {
        node.* = switch (record.kind) {
            1 => switch (sources[record.a]) {
                .leaf => |source| .{ .leaf = source },
                else => return error.RiscCircuitFoldSourceKindMismatch,
            },
            3 => switch (sources[record.a]) {
                .originals => |source| .{ .originals = source },
                else => return error.RiscCircuitFoldSourceKindMismatch,
            },
            2 => pair: {
                const children = try a.create([2]Fold.Metadata);
                children.* = .{ metadata[record.a], metadata[record.b] };
                break :pair .{ .pair = children };
            },
            else => unreachable,
        };
    }
    const root = metadata[catalog.root];
    try Fold.validateMetadata(root);
    return root;
}
pub const Receiving = struct {
    sources: []const Upper.Tree,
    elf: []const u8,
    private_input: []const u8,
    trusted: Full.Trusted,
    canonical_circuit_air: []const u8,
    canonical_circuit_projection: []const u8,
};
pub const SourceReceiving = struct {
    sources: []const SourceMetadata,
    elf: []const u8,
    private_input: []const u8,
    trusted: Full.Trusted,
    canonical_circuit_air: []const u8,
    canonical_circuit_projection: []const u8,
};
/// Complete wire entry point: receiving independently parses the pinned
/// eleven-AIR authorities and derives the loader/input/expected-output policy.
/// No serialized backend, evaluator, expected VK or producer receipt is read.
pub fn verifyFullBytes(a: std.mem.Allocator, public_wire: []const u8, proof: []const u8, receiving: Receiving, options: Registry.Options) !void {
    if (proof.len == 0 or proof.len > 128 << 20) return error.RiscCircuitProofResourceLimit;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const metadata = try decodeLeaky(arena.allocator(), public_wire, receiving.sources);
    const backend = try Registry.BackendAuthority.load(a, receiving.canonical_circuit_air, receiving.canonical_circuit_projection);
    defer backend.deinit();
    var boundary = try Full.Owned.derive(a, receiving.elf, receiving.private_input, receiving.trusted, .{});
    defer boundary.deinit();
    try Fold.verifyFull(a, metadata, proof, &boundary, backend, options);
}
/// Direct ORIGINAL_JOIN leaves and legacy wrapped leaves share the same full
/// circuit verifier and boundary law; independently derived role-specific
/// topology keys prevent either family being substituted for the other.
pub fn verifyFullSourceBytes(a: std.mem.Allocator, public_wire: []const u8, proof: []const u8, receiving: SourceReceiving, options: Registry.Options) !void {
    if (proof.len == 0 or proof.len > 128 << 20) return error.RiscCircuitProofResourceLimit;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const metadata = try decodeSourcesLeaky(arena.allocator(), public_wire, receiving.sources);
    const backend = try Registry.BackendAuthority.load(a, receiving.canonical_circuit_air, receiving.canonical_circuit_projection);
    defer backend.deinit();
    var boundary = try Full.Owned.derive(a, receiving.elf, receiving.private_input, receiving.trusted, .{});
    defer boundary.deinit();
    try Fold.verifyFull(a, metadata, proof, &boundary, backend, options);
}
fn put(bytes: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], value, .little);
}
fn get(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}
