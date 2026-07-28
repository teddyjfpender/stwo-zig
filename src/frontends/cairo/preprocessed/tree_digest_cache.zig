//! Protocol-identity-bound cache for the preprocessed Merkle tree digests.
//!
//! The second artifact kind of the preprocessed product cache. Increment 9
//! cached the Pedersen affine-point table — the *source data* of the
//! preprocessed columns. This caches the *commitment* over those columns: the
//! complete Merkle layer set, root first. On a hit the preprocessed
//! `merkle_commit` is skipped entirely; the column interpolation and
//! extended-domain evaluation are still recomputed, because later stages
//! consume those evaluations.
//!
//! Key discipline is identical to the table artifact: the key is derived from
//! the product's own authenticated identity document, the preprocessed variant,
//! the structural column specification and the PCS configuration, plus this
//! artifact's own distinguishing kind tag and the exact tree shape (hasher,
//! digest width, committed domain log size and the sorted committed column
//! heights). No program, no input and no user-supplied string enters the key.
//!
//! Soundness. A loaded layer set feeds exactly the pipeline a built one would.
//! The only value the channel observes is the root, so a deviating artifact
//! yields a transcript the verifier does not reproduce and the proof fails its
//! own `--verify` replay and the official verifier. The cache is an
//! availability mechanism only. Every load failure falls back to computing, and
//! the subsequent store atomically rewrites a good artifact.
//!
//! Format note. This artifact is ~134 MB for `canonical_small`, two orders of
//! magnitude larger than the table artifact, so a single serial SHA-256 over it
//! would consume a large share of the commit time it saves. The integrity
//! trailer is therefore a *chunked* SHA-256: the payload is cut into fixed-size
//! chunks declared in the header, each chunk is hashed independently and in
//! parallel, and the trailer is SHA-256 over the header followed by the chunk
//! digests in order. That covers every payload byte exactly once under a
//! collision-resistant construction, and it parallelises across the machine.

const std = @import("std");
const prover = @import("stwo_prover_impl");
const product_cache = @import("product_cache.zig");

const magic = "STWOZPT1";
const format_version: u32 = 1;
const kind_tree_digests: u32 = 2;
const header_bytes: usize = 128;
const digest_bytes: usize = 32;
const chunk_bytes: u32 = 4 * 1024 * 1024;
/// Bounds the cache: nothing larger is ever written or read. A log-24 domain
/// with 32-byte digests is 1 GiB, so this also caps the shapes admitted.
const max_artifact_bytes: usize = 1024 * 1024 * 1024;
const max_hash_workers: usize = 16;

pub const Binding = product_cache.Binding;

const Session = struct {
    allocator: std.mem.Allocator,
    binding: Binding,
    recorder: ?*prover.stage_profile.Recorder,
};

var session: Session = undefined;

/// Arms the seam for the immediately following preprocessed commit. Inert
/// unless a product configured the preprocessed cache.
pub fn arm(
    allocator: std.mem.Allocator,
    binding: Binding,
    recorder: ?*prover.stage_profile.Recorder,
) void {
    if (!product_cache.isEnabled()) return;
    session = .{ .allocator = allocator, .binding = binding, .recorder = recorder };
    prover.pcs.merkle_layer_cache.arm(.{
        .ctx = @ptrCast(&session),
        .load = loadThunk,
        .store = storeThunk,
    });
}

pub fn disarm() void {
    prover.pcs.merkle_layer_cache.disarm();
}

const Request = prover.pcs.merkle_layer_cache.Request;

fn loadThunk(ctx: *anyopaque, request: Request, layers: []const []u8) bool {
    const state: *Session = @ptrCast(@alignCast(ctx));
    load(state, request, layers) catch {
        product_cache.recordMiss();
        return false;
    };
    var loaded: u64 = @as(u64, header_bytes) + @as(u64, digest_bytes);
    for (layers) |layer| loaded += @as(u64, layer.len);
    product_cache.recordHit(loaded);
    return true;
}

fn storeThunk(ctx: *anyopaque, request: Request, layers: []const []const u8) void {
    const state: *Session = @ptrCast(@alignCast(ctx));
    store(state, request, layers) catch return;
    var stored: u64 = @as(u64, header_bytes) + @as(u64, digest_bytes);
    for (layers) |layer| stored += @as(u64, layer.len);
    product_cache.recordStore(stored);
    product_cache.enforceBudget(state.allocator);
}

fn updateU32(hasher: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var buffer: [4]u8 = undefined;
    std.mem.writeInt(u32, &buffer, value, .little);
    hasher.update(&buffer);
}

fn updateU64(hasher: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(u64, &buffer, value, .little);
    hasher.update(&buffer);
}

/// Digest of everything about the tree's shape that is not already in the
/// binding: the hasher identity, the digest width and every committed column
/// height in committed order.
fn shapeDigest(request: Request) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("cairo-preprocessed-tree-shape/v1\x00");
    updateU32(&hasher, @intCast(request.hasher_tag.len));
    hasher.update(request.hasher_tag);
    updateU32(&hasher, request.hash_bytes);
    updateU32(&hasher, request.log_size);
    updateU32(&hasher, @intCast(request.column_log_sizes.len));
    for (request.column_log_sizes) |log_size| updateU32(&hasher, log_size);
    return hasher.finalResult();
}

fn artifactKey(binding: Binding, request: Request) [32]u8 {
    const config = product_cache.currentConfig();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cairo-preprocessed-tree-digests/v1\x00");
    hasher.update(&config.product_digest);
    hasher.update("preprocessed-merkle-layers\x00");
    hasher.update(@tagName(binding.variant));
    hasher.update("\x00");
    hasher.update(&binding.spec_digest);
    hasher.update(&binding.pcs_digest);
    updateU32(&hasher, format_version);
    updateU32(&hasher, kind_tree_digests);
    updateU32(&hasher, chunk_bytes);
    hasher.update(&shapeDigest(request));
    return hasher.finalResult();
}

fn artifactPath(buffer: []u8, key: [32]u8) ![]const u8 {
    const hex = std.fmt.bytesToHex(key, .lower);
    return std.fmt.bufPrint(
        buffer,
        "{s}/{s}.preprocessed-tree",
        .{ product_cache.currentConfig().directory, hex },
    );
}

fn payloadBytes(request: Request) !u64 {
    // Layers are 1, 2, ... 1 << log_size digests: 2^(log_size + 1) - 1 total.
    const nodes = (@as(u64, 2) << @intCast(request.log_size)) - 1;
    const total = std.math.mul(u64, nodes, request.hash_bytes) catch
        return error.PreprocessedTreeCacheUnusable;
    if (header_bytes + total + digest_bytes > max_artifact_bytes)
        return error.PreprocessedTreeCacheUnusable;
    return total;
}

fn writeHeader(
    header: *[header_bytes]u8,
    key: [32]u8,
    request: Request,
    payload: u64,
) void {
    @memset(header, 0);
    @memcpy(header[0..magic.len], magic);
    std.mem.writeInt(u32, header[8..12], format_version, .little);
    std.mem.writeInt(u32, header[12..16], kind_tree_digests, .little);
    @memcpy(header[16..48], &key);
    std.mem.writeInt(u32, header[48..52], request.hash_bytes, .little);
    std.mem.writeInt(u32, header[52..56], request.log_size, .little);
    std.mem.writeInt(u32, header[56..60], @intCast(request.log_size + 1), .little);
    std.mem.writeInt(u32, header[60..64], chunk_bytes, .little);
    std.mem.writeInt(u64, header[64..72], payload, .little);
    @memcpy(header[72..104], &shapeDigest(request));
}

// ---------------------------------------------------------------------------
// Chunked, parallel integrity digest
// ---------------------------------------------------------------------------

const ChunkPlan = struct {
    layers: []const []const u8,
    digests: [][32]u8,
    next: std.atomic.Value(usize),

    fn chunkAt(self: *const ChunkPlan, wanted: usize) ?[]const u8 {
        var remaining = wanted;
        for (self.layers) |layer| {
            const count = chunkCount(layer.len);
            if (remaining < count) {
                const start = remaining * chunk_bytes;
                const end = @min(layer.len, start + chunk_bytes);
                return layer[start..end];
            }
            remaining -= count;
        }
        return null;
    }

    fn run(self: *ChunkPlan) void {
        while (true) {
            const index = self.next.fetchAdd(1, .monotonic);
            if (index >= self.digests.len) return;
            const chunk = self.chunkAt(index) orelse return;
            std.crypto.hash.sha2.Sha256.hash(chunk, &self.digests[index], .{});
        }
    }
};

fn chunkCount(length: usize) usize {
    if (length == 0) return 1;
    return (length + chunk_bytes - 1) / chunk_bytes;
}

fn totalChunks(layers: []const []const u8) usize {
    var total: usize = 0;
    for (layers) |layer| total += chunkCount(layer.len);
    return total;
}

/// SHA-256 over the header followed by every payload chunk digest in order.
/// Each payload byte is covered exactly once; the chunk boundaries are fixed by
/// the header, so the construction is unambiguous for a given header.
fn integrityDigest(
    allocator: std.mem.Allocator,
    header: *const [header_bytes]u8,
    layers: []const []const u8,
) ![32]u8 {
    const count = totalChunks(layers);
    const digests = try allocator.alloc([32]u8, count);
    defer allocator.free(digests);

    var plan = ChunkPlan{
        .layers = layers,
        .digests = digests,
        .next = std.atomic.Value(usize).init(0),
    };

    const worker_target = @min(
        @min(count, max_hash_workers),
        @max(@as(usize, 1), std.Thread.getCpuCount() catch 1),
    );
    var threads: [max_hash_workers]std.Thread = undefined;
    var spawned: usize = 0;
    while (spawned + 1 < worker_target) : (spawned += 1) {
        threads[spawned] = std.Thread.spawn(.{}, ChunkPlan.run, .{&plan}) catch break;
    }
    plan.run();
    for (threads[0..spawned]) |thread| thread.join();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(header);
    for (digests) |digest| hasher.update(&digest);
    return hasher.finalResult();
}

// ---------------------------------------------------------------------------
// Load / store
// ---------------------------------------------------------------------------

fn load(state: *Session, request: Request, layers: []const []u8) !void {
    var stage = try prover.stage_profile.StageScope.begin(
        state.recorder,
        "preprocessed_tree_cache_load",
        "Preprocessed tree cache load",
    );
    defer stage.end();

    if (layers.len != @as(usize, request.log_size) + 1)
        return error.PreprocessedTreeCacheUnusable;
    const payload = try payloadBytes(request);
    const key = artifactKey(state.binding, request);
    product_cache.protectKey(key);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try artifactPath(&path_buffer, key);

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size != header_bytes + payload + digest_bytes)
        return error.PreprocessedTreeCacheUnusable;

    var expected_header: [header_bytes]u8 = undefined;
    writeHeader(&expected_header, key, request, payload);
    var actual_header: [header_bytes]u8 = undefined;
    try readExact(file, &actual_header);
    if (!std.mem.eql(u8, &expected_header, &actual_header))
        return error.PreprocessedTreeCacheUnusable;

    var written: u64 = 0;
    for (layers) |layer| {
        try readExact(file, layer);
        written += layer.len;
    }
    if (written != payload) return error.PreprocessedTreeCacheUnusable;

    var trailer: [digest_bytes]u8 = undefined;
    try readExact(file, &trailer);

    const views = try state.allocator.alloc([]const u8, layers.len);
    defer state.allocator.free(views);
    for (layers, views) |layer, *view| view.* = layer;

    const actual = try integrityDigest(state.allocator, &actual_header, views);
    if (!std.crypto.timing_safe.eql([digest_bytes]u8, actual, trailer))
        return error.PreprocessedTreeCacheUnusable;
    // Refreshes the last-used marker the eviction policy reads. Best-effort:
    // a failure only makes this artifact look older than it is.
    product_cache.touchArtifact(file);
}

fn readExact(file: std.fs.File, destination: []u8) !void {
    var filled: usize = 0;
    while (filled < destination.len) {
        const count = try file.read(destination[filled..]);
        if (count == 0) return error.PreprocessedTreeCacheUnusable;
        filled += count;
    }
}

fn store(state: *Session, request: Request, layers: []const []const u8) !void {
    var stage = try prover.stage_profile.StageScope.begin(
        state.recorder,
        "preprocessed_tree_cache_store",
        "Preprocessed tree cache store",
    );
    defer stage.end();

    const payload = try payloadBytes(request);
    var written: u64 = 0;
    for (layers) |layer| written += layer.len;
    if (written != payload) return error.PreprocessedTreeCacheUnusable;

    const key = artifactKey(state.binding, request);
    product_cache.protectKey(key);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try artifactPath(&path_buffer, key);

    try std.fs.cwd().makePath(product_cache.currentConfig().directory);

    var header: [header_bytes]u8 = undefined;
    writeHeader(&header, key, request, payload);
    const trailer = try integrityDigest(state.allocator, &header, layers);

    var suffix: [16]u8 = undefined;
    std.crypto.random.bytes(&suffix);
    var temporary_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const temporary = try std.fmt.bufPrint(
        &temporary_buffer,
        "{s}.{s}.tmp",
        .{ path, std.fmt.bytesToHex(suffix, .lower) },
    );

    {
        const file = try std.fs.createFileAbsolute(temporary, .{
            .exclusive = true,
            .mode = 0o600,
        });
        errdefer std.fs.deleteFileAbsolute(temporary) catch {};
        defer file.close();
        try file.writeAll(&header);
        for (layers) |layer| try file.writeAll(layer);
        try file.writeAll(&trailer);
        try file.sync();
    }
    errdefer std.fs.deleteFileAbsolute(temporary) catch {};
    try std.fs.renameAbsolute(temporary, path);
}

// ---------------------------------------------------------------------------

test "the tree-digest seam stays inert without a configured product" {
    try std.testing.expect(!product_cache.isEnabled());
    try std.testing.expect(prover.pcs.merkle_layer_cache.armed() == null);
    arm(std.testing.allocator, .{
        .variant = .canonical_small,
        .spec_digest = @splat(1),
        .pcs_digest = @splat(2),
    }, null);
    try std.testing.expect(prover.pcs.merkle_layer_cache.armed() == null);
}

test "the key separates tree shapes, kinds and bindings" {
    const saved = product_cache.currentConfig();
    defer product_cache.configure(saved);
    product_cache.configure(.{
        .enabled = true,
        .product_digest = @splat(7),
        .directory = "/nonexistent",
    });
    const binding = Binding{
        .variant = .canonical_small,
        .spec_digest = @splat(1),
        .pcs_digest = @splat(2),
    };
    const heights = [_]u32{ 4, 4, 20, 21 };
    const request = Request{
        .hasher_tag = "H",
        .hash_bytes = 32,
        .log_size = 21,
        .column_log_sizes = &heights,
    };
    const base = artifactKey(binding, request);

    var other_hasher = request;
    other_hasher.hasher_tag = "G";
    try std.testing.expect(!std.mem.eql(u8, &base, &artifactKey(binding, other_hasher)));

    var other_domain = request;
    other_domain.log_size = 20;
    try std.testing.expect(!std.mem.eql(u8, &base, &artifactKey(binding, other_domain)));

    const other_heights = [_]u32{ 4, 5, 20, 21 };
    var other_columns = request;
    other_columns.column_log_sizes = &other_heights;
    try std.testing.expect(!std.mem.eql(u8, &base, &artifactKey(binding, other_columns)));

    var other_variant = binding;
    other_variant.variant = .canonical;
    try std.testing.expect(!std.mem.eql(u8, &base, &artifactKey(other_variant, request)));

    var other_spec = binding;
    other_spec.spec_digest = @splat(3);
    try std.testing.expect(!std.mem.eql(u8, &base, &artifactKey(other_spec, request)));
}

test "a stored layer set round-trips and any corruption falls back" {
    const allocator = std.testing.allocator;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const absolute = try directory.dir.realpathAlloc(allocator, ".");
    defer allocator.free(absolute);

    const saved = product_cache.currentConfig();
    defer product_cache.configure(saved);
    product_cache.configure(.{
        .enabled = true,
        .product_digest = @splat(9),
        .directory = absolute,
    });

    const log_size: u32 = 8;
    const heights = [_]u32{ 6, 8 };
    const request = Request{
        .hasher_tag = "test-hasher",
        .hash_bytes = 32,
        .log_size = log_size,
        .column_log_sizes = &heights,
    };
    const binding = Binding{
        .variant = .canonical_small,
        .spec_digest = @splat(1),
        .pcs_digest = @splat(2),
    };
    var state = Session{ .allocator = allocator, .binding = binding, .recorder = null };

    var owned: [log_size + 1][]u8 = undefined;
    var views: [log_size + 1][]const u8 = undefined;
    for (0..log_size + 1) |index| {
        owned[index] = try allocator.alloc(u8, (@as(usize, 1) << @intCast(index)) * 32);
        for (owned[index], 0..) |*byte, position| byte.* = @truncate(index *% 31 +% position);
        views[index] = owned[index];
    }
    defer for (owned) |layer| allocator.free(layer);

    try store(&state, request, &views);

    var loaded: [log_size + 1][]u8 = undefined;
    for (0..log_size + 1) |index| {
        loaded[index] = try allocator.alloc(u8, (@as(usize, 1) << @intCast(index)) * 32);
    }
    defer for (loaded) |layer| allocator.free(layer);
    try load(&state, request, &loaded);
    for (owned, loaded) |expected, actual| {
        try std.testing.expectEqualSlices(u8, expected, actual);
    }

    const key = artifactKey(binding, request);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try artifactPath(&path_buffer, key);

    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    defer file.close();
    try file.seekTo(header_bytes + 5);
    var byte: [1]u8 = undefined;
    try readExact(file, &byte);
    byte[0] ^= 0x01;
    try file.seekTo(header_bytes + 5);
    try file.writeAll(&byte);
    try std.testing.expectError(
        error.PreprocessedTreeCacheUnusable,
        load(&state, request, &loaded),
    );

    try file.setEndPos(header_bytes);
    try std.testing.expectError(
        error.PreprocessedTreeCacheUnusable,
        load(&state, request, &loaded),
    );

    // A different shape derives a different key and therefore never loads.
    var wrong_shape = request;
    wrong_shape.hasher_tag = "other-hasher";
    try std.testing.expectError(
        error.FileNotFound,
        load(&state, wrong_shape, &loaded),
    );
}
