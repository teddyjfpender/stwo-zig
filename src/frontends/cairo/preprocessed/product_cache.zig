//! Protocol-identity-bound cache for the profile-invariant preprocessed product.
//!
//! The Cairo preprocessed data this module caches is a pure function of the
//! *protocol identity*: the proving profile's preprocessed variant, the PCS
//! configuration, the structural preprocessed column specification, and the
//! implementation revision that produced them. No program, no input and no
//! user-supplied string ever enters the key. Callers hand over an opaque
//! product-identity digest (the product's own authenticated identity document
//! digest) and this module derives the storage key structurally from it.
//!
//! Soundness. A cache hit substitutes bytes for a recomputation whose result
//! then flows into exactly the same commitment pipeline. Any deviation —
//! tampering, truncation, a stale artifact, a bit flip — changes the
//! preprocessed commitment, which changes the transcript, which makes the proof
//! fail its own `--verify` replay and the official verifier. The cache can
//! therefore only ever cost availability, never soundness. Every load failure
//! mode is handled by silently falling back to computing the data.

const std = @import("std");
const prover = @import("stwo_prover_engine");
const pedersen_table = @import("pedersen_table.zig");
const trace = @import("trace.zig");

const stark_curve = @import("../witness/deductions/stark_curve.zig");

const magic = "STWOZPP1";
const format_version: u32 = 1;
const kind_pedersen_points: u32 = 1;
const point_bytes: u32 = 64;
const header_bytes: usize = 64;
const digest_bytes: usize = 32;
/// Bounds the cache: nothing larger is ever written or read.
const max_artifact_bytes: usize = 1024 * 1024 * 1024;

/// Default total-size budget for the cache directory.
///
/// One `(implementation commit x profile x variant)` generation is ~136 MB (the
/// 2 MB Pedersen table plus the ~134 MB tree-digest artifact), so 2 GiB holds
/// roughly fifteen generations before anything is reclaimed. A developer
/// iterating on a dirty tree mints a new key per build; without a budget the
/// directory grows without bound.
pub const default_budget_bytes: u64 = 2 * 1024 * 1024 * 1024;

/// Opaque protocol identity supplied by the product.
///
/// `product_digest` must be a structural digest of the product's own
/// authenticated identity document (protocol manifest digest, identity digest,
/// implementation revision and dirty content digest, target, optimize mode and
/// upstream revisions). It must never be derived from a program or an input.
pub const Config = struct {
    enabled: bool = false,
    product_digest: [32]u8 = @splat(0),
    /// Absolute directory that holds the cache. Must outlive the process use.
    directory: []const u8 = "",
    /// Total-size budget for the whole cache directory, enforced after every
    /// successful store. Zero means unbounded: no eviction ever runs.
    budget_bytes: u64 = default_budget_bytes,
};

var config: Config = .{};

pub fn configure(value: Config) void {
    config = value;
    resetProtectedKeys();
    resetAccounting();
}

pub fn currentConfig() Config {
    return config;
}

pub fn isEnabled() bool {
    return config.enabled and config.directory.len != 0;
}

// ---------------------------------------------------------------------------
// Per-run accounting
//
// Ops surface only. None of this reaches the key, the artifact bytes or the
// proof; it exists so a machine-readable run report can say what the cache did.
// ---------------------------------------------------------------------------

pub const Accounting = struct {
    enabled: bool = false,
    budget_bytes: u64 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    stores: u64 = 0,
    evictions: u64 = 0,
    loaded_bytes: u64 = 0,
    stored_bytes: u64 = 0,
    evicted_bytes: u64 = 0,
    /// Total size of the cache directory observed at the last enforcement pass.
    directory_bytes: u64 = 0,
    /// Wall time spent in eviction passes, store-time cost included.
    eviction_ns: u64 = 0,
};

var accounting_mutex: std.Thread.Mutex = .{};
var accounting: Accounting = .{};

/// Snapshot of what the cache did this run. `enabled` and `budget_bytes` are
/// read from the live configuration so a disabled cache reports honestly.
pub fn accountingSnapshot() Accounting {
    accounting_mutex.lock();
    defer accounting_mutex.unlock();
    var snapshot = accounting;
    snapshot.enabled = isEnabled();
    snapshot.budget_bytes = if (isEnabled()) config.budget_bytes else 0;
    return snapshot;
}

pub fn resetAccounting() void {
    accounting_mutex.lock();
    defer accounting_mutex.unlock();
    accounting = .{};
}

pub fn recordHit(bytes: u64) void {
    accounting_mutex.lock();
    defer accounting_mutex.unlock();
    accounting.hits += 1;
    accounting.loaded_bytes += bytes;
}

pub fn recordMiss() void {
    accounting_mutex.lock();
    defer accounting_mutex.unlock();
    accounting.misses += 1;
}

pub fn recordStore(bytes: u64) void {
    accounting_mutex.lock();
    defer accounting_mutex.unlock();
    accounting.stores += 1;
    accounting.stored_bytes += bytes;
}

// ---------------------------------------------------------------------------
// Current-identity protection
//
// Eviction must never reclaim an artifact this run needs. The set of keys the
// current product identity can address is not enumerable from the identity
// digest alone (the shape of the tree artifact depends on the committed column
// heights), so instead every key this process *derives* is registered here.
// That covers the just-written artifact and every artifact the run has already
// loaded, which is exactly the current product identity's working set.
// ---------------------------------------------------------------------------

const max_protected_keys: usize = 16;
var protected_mutex: std.Thread.Mutex = .{};
var protected_keys: [max_protected_keys][64]u8 = undefined;
var protected_len: usize = 0;

fn resetProtectedKeys() void {
    protected_mutex.lock();
    defer protected_mutex.unlock();
    protected_len = 0;
}

/// Registers a key the current run addresses. Best-effort: if the registry is
/// full the oldest entry is kept and the new one is dropped, which can only
/// cost availability (a re-store), never correctness.
pub fn protectKey(key: [32]u8) void {
    const hex = std.fmt.bytesToHex(key, .lower);
    protected_mutex.lock();
    defer protected_mutex.unlock();
    for (protected_keys[0..protected_len]) |existing| {
        if (std.mem.eql(u8, &existing, &hex)) return;
    }
    if (protected_len == max_protected_keys) return;
    protected_keys[protected_len] = hex;
    protected_len += 1;
}

/// True when `name` is `<protected-key-hex>.<extension>`.
fn nameIsProtected(name: []const u8) bool {
    if (name.len < 64) return false;
    protected_mutex.lock();
    defer protected_mutex.unlock();
    for (protected_keys[0..protected_len]) |existing| {
        if (std.mem.eql(u8, &existing, name[0..64])) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Last-used marker and least-recently-used eviction
//
// The marker is the artifact file's own mtime, refreshed on every verified
// load. atime is unreliable (`relatime`, `noatime`, and macOS coalescing all
// defeat it) and a separate sidecar file would double the entry count, need its
// own orphan reclamation, and add a corruptible surface. An in-band mtime has
// none of those problems: a store sets it (temp-fsync-rename), a verified load
// refreshes it, and there is no state that can disagree with the artifact
// because there is no second file. The cost is that mtime no longer means
// "written at", which nothing in this cache depends on.
//
// Concurrency. Eviction only ever unlinks whole artifact files. A reader that
// already opened its file is unaffected by the unlink (POSIX keeps the inode
// alive for the open descriptor); a reader that had not opened it yet sees
// `FileNotFound` and falls back to computing, which is the same fail-open path
// every other integrity failure takes. No partial artifact is ever observable,
// because no artifact is ever mutated in place.
// ---------------------------------------------------------------------------

const artifact_extensions = [_][]const u8{ ".preprocessed", ".preprocessed-tree" };
const temporary_extension = ".tmp";
/// A temporary older than this is a crashed writer's leftover rather than an
/// in-flight write, and may be reclaimed. In-flight temporaries are never
/// touched, so a concurrent store cannot be broken by a concurrent eviction.
const stale_temporary_ns: i128 = 60 * 60 * std.time.ns_per_s;
/// Bounds the eviction scan so a pathological directory cannot make a store
/// pass unbounded.
const max_scanned_entries: usize = 8192;

/// Refreshes the last-used marker. Best-effort by construction.
pub fn touchArtifact(file: std.fs.File) void {
    const now = std.time.nanoTimestamp();
    file.updateTimes(now, now) catch {};
}

fn hasArtifactExtension(name: []const u8) bool {
    for (artifact_extensions) |extension| {
        if (std.mem.endsWith(u8, name, extension)) return true;
    }
    return false;
}

const Candidate = struct {
    name: []const u8,
    size: u64,
    mtime: i128,
    stale_temporary: bool,

    /// Stale temporaries go first — they are garbage, not cache value. Real
    /// artifacts then go least-recently-used first.
    fn lessUseful(_: void, left: Candidate, right: Candidate) bool {
        if (left.stale_temporary != right.stale_temporary)
            return left.stale_temporary;
        return left.mtime < right.mtime;
    }
};

/// Brings the cache directory back within budget by unlinking the
/// least-recently-used artifacts. Never unlinks an artifact registered by
/// `protectKey` (which includes the artifact the caller just wrote), never
/// unlinks a file this cache does not own, and never fails the caller.
pub fn enforceBudget(allocator: std.mem.Allocator) void {
    if (!isEnabled() or config.budget_bytes == 0) return;
    const started = std.time.Instant.now() catch return;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    var directory = std.fs.openDirAbsolute(
        config.directory,
        .{ .iterate = true },
    ) catch return;
    defer directory.close();

    var candidates = std.ArrayList(Candidate).empty;
    var total: u64 = 0;
    var scanned: usize = 0;
    const now = std.time.nanoTimestamp();
    var iterator = directory.iterate();
    while (iterator.next() catch null) |entry| {
        if (scanned >= max_scanned_entries) break;
        scanned += 1;
        if (entry.kind != .file) continue;
        const stat = directory.statFile(entry.name) catch continue;
        total += stat.size;
        const temporary = std.mem.endsWith(u8, entry.name, temporary_extension);
        const stale = temporary and now -| stat.mtime > stale_temporary_ns;
        if (!stale) {
            if (temporary) continue;
            if (!hasArtifactExtension(entry.name)) continue;
            if (nameIsProtected(entry.name)) continue;
        }
        const name = scratch.dupe(u8, entry.name) catch continue;
        candidates.append(scratch, .{
            .name = name,
            .size = stat.size,
            .mtime = stat.mtime,
            .stale_temporary = stale,
        }) catch continue;
    }

    var evictions: u64 = 0;
    var evicted_bytes: u64 = 0;
    if (total > config.budget_bytes) {
        std.mem.sort(Candidate, candidates.items, {}, Candidate.lessUseful);
        for (candidates.items) |candidate| {
            if (total <= config.budget_bytes) break;
            directory.deleteFile(candidate.name) catch continue;
            total -|= candidate.size;
            evictions += 1;
            evicted_bytes += candidate.size;
        }
    }

    const elapsed = (std.time.Instant.now() catch started).since(started);
    accounting_mutex.lock();
    defer accounting_mutex.unlock();
    accounting.evictions += evictions;
    accounting.evicted_bytes += evicted_bytes;
    accounting.directory_bytes = total;
    accounting.eviction_ns += elapsed;
}

/// Structural binding of everything the preprocessed product depends on.
pub const Binding = struct {
    variant: trace.Variant,
    spec_digest: [32]u8,
    pcs_digest: [32]u8,
};

/// Digest of the preprocessed column specification: identities and log sizes.
pub fn specDigest(spec: trace.Spec) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("cairo-preprocessed-spec/v1");
    updateU32(&hasher, @intCast(spec.columns.len));
    for (spec.columns) |column| {
        updateU32(&hasher, @intCast(column.identity.len));
        hasher.update(column.identity);
        updateU32(&hasher, column.log_size);
    }
    return hasher.finalResult();
}

/// Digest of the PCS parameters the preprocessed commitment is made under.
pub fn pcsDigest(pcs: anytype) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("cairo-pcs-config/v1");
    updateU32(&hasher, pcs.pow_bits);
    updateU32(&hasher, pcs.fri_config.log_blowup_factor);
    updateU32(&hasher, pcs.fri_config.log_last_layer_degree_bound);
    updateU32(&hasher, @intCast(pcs.fri_config.n_queries));
    updateU32(&hasher, pcs.fri_config.fold_step);
    updateU32(&hasher, pcs.lifting_log_size orelse 0xffff_ffff);
    return hasher.finalResult();
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

fn artifactKey(
    binding: Binding,
    window: pedersen_table.Window,
    rows: u64,
) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo-zig/cairo-preprocessed-product/v1\x00");
    hasher.update(&config.product_digest);
    hasher.update("pedersen-affine-points\x00");
    hasher.update(@tagName(binding.variant));
    hasher.update("\x00");
    hasher.update(&binding.spec_digest);
    hasher.update(&binding.pcs_digest);
    updateU32(&hasher, format_version);
    updateU32(&hasher, kind_pedersen_points);
    updateU32(&hasher, window.bits());
    updateU64(&hasher, rows);
    updateU32(&hasher, point_bytes);
    return hasher.finalResult();
}

/// Returns the Pedersen preprocessed table, loading it from the authenticated
/// cache when one is present and computing (then storing) it otherwise.
///
/// Every failure path falls back to computing. A caller cannot observe whether
/// a hit occurred except through the stage profile and the wall clock.
pub fn pedersenTable(
    allocator: std.mem.Allocator,
    window: pedersen_table.Window,
    binding: Binding,
    recorder: ?*prover.stage_profile.Recorder,
) !pedersen_table.Table {
    if (!isEnabled()) return pedersen_table.Table.init(allocator, window);

    const rows: u64 = window.rowCount();
    const key = artifactKey(binding, window, rows);
    // Registered before anything touches the filesystem: this run's artifacts
    // are protected from its own and any concurrent run's eviction pass.
    protectKey(key);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = artifactPath(&path_buffer, key) catch
        return pedersen_table.Table.init(allocator, window);

    const artifact_bytes = @as(u64, header_bytes) +
        rows * @as(u64, point_bytes) + @as(u64, digest_bytes);
    if (loadPedersen(allocator, path, key, window, rows, recorder)) |table| {
        recordHit(artifact_bytes);
        return table;
    } else |_| {}
    recordMiss();

    var table = try pedersen_table.Table.init(allocator, window);
    errdefer table.deinit();
    if (storePedersen(allocator, path, key, window, table.points, recorder)) {
        recordStore(artifact_bytes);
        enforceBudget(allocator);
    } else |_| {}
    return table;
}

fn artifactPath(buffer: []u8, key: [32]u8) ![]const u8 {
    const hex = std.fmt.bytesToHex(key, .lower);
    return std.fmt.bufPrint(
        buffer,
        "{s}/{s}.preprocessed",
        .{ config.directory, hex },
    );
}

fn writeHeader(
    header: *[header_bytes]u8,
    key: [32]u8,
    window: pedersen_table.Window,
    rows: u64,
) void {
    @memset(header, 0);
    @memcpy(header[0..magic.len], magic);
    std.mem.writeInt(u32, header[8..12], format_version, .little);
    std.mem.writeInt(u32, header[12..16], kind_pedersen_points, .little);
    @memcpy(header[16..48], &key);
    std.mem.writeInt(u32, header[48..52], window.bits(), .little);
    std.mem.writeInt(u64, header[52..60], rows, .little);
    std.mem.writeInt(u32, header[60..64], point_bytes, .little);
}

fn loadPedersen(
    allocator: std.mem.Allocator,
    path: []const u8,
    key: [32]u8,
    window: pedersen_table.Window,
    rows: u64,
    recorder: ?*prover.stage_profile.Recorder,
) !pedersen_table.Table {
    var stage = try prover.stage_profile.StageScope.begin(
        recorder,
        "preprocessed_table_cache_load",
        "Preprocessed table cache load",
    );
    defer stage.end();

    const payload_bytes = std.math.mul(u64, rows, point_bytes) catch
        return error.PreprocessedCacheUnusable;
    const expected_bytes = header_bytes + payload_bytes + digest_bytes;
    if (expected_bytes > max_artifact_bytes) return error.PreprocessedCacheUnusable;

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size != expected_bytes)
        return error.PreprocessedCacheUnusable;

    var expected_header: [header_bytes]u8 = undefined;
    writeHeader(&expected_header, key, window, rows);
    var actual_header: [header_bytes]u8 = undefined;
    try readExact(file, &actual_header);
    if (!std.mem.eql(u8, &expected_header, &actual_header))
        return error.PreprocessedCacheUnusable;

    const payload = try allocator.alloc(u8, @intCast(payload_bytes));
    defer allocator.free(payload);
    try readExact(file, payload);
    var trailer: [digest_bytes]u8 = undefined;
    try readExact(file, &trailer);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&actual_header);
    hasher.update(payload);
    const actual_digest = hasher.finalResult();
    if (!std.crypto.timing_safe.eql([digest_bytes]u8, actual_digest, trailer))
        return error.PreprocessedCacheUnusable;
    touchArtifact(file);

    const points = try allocator.alloc(stark_curve.AffinePoint, @intCast(rows));
    errdefer allocator.free(points);
    for (points, 0..) |*point, index| {
        const base = index * point_bytes;
        point.* = .{
            .x = std.mem.readInt(u256, payload[base..][0..32], .little),
            .y = std.mem.readInt(u256, payload[base + 32 ..][0..32], .little),
        };
    }
    return .{ .allocator = allocator, .window = window, .points = points };
}

fn readExact(file: std.fs.File, destination: []u8) !void {
    var filled: usize = 0;
    while (filled < destination.len) {
        const count = try file.read(destination[filled..]);
        if (count == 0) return error.PreprocessedCacheUnusable;
        filled += count;
    }
}

fn storePedersen(
    allocator: std.mem.Allocator,
    path: []const u8,
    key: [32]u8,
    window: pedersen_table.Window,
    points: []const stark_curve.AffinePoint,
    recorder: ?*prover.stage_profile.Recorder,
) !void {
    var stage = try prover.stage_profile.StageScope.begin(
        recorder,
        "preprocessed_table_cache_store",
        "Preprocessed table cache store",
    );
    defer stage.end();

    const payload_bytes = std.math.mul(u64, points.len, point_bytes) catch
        return error.PreprocessedCacheUnusable;
    if (header_bytes + payload_bytes + digest_bytes > max_artifact_bytes)
        return error.PreprocessedCacheUnusable;

    try std.fs.cwd().makePath(config.directory);

    var header: [header_bytes]u8 = undefined;
    writeHeader(&header, key, window, points.len);
    const payload = try allocator.alloc(u8, @intCast(payload_bytes));
    defer allocator.free(payload);
    for (points, 0..) |point, index| {
        const base = index * point_bytes;
        std.mem.writeInt(u256, payload[base..][0..32], point.x, .little);
        std.mem.writeInt(u256, payload[base + 32 ..][0..32], point.y, .little);
    }
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&header);
    hasher.update(payload);
    const trailer = hasher.finalResult();

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
        try file.writeAll(payload);
        try file.writeAll(&trailer);
        try file.sync();
    }
    errdefer std.fs.deleteFileAbsolute(temporary) catch {};
    try std.fs.renameAbsolute(temporary, path);
}

test "preprocessed cache is inert until a product configures it" {
    try std.testing.expect(!isEnabled());
}

test "protocol identity keys separate variants, windows and revisions" {
    const saved = config;
    defer configure(saved);
    configure(.{
        .enabled = true,
        .product_digest = @splat(7),
        .directory = "/nonexistent",
    });
    const binding = Binding{
        .variant = .canonical_small,
        .spec_digest = @splat(1),
        .pcs_digest = @splat(2),
    };
    const base = artifactKey(binding, .small, 1 << 15);

    var other_variant = binding;
    other_variant.variant = .canonical;
    try std.testing.expect(!std.mem.eql(
        u8,
        &base,
        &artifactKey(other_variant, .small, 1 << 15),
    ));

    var other_spec = binding;
    other_spec.spec_digest = @splat(3);
    try std.testing.expect(!std.mem.eql(
        u8,
        &base,
        &artifactKey(other_spec, .small, 1 << 15),
    ));

    var other_pcs = binding;
    other_pcs.pcs_digest = @splat(4);
    try std.testing.expect(!std.mem.eql(
        u8,
        &base,
        &artifactKey(other_pcs, .small, 1 << 15),
    ));

    try std.testing.expect(!std.mem.eql(
        u8,
        &base,
        &artifactKey(binding, .standard, 1 << 23),
    ));

    configure(.{
        .enabled = true,
        .product_digest = @splat(8),
        .directory = "/nonexistent",
    });
    try std.testing.expect(!std.mem.eql(
        u8,
        &base,
        &artifactKey(binding, .small, 1 << 15),
    ));
}

test "spec digest distinguishes preprocessed variants" {
    var small = try trace.Spec.init(std.testing.allocator, .canonical_small);
    defer small.deinit();
    var canonical = try trace.Spec.init(std.testing.allocator, .canonical);
    defer canonical.deinit();
    try std.testing.expect(!std.mem.eql(
        u8,
        &specDigest(small),
        &specDigest(canonical),
    ));
}

test "a stored artifact round-trips and any corruption falls back" {
    const allocator = std.testing.allocator;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const absolute = try directory.dir.realpathAlloc(allocator, ".");
    defer allocator.free(absolute);

    const saved = config;
    defer configure(saved);
    configure(.{
        .enabled = true,
        .product_digest = @splat(9),
        .directory = absolute,
    });

    const binding = Binding{
        .variant = .canonical_small,
        .spec_digest = @splat(1),
        .pcs_digest = @splat(2),
    };
    const window = pedersen_table.Window.small;
    const rows: u64 = window.rowCount();
    const key = artifactKey(binding, window, rows);
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try artifactPath(&path_buffer, key);

    var computed = try pedersen_table.Table.init(allocator, window);
    defer computed.deinit();
    try storePedersen(allocator, path, key, window, computed.points, null);

    var loaded = try loadPedersen(allocator, path, key, window, rows, null);
    defer loaded.deinit();
    try std.testing.expectEqualSlices(
        stark_curve.AffinePoint,
        computed.points,
        loaded.points,
    );

    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    defer file.close();
    try file.seekTo(header_bytes + 3);
    var byte: [1]u8 = undefined;
    try readExact(file, &byte);
    byte[0] ^= 0x01;
    try file.seekTo(header_bytes + 3);
    try file.writeAll(&byte);
    try std.testing.expectError(
        error.PreprocessedCacheUnusable,
        loadPedersen(allocator, path, key, window, rows, null),
    );

    try file.setEndPos(header_bytes);
    try std.testing.expectError(
        error.PreprocessedCacheUnusable,
        loadPedersen(allocator, path, key, window, rows, null),
    );

    // The public entry point never surfaces a cache failure to the caller.
    var recovered = try pedersenTable(allocator, window, binding, null);
    defer recovered.deinit();
    try std.testing.expectEqualSlices(
        stark_curve.AffinePoint,
        computed.points,
        recovered.points,
    );
}
