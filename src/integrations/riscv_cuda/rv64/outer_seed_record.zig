//! gn-node piece-harness recorder (request-owned common artifact root, default
//! off; diagnostics only, never changes a proof byte). It records the legacy
//! path's inputs and outputs of the GPU-native node job so the device seed
//! fill, statement mix and checks can be run against REAL data in the
//! piece-only harness (jobs/outer_seed_device.zig):
//!
//!   pcs-<sha8>.gnp   every legacy in-process PCS readback image
//!                    (pcs_native.zig, one call per native segment, truth
//!                    and outer node proof) with its PCS shape;
//!   node-<ord>-<sha8>.gnr  every OuterNodeJob node (outer_job_factory.zig,
//!                    GPU-native class install): host seeds, host transcript
//!                    checkpoint, expected outputs, own PCS image + shape,
//!                    claims and the om31 wire bytes.
//!
//! Files are written once (exclusive create): a block's cold and warm
//! requests prove identical proofs. Word layout: outer_seed_device.zig
//! `Record` / `PcsRecord`.
const std = @import("std");

pub const node_magic: u32 = 0x31524e47; // "GNR1"
pub const pcs_magic: u32 = 0x31504e47; // "GNP1"

/// Appends the PCS shape words: config (6), degree_log, n_trees, then per
/// tree: n_columns, coefficient_logs, sorted_to_original, sample_counts.
pub fn appendShape(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u32), shape: anytype) !void {
    const c = shape.config;
    try out.appendSlice(a, &.{ c.pow_bits, c.fri_config.log_blowup_factor, c.fri_config.log_last_layer_degree_bound, @intCast(c.fri_config.n_queries), c.fri_config.fold_step, c.lifting_log_size orelse 0xffff_ffff, shape.degree_log, @intCast(shape.trees.len) });
    for (shape.trees) |t| {
        try out.append(a, @intCast(t.coefficient_logs.len));
        try out.appendSlice(a, t.coefficient_logs);
        try out.appendSlice(a, t.sorted_to_original);
        try out.appendSlice(a, t.sample_counts);
    }
}

/// pcs_native.zig hook: one legacy PCS readback image and its shape.
/// Never fails the proof (a recorder error is printed and dropped).
pub fn pcsImage(slot: *const @import("recording_dataset.zig").Slot, shape: anytype, image: []const u32) void {
    var lease = slot.borrowDiagnostic() orelse return;
    defer lease.release() catch unreachable;
    pcsImageInner(&lease, shape, image) catch |err| {
        lease.owner.fail(err);
        std.debug.print("GN_NODE_RECORD pcs error={s}\n", .{@errorName(err)});
    };
}
fn pcsImageInner(lease: *const @import("recording_dataset.zig").Borrow, shape: anytype, image: []const u32) !void {
    const a = std.heap.c_allocator;
    var out: std.ArrayListUnmanaged(u32) = .empty;
    defer out.deinit(a);
    try out.appendSlice(a, &.{ pcs_magic, 1 });
    try appendShape(a, &out, shape);
    try out.append(a, @intCast(image.len));
    try out.appendSlice(a, image);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(image), &digest, .{});
    var name_buf: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "pcs-{x}.gnp", .{digest[0..8].*});
    if (try lease.owner.write(.nodes, name, std.mem.sliceAsBytes(out.items))) std.debug.print("GN_NODE_RECORD pcs trees={d} image_words={d} file={s}\n", .{ shape.trees.len, image.len, name });
}

/// STWO_RV64_M8_GN_NODE=check: the in-process registry of child seed
/// sources for the in-service GPU-native node check (outer_job_factory.zig
/// GnCheck). Every legacy PCS image (native segments, truths) and every
/// proved outer node (its wire bytes + PCS image) is kept, keyed by its MAIN
/// (tree 1) root, until a parent consumes it. Stands in for the request
/// slab's encoded regions, which the GPU-native producers fill on device.
pub fn liveSelected() !bool {
    const v = std.posix.getenv("STWO_RV64_M8_GN_NODE") orelse return false;
    if (std.mem.eql(u8, v, "0")) return false;
    if (std.mem.eql(u8, v, "check") or std.mem.eql(u8, v, "job")) return true;
    return error.InvalidGnNodeSelection;
}
/// STWO_RV64_M8_GN_NODE=job: check mode, plus every node is proved a second
/// time through the production GPU-native node job (outer_device.NodeJob over
/// its NodeClasses template) and its device-encoded bytes must equal the
/// published host bytes.
pub fn jobSelected() bool {
    const v = std.posix.getenv("STWO_RV64_M8_GN_NODE") orelse return false;
    return std.mem.eql(u8, v, "job");
}
pub const Live = struct {
    pub const Entry = struct {
        key: [8]u32,
        node: bool,
        shape: []u32,
        image: []u32,
        wire: []u8,
        identity: [8]u32 = @splat(0),
        fixed_root: [8]u32 = @splat(0),
        n_outputs: u32 = 0,
        fn deinit(self: *Entry) void {
            const a = std.heap.c_allocator;
            a.free(self.shape);
            a.free(self.image);
            a.free(self.wire);
        }
    };
    /// MAIN root offset in a PCS readback image (header 14, status 1, state 16, root 0).
    pub const main_root_at: usize = 14 + 1 + 16 + 8;
    pub const capacity = 128;
    var mutex: std.Thread.Mutex = .{};
    var entries: std.ArrayListUnmanaged(Entry) = .empty;
    var install_limit: ?usize = null;

    pub const Install = struct {
        active: bool = true,
        pub fn deinit(self: *Install) void {
            if (!self.active) return;
            mutex.lock();
            defer mutex.unlock();
            clear();
            install_limit = null;
            self.active = false;
        }
    };
    fn clear() void {
        for (entries.items) |*e| e.deinit();
        entries.deinit(std.heap.c_allocator);
        entries = .empty;
    }
    pub fn beginInstall(limit: usize) !Install {
        mutex.lock();
        defer mutex.unlock();
        if (install_limit != null) return error.GnNodeInstallBusy;
        if (limit == 0) return error.GnNodeSeedCapacity;
        clear();
        install_limit = limit;
        return .{};
    }
    fn put(e: Entry) !void {
        mutex.lock();
        defer mutex.unlock();
        const a = std.heap.c_allocator;
        for (entries.items, 0..) |*x, i| if (std.mem.eql(u32, &x.key, &e.key) and x.node == e.node) {
            x.deinit();
            entries.items[i] = e;
            return;
        };
        if (entries.items.len == (install_limit orelse capacity)) {
            if (install_limit != null) return error.GnNodeSeedCapacity;
            entries.items[0].deinit();
            _ = entries.orderedRemove(0);
        }
        try entries.append(a, e);
    }
    pub fn putPcs(shape: anytype, image: []const u32) !void {
        store(shape, image, null, @splat(0), @splat(0), 0) catch |err| {
            mutex.lock();
            defer mutex.unlock();
            if (install_limit != null) return err;
            std.debug.print("GN_NODE_LIVE pcs error={s}\n", .{@errorName(err)});
        };
    }
    pub fn putNode(shape: anytype, image: []const u32, wire: []const u8, identity: [8]u32, fixed_root: [8]u32, n_outputs: u32) !void {
        try store(shape, image, wire, identity, fixed_root, n_outputs);
    }
    fn store(shape: anytype, image: []const u32, wire: ?[]const u8, identity: [8]u32, fixed_root: [8]u32, n_outputs: u32) !void {
        if (image.len < main_root_at + 8) return error.GnNodeImageTooShort;
        const a = std.heap.c_allocator;
        var sw: std.ArrayListUnmanaged(u32) = .empty;
        defer sw.deinit(a);
        try appendShape(a, &sw, shape);
        const words = try sw.toOwnedSlice(a);
        errdefer a.free(words);
        const img = try a.dupe(u32, image);
        errdefer a.free(img);
        const w = try a.dupe(u8, wire orelse &.{});
        errdefer a.free(w);
        try put(.{ .key = image[main_root_at..][0..8].*, .node = wire != null, .shape = words, .image = img, .wire = w, .identity = identity, .fixed_root = fixed_root, .n_outputs = n_outputs });
    }
    /// A copy of an entry (caller frees with `a` via Found.deinit).
    pub const Found = struct {
        at: usize, // seed index of the child's proof start (its tree-0 root)
        entry: Entry,
        pub fn deinit(self: *Found, a: std.mem.Allocator) void {
            a.free(self.entry.shape);
            a.free(self.entry.image);
            a.free(self.entry.wire);
        }
    };
    /// Children of a node from its host seed records (5 words each): every
    /// registered source (of kind `node`) whose MAIN root appears as the 16
    /// half-word seeds following a tree-0 root, in seed order. Check mode
    /// only (production gets the children from the driver's DAG).
    pub fn find(a: std.mem.Allocator, seeds: []const u32, node: bool, out: *std.ArrayListUnmanaged(Found)) !void {
        mutex.lock();
        defer mutex.unlock();
        const n = seeds.len / 5;
        for (entries.items) |e| {
            if (e.node != node) continue;
            var i: usize = 16;
            scan: while (i + 16 <= n) : (i += 1) {
                for (0..8) |w| {
                    if (seeds[5 * (i + 2 * w) + 1] != (e.key[w] & 0xffff) or seeds[5 * (i + 2 * w + 1) + 1] != (e.key[w] >> 16)) continue :scan;
                }
                var copy = e;
                copy.shape = try a.dupe(u32, e.shape);
                errdefer a.free(copy.shape);
                copy.image = try a.dupe(u32, e.image);
                errdefer a.free(copy.image);
                copy.wire = try a.dupe(u8, e.wire);
                errdefer a.free(copy.wire);
                try out.append(a, .{ .at = i - 16, .entry = copy });
                break;
            }
        }
        std.mem.sort(Found, out.items, {}, struct {
            fn less(_: void, x: Found, y: Found) bool {
                return x.at < y.at;
            }
        }.less);
    }
};

test "recursive discovery holds late leaf roots until its installation ends" {
    const a = std.testing.allocator;
    var lease = try Live.beginInstall(132);
    defer lease.deinit();
    try std.testing.expectError(error.GnNodeInstallBusy, Live.beginInstall(132));
    for (0..132) |i| try Live.put(.{
        .key = @splat(@intCast(i + 42)),
        .node = i % 2 != 0,
        .image = &.{},
        .shape = &.{},
        .wire = &.{},
    });
    var replacement = Live.entries.items[0];
    replacement.n_outputs = 17;
    try Live.put(replacement);
    var excess = replacement;
    excess.key = @splat(1001);
    try std.testing.expectError(error.GnNodeSeedCapacity, Live.put(excess));
    var seeds = [_]u32{0} ** (5 * 32);
    for (0..8) |i| seeds[5 * (16 + 2 * i) + 1] = 42;
    var found: std.ArrayListUnmanaged(Live.Found) = .empty;
    defer {
        for (found.items) |*f| f.deinit(a);
        found.deinit(a);
    }
    try Live.find(a, &seeds, true, &found);
    try std.testing.expectEqual(0, found.items.len);
    try Live.find(a, &seeds, false, &found);
    try std.testing.expectEqual(1, found.items.len);
    try std.testing.expectEqual(17, found.items[0].entry.n_outputs);
    lease.deinit();
    var next = try Live.beginInstall(1);
    defer next.deinit();
    try std.testing.expectEqual(0, Live.entries.items.len);
}
