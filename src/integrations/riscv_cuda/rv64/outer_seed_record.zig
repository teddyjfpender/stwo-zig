//! gn-node piece-harness recorder (STWO_RV64_M8_GN_NODE_RECORD=<dir>, default
//! off; diagnostics only, never changes a proof byte). It records the legacy
//! path's inputs and outputs of the GPU-native node job so the device seed
//! fill, statement mix and checks can be run against REAL data in the
//! piece-only harness (jobs/outer_seed_device.zig):
//!
//!   pcs-<sha8>.gnp   every legacy in-process PCS readback image
//!                    (pcs_native.zig, one call per native segment, truth
//!                    and outer node proof) with its PCS shape;
//!   node-<ord>-<sha8>.gnr  every OuterNodeJob node (outer_job_factory.zig,
//!                    STWO_RV64_M8_OUTER_JOBS=1): host seeds, host transcript
//!                    checkpoint, expected outputs, own PCS image + shape,
//!                    claims and the om31 wire bytes.
//!
//! Files are written once (exclusive create): a block's cold and warm
//! requests prove identical proofs. Word layout: outer_seed_device.zig
//! `Record` / `PcsRecord`.
const std = @import("std");

pub const node_magic: u32 = 0x31524e47; // "GNR1"
pub const pcs_magic: u32 = 0x31504e47; // "GNP1"

pub fn dir() ?[]const u8 {
    const v = std.posix.getenv("STWO_RV64_M8_GN_NODE_RECORD") orelse return null;
    return if (v.len == 0) null else v;
}

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

pub fn writeOnce(path: []const u8, name: []const u8, words: []const u32) !bool {
    var d = try std.fs.cwd().makeOpenPath(path, .{});
    defer d.close();
    const file = d.createFile(name, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return false,
        else => return err,
    };
    defer file.close();
    try file.writeAll(std.mem.sliceAsBytes(words));
    return true;
}

/// pcs_native.zig hook: one legacy PCS readback image and its shape.
/// Never fails the proof (a recorder error is printed and dropped).
pub fn pcsImage(shape: anytype, image: []const u32) void {
    const path = dir() orelse return;
    pcsImageInner(path, shape, image) catch |err| std.debug.print("GN_NODE_RECORD pcs error={s}\n", .{@errorName(err)});
}
fn pcsImageInner(path: []const u8, shape: anytype, image: []const u32) !void {
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
    if (try writeOnce(path, name, out.items)) std.debug.print("GN_NODE_RECORD pcs trees={d} image_words={d} file={s}\n", .{ shape.trees.len, image.len, name });
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
    fn put(e: Entry) !void {
        mutex.lock();
        defer mutex.unlock();
        const a = std.heap.c_allocator;
        for (entries.items, 0..) |*x, i| if (std.mem.eql(u32, &x.key, &e.key) and x.node == e.node) {
            x.deinit();
            entries.items[i] = e;
            return;
        };
        if (entries.items.len == capacity) {
            entries.items[0].deinit();
            _ = entries.orderedRemove(0);
        }
        try entries.append(a, e);
    }
    pub fn putPcs(shape: anytype, image: []const u32) void {
        putPcsInner(shape, image) catch |err| std.debug.print("GN_NODE_LIVE pcs error={s}\n", .{@errorName(err)});
    }
    fn putPcsInner(shape: anytype, image: []const u32) !void {
        if (image.len < main_root_at + 8) return error.GnNodeImageTooShort;
        const a = std.heap.c_allocator;
        var sw: std.ArrayListUnmanaged(u32) = .empty;
        errdefer sw.deinit(a);
        try appendShape(a, &sw, shape);
        const img = try a.dupe(u32, image);
        errdefer a.free(img);
        try put(.{ .key = image[main_root_at..][0..8].*, .node = false, .shape = try sw.toOwnedSlice(a), .image = img, .wire = try a.alloc(u8, 0) });
    }
    pub fn putNode(shape: anytype, image: []const u32, wire: []const u8, identity: [8]u32, fixed_root: [8]u32, n_outputs: u32) !void {
        if (image.len < main_root_at + 8) return error.GnNodeImageTooShort;
        const a = std.heap.c_allocator;
        var sw: std.ArrayListUnmanaged(u32) = .empty;
        errdefer sw.deinit(a);
        try appendShape(a, &sw, shape);
        const img = try a.dupe(u32, image);
        errdefer a.free(img);
        const w = try a.dupe(u8, wire);
        errdefer a.free(w);
        try put(.{ .key = image[main_root_at..][0..8].*, .node = true, .shape = try sw.toOwnedSlice(a), .image = img, .wire = w, .identity = identity, .fixed_root = fixed_root, .n_outputs = n_outputs });
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
                try out.append(a, .{ .at = i - 16, .entry = .{ .key = e.key, .node = e.node, .shape = try a.dupe(u32, e.shape), .image = try a.dupe(u32, e.image), .wire = try a.dupe(u8, e.wire), .identity = e.identity, .fixed_root = e.fixed_root, .n_outputs = e.n_outputs } });
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
