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
