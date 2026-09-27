//! Device-only ingress into the original PCS owner. Aligned arenas retain
//! their allocation contract after becoming polynomial coefficient storage.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const runtime = @import("../runtime.zig");
const shared = @import("../shared_runtime.zig");
const combined = @import("combined_commit.zig");
const M = core.fields.m31.M31;
pub const ALIGNMENT: std.mem.Alignment = .fromByteUnits(16 * 1024);
extern fn stwo_zig_secure_columns_blit(*anyopaque, *anyopaque, usize, [*]M, usize, *f64) u32;
pub const Role = enum { lane_fixed, lane_main, lane_interaction, range_fixed, range_main, range_interaction };
pub fn count(role: Role) usize {
    return switch (role) {
        .lane_fixed => 24,
        .lane_main => 54,
        .lane_interaction => 92,
        .range_fixed, .range_main => 1,
        .range_interaction => 8,
    };
}
pub fn bytes(role: Role, log: u32) !usize {
    // Every column is page-sized. Smaller domains need an explicitly owned
    // padded transport ABI; never round a borrowed extent beyond its owner.
    if (log < 12 or log > 24 or ((role == .range_fixed or role == .range_main or role == .range_interaction) and log != 16)) return error.InvalidSecureResidentColumnGeometry;
    return std.math.mul(usize, try std.math.mul(usize, @as(usize, 1) << @intCast(log), count(role)), @sizeOf(M));
}
/// Retained coefficients/evaluations plus all lifted Merkle layers and
/// column-stride padding. FFT/twiddle workspace is added separately.
pub fn retainedBytes(role: Role, log: u32) !usize {
    _ = try bytes(role, log);
    const rows = @as(usize, 1) << @intCast(log);
    return std.math.add(usize, try std.math.mul(usize, rows, 12 * count(role) + 128), try std.math.mul(usize, count(role), 16 * 1024 + 64));
}
pub const Arena = struct {
    a: std.mem.Allocator,
    values: ?[]align(16 * 1024) M,
    columns: ?[]engine.pcs.ColumnEvaluation,
    backings: ?[][]M,
    pub fn init(a: std.mem.Allocator, role: Role, log: u32, cap: usize) !Arena {
        const length = try bytes(role, log);
        if (length > cap) return error.SecureResidentColumnCap;
        const values = try a.alignedAlloc(M, ALIGNMENT, length / @sizeOf(M));
        errdefer a.free(values);
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, count(role));
        errdefer a.free(columns);
        const backings = try a.alloc([]M, 1);
        const rows = @as(usize, 1) << @intCast(log);
        for (columns, 0..) |*column, i| column.* = .{ .log_size = log, .values = values[i * rows ..][0..rows] };
        backings[0] = values;
        return .{ .a = a, .values = values, .columns = columns, .backings = backings };
    }
    pub fn deinit(self: *Arena) void {
        if (self.values) |values| self.a.free(values);
        if (self.columns) |columns| self.a.free(columns);
        if (self.backings) |backings| self.a.free(backings);
        self.* = undefined;
    }
    pub fn transfer(self: *Arena) void {
        self.values = null;
        self.columns = null;
        self.backings = null;
    }
};
/// Caller retains the source buffer. All blits finish before any source or
/// arena can be released. A precommit decline is an error, never a CPU route.
pub fn commit(comptime H: type, a: std.mem.Allocator, runtime_handle: *anyopaque, initialization_count: u64, scheme: anytype, source: *const runtime.ResidentBuffer, first_column: usize, role: Role, log: u32, cap: usize, channel: anytype) !f64 {
    const length = try bytes(role, log);
    const offset = try std.math.mul(usize, try std.math.mul(usize, first_column, @as(usize, 1) << @intCast(log)), @sizeOf(M));
    if (try std.math.add(usize, offset, length) > source.byte_length or scheme.coefficient_retention_policy != .always) return error.InvalidSecureResidentColumnOwner;
    // Source + base coefficients + extended evaluations/Merkle workspace.
    // The extra full-size envelope covers stride rotation and transient FFT.
    if (try std.math.add(usize, source.byte_length, try std.math.add(usize, try retainedBytes(role, log), try std.math.mul(usize, @as(usize, 1) << @intCast(log), 64))) > cap) return error.SecureResidentColumnCap;
    var arena = try Arena.init(a, role, log, cap);
    defer arena.deinit();
    var milliseconds: f64 = 0;
    {
        var lease = try shared.acquireExisting();
        defer lease.deinit();
        if (lease.runtime.handle != runtime_handle or lease.identitySnapshot().initialization_count != initialization_count) return error.StaleSecureRamProducer;
        if (stwo_zig_secure_columns_blit(lease.runtime.handle, source.handle, offset, arena.values.?.ptr, length, &milliseconds) != 0) return error.SecureResidentColumnBlitFailed;
    }
    const prepared = (try combined.prepareAndCommitResidentOwned(H, a, arena.columns.?, scheme.config.fri_config.log_blowup_factor, scheme.coefficient_retention_policy, &scheme.twiddle_source, arena.backings.?)) orelse return error.SecureResidentCommitUnavailable;
    arena.transfer();
    const Tree = @TypeOf(scheme.trees.items[0]);
    var tree = Tree.initPrecommittedWithTeardown(prepared.columns, prepared.coefficients, prepared.column_backing_buffers, prepared.coefficient_backing_buffers, prepared.commitment, prepared.backing_teardown);
    tree.column_backing_alignment = prepared.column_backing_alignment;
    tree.coefficient_backing_alignment = prepared.coefficient_backing_alignment;
    errdefer tree.deinit(a);
    try scheme.appendCommittedTree(a, tree, channel);
    return milliseconds;
}
