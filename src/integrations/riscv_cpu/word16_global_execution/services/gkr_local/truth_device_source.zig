//! Device-owned truth witness contract. Compact call advice may be gathered on
//! the host; expanded MAIN, interactions and their commitment storage stay on
//! the device. Narrow claims retain the native transcript and receiver framing.
const std = @import("std");
const Api = @import("stwo_prover_api");
const D = Api.device_pcs;
const R = @import("../roster.zig");
const M = @import("manifest.zig");
pub const Shared = M.Shared;
const W = @import("worker_protocol.zig");
pub const Local = union(enum) {
    classic: @import("truth_fractions.zig").ChallengesFor(W.O),
    delegated: W.O,
};
pub const Prepare = struct {
    truth: R.Truth,
    advice: *const @import("../collector.zig").Advice,
    expected: M.ExpectedWorker,
    config: W.PcsConfig,
    budget: usize,
};
pub const Sealed = struct {
    scope: D.Scope,
    fixed: D.Tree,
    config: W.PcsConfig,
};
pub const Interactions = struct {
    /// Caller owns the narrow claim allocation; the owner retains the tree.
    claims: []W.O,
    tree: D.Tree,
    /// Optional deterministic replay of the original MAIN after releasing its
    /// wide storage at the stage-one barrier. Worker checks root/geometry.
    main: ?D.Tree = null,
};
pub const Owner = struct {
    context: *anyopaque,
    seal_main: *const fn (*anyopaque, std.mem.Allocator, Sealed) anyerror!D.Tree,
    generate_interactions: *const fn (*anyopaque, std.mem.Allocator, Local, M.Shared) anyerror!Interactions,
    release: *const fn (*anyopaque) void,
    pub fn deinit(self: *@This()) void {
        self.release(self.context);
        self.* = undefined;
    }
};
/// Requested bytes surviving the stage-one barrier, not total RSS/device peak.
/// Original advice and immutable setup remain separately admitted. MAIN replay
/// preserves the original committed root and compact input; it never retires
/// the cross-shard claims/statement obligation.
pub const RetentionRequest = struct {
    truth: R.Truth,
    expected: M.ExpectedWorker,
    config: W.PcsConfig,
};
pub const Retained = struct {
    compact_input_bytes: usize,
    narrow_metadata_bytes: usize,
    kept_device_bytes: usize,
    main_replayed: bool,
    pub fn total(self: @This(), minimum_compact: usize, minimum_main: usize) !usize {
        if (self.compact_input_bytes < minimum_compact or self.narrow_metadata_bytes == 0 or (!self.main_replayed and self.kept_device_bytes < minimum_main)) return error.InvalidDeviceTruthRetainedBound;
        return std.math.add(usize, self.narrow_metadata_bytes, try std.math.add(usize, self.compact_input_bytes, self.kept_device_bytes));
    }
};
/// Derive the compact payload from the execution ABI, including packet padding.
pub fn compactInputBytes(truth: R.Truth) !usize {
    const A = @import("stwo_riscv_frontend").rv64_air;
    const bytes: usize = switch (truth) {
        .keccak => 200,
        .sha256 => 96,
        .arith256_mod => 160,
        .secp_row => |t| if (t.setup.kind == .add) 192 else 96,
        .curve => |t| switch (t.setup.op) {
            inline else => |op| A.crypto.curves.Layout(op).PACKET_BYTES,
        },
        else => return error.UnsupportedDeviceTruthRetention,
    };
    return std.math.mul(usize, truth.count(), bytes);
}
pub const Stage = struct {
    context: *anyopaque,
    prepare: *const fn (*anyopaque, std.mem.Allocator, Prepare) anyerror!Owner,
    /// Absent means legacy conservative accounting. Merely selecting a device
    /// source never grants a smaller whole-inventory lease.
    retained_upper_bound: ?*const fn (*anyopaque, RetentionRequest) anyerror!Retained = null,
    pub fn retainedUpperBound(self: @This(), request: RetentionRequest, minimum_main: usize) !?usize {
        const callback = self.retained_upper_bound orelse return null;
        const bound = try callback(self.context, request);
        return try bound.total(try compactInputBytes(request.truth), minimum_main);
    }
};
/// FIXED remains independently derived immutable setup; this is a synchronous
/// borrowed coefficient view, never a producer-declared replacement key.
pub fn seal(owner: *Owner, a: std.mem.Allocator, scheme: *W.Scheme, expected: M.ExpectedWorker) !D.Tree {
    if (scheme.trees.items.len != 1 or scheme.device_om31_trace_trees[1] != null) return error.InvalidDeviceTruthSealPhase;
    const fixed = &scheme.trees.items[0];
    const coefficients = fixed.coefficients orelse return error.DeviceTruthFixedCoefficientsRequired;
    const columns = try a.alloc(D.Column, coefficients.len);
    defer a.free(columns);
    for (columns, coefficients) |*column, polynomial| column.* = .{ .log_size = polynomial.logSize(), .coefficients = polynomial.coefficients() };
    const root = fixed.root();
    if (!std.mem.eql(u8, &root, &expected.fixed)) return error.DeviceTruthFixedRootMismatch;
    return owner.seal_main(owner.context, a, .{ .scope = .{ .statement = expected.statement, .fixed = root, .main = @splat(0), .ordinal = @intCast(expected.ordinal) }, .fixed = .{ .root = root, .columns = columns }, .config = scheme.config });
}

/// Device callback geometry is checked against receiver-owned native authority,
/// before a root enters the transcript or any component slices the trace.
pub fn validateTree(tree: D.Tree, logs: []const u32) !void {
    if (logs.len == 0 or tree.columns.len != logs.len) return error.DeviceTruthShapeMismatch;
    var token: ?u64 = null;
    for (tree.columns, logs) |column, expected_log| {
        const device = column.device orelse return error.DeviceTruthHostFallback;
        if (column.coefficients.len != 0 or column.log_size != expected_log or expected_log < 5 or expected_log > 28 or device.count != @as(u64, 1) << @intCast(expected_log) or device.context_token == 0 or device.generation == 0) return error.DeviceTruthShapeMismatch;
        if (token) |previous| {
            if (previous != device.context_token) return error.DeviceTruthContextMismatch;
        } else token = device.context_token;
    }
}
test "truth device tree is bound to independent heterogeneous native geometry" {
    var columns = [_]D.Column{ .{ .log_size = 5, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 11 } }, .{ .log_size = 8, .device = .{ .words = @ptrFromInt(8192), .count = 256, .context_token = 7, .generation = 12 } } };
    const tree = D.Tree{ .root = @splat(0), .columns = &columns };
    try validateTree(tree, &.{ 5, 8 });
    try std.testing.expectError(error.DeviceTruthShapeMismatch, validateTree(tree, &.{ 5, 7 }));
    try std.testing.expectError(error.DeviceTruthShapeMismatch, validateTree(tree, &.{5}));
    columns[1].device.?.context_token = 8;
    try std.testing.expectError(error.DeviceTruthContextMismatch, validateTree(tree, &.{ 5, 8 }));
}

test "device truth retained bound charges replay evidence and keeps nonreplay MAIN" {
    const replay = Retained{ .compact_input_bytes = 200, .narrow_metadata_bytes = 4096, .kept_device_bytes = 0, .main_replayed = true };
    try std.testing.expectEqual(@as(usize, 4296), try replay.total(200, 1000000));
    var bad = replay;
    bad.compact_input_bytes = 199;
    try std.testing.expectError(error.InvalidDeviceTruthRetainedBound, bad.total(200, 1000000));
    bad = replay;
    bad.narrow_metadata_bytes = 0;
    try std.testing.expectError(error.InvalidDeviceTruthRetainedBound, bad.total(200, 1000000));
    bad = replay;
    bad.main_replayed = false;
    try std.testing.expectError(error.InvalidDeviceTruthRetainedBound, bad.total(200, 1000000));
    bad.kept_device_bytes = 1000000;
    try std.testing.expectEqual(@as(usize, 1004296), try bad.total(200, 1000000));
    bad.kept_device_bytes = std.math.maxInt(usize);
    try std.testing.expectError(error.Overflow, bad.total(200, 1000000));
}
