//! Device-owned truth witness contract. Compact call advice may be gathered on
//! the host; expanded MAIN, interactions and their commitment storage stay on
//! the device. Narrow claims retain the native transcript and receiver framing.
const std = @import("std");
const Api = @import("stwo_prover_api");
const D = Api.device_pcs;
const R = @import("../roster.zig");
const M = @import("manifest.zig");
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
pub const Stage = struct {
    context: *anyopaque,
    prepare: *const fn (*anyopaque, std.mem.Allocator, Prepare) anyerror!Owner,
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
