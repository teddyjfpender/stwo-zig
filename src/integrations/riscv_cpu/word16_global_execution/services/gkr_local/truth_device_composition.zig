//! Per-proof truth authority adapter; no CUDA dependency or process-global hook.
const std = @import("std");
const Api = @import("stwo_prover_api");
const D = Api.device_pcs;
const O = D.O;
pub const Classic = @import("truth_role.zig").Component;
pub const Delegated = @import("truth_v3_role.zig").Component;
pub const Roles = union(enum) { classic: []const Classic, delegated: *const Delegated };
pub const Stage = struct {
    context: *anyopaque,
    evaluate_and_commit: *const fn (*anyopaque, std.mem.Allocator, Roles, O, u32, u32, usize, *const anyopaque, D.Scope) anyerror!D.Tree,
    evaluate_and_commit_at_blowup: ?*const fn (*anyopaque, std.mem.Allocator, Roles, O, u32, u32, usize, *const anyopaque, D.Scope, u32) anyerror!D.Tree = null,
};
pub const Invocation = struct {
    stage: Stage,
    log_blowup: u32 = 1,
    roles: Roles,
    scope: D.Scope,
    pub fn adapter(self: *@This()) Api.device_composition.ResidentOm31Stage {
        return .{ .context = self, .evaluate_and_commit = evaluate };
    }
    fn evaluate(raw: *anyopaque, a: std.mem.Allocator, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque) anyerror!D.Tree {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.stage.evaluate_and_commit_at_blowup) |callback| return callback(self.stage.context, a, self.roles, alpha, log, split, total, trace, self.scope, self.log_blowup);
        if (self.log_blowup != 1) return error.ResidentCompositionBlowupNotSupported;
        return self.stage.evaluate_and_commit(self.stage.context, a, self.roles, alpha, log, split, total, trace, self.scope);
    }
};

test "D2 truth composition binds per-proof blowup and rejects legacy adapters" {
    const Mock = struct {
        fn legacy(_: *anyopaque, _: std.mem.Allocator, _: Roles, _: O, _: u32, _: u32, _: usize, _: *const anyopaque, _: D.Scope) !D.Tree {
            return error.LegacyMustNotRun;
        }
        fn selected(raw: *anyopaque, _: std.mem.Allocator, _: Roles, _: O, _: u32, _: u32, _: usize, _: *const anyopaque, _: D.Scope, beta: u32) !D.Tree {
            const out: *u32 = @ptrCast(@alignCast(raw));
            out.* = beta;
            return .{ .root = @splat(0), .columns = &.{} };
        }
    };
    var seen: u32 = 0;
    var invocation = Invocation{ .stage = .{ .context = &seen, .evaluate_and_commit = Mock.legacy }, .log_blowup = 2, .roles = .{ .classic = &.{} }, .scope = .{ .statement = @splat(0), .fixed = @splat(0), .main = @splat(0), .ordinal = 0 } };
    var adapter = invocation.adapter();
    try std.testing.expectError(error.ResidentCompositionBlowupNotSupported, adapter.evaluate_and_commit(adapter.context, std.testing.allocator, O.one(), 5, 0, 0, &seen));
    invocation.stage.evaluate_and_commit_at_blowup = Mock.selected;
    _ = try adapter.evaluate_and_commit(adapter.context, std.testing.allocator, O.one(), 5, 0, 0, &seen);
    try std.testing.expectEqual(@as(u32, 2), seen);
}
