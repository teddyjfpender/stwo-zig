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
};
pub const Invocation = struct {
    stage: Stage,
    roles: Roles,
    scope: D.Scope,
    pub fn adapter(self: *@This()) Api.device_composition.ResidentOm31Stage {
        return .{ .context = self, .evaluate_and_commit = evaluate };
    }
    fn evaluate(raw: *anyopaque, a: std.mem.Allocator, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque) anyerror!D.Tree {
        const self: *@This() = @ptrCast(@alignCast(raw));
        return self.stage.evaluate_and_commit(self.stage.context, a, self.roles, alpha, log, split, total, trace, self.scope);
    }
};
