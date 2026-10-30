//! Numerical qualification fixture only: no child proof is certified by empty
//! fixed rows. Every original parent AIR and both real lookup tables still run.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const Program = @import("resident_parent_program_v1.zig");
const PCS = @import("resident_parent_pcs_v1.zig");
const Memory = @import("resident_parent_memory_v1.zig");
const Framework = @import("resident_parent_framework_v1.zig");
pub const Plan = struct {
    framework: Framework.Plan,
    pub fn init(a: std.mem.Allocator, program: *const Program.Owned) !Plan {
        // Prevent accidentally applying zero-witness generation to real rows.
        for (program.view().admission.key.log_sizes) |log| if (log != 1) return error.NotPaddingResidentProgram;
        return .{ .framework = try Framework.Plan.init(a, program, .{}) };
    }
    pub fn deinit(self: *Plan) void {
        self.framework.deinit();
    }
    pub fn requirements(self: *const Plan, a: std.mem.Allocator, _: *const Program.Owned, _: *const PCS.Plans) ![]cuda.runtime.arena.Requirement {
        return a.dupe(cuda.runtime.arena.Requirement, self.framework.requirements);
    }
    pub fn bind(self: *const Plan, _: std.mem.Allocator, tx: *cuda.runtime.proof_transaction.ResidentProofTransaction, program: *const Program.Owned, _: *const PCS.Plans, _: *const Memory.Views) !Bound {
        if (program != self.framework.program) return error.NotPaddingResidentProgram;
        return .{ .framework = try Framework.Bound.init(&self.framework, tx) };
    }
};
pub const Bound = struct {
    framework: Framework.Bound,
    pub fn deinit(_: *Bound, _: std.mem.Allocator) void {}
    pub fn prime(self: *Bound, session: *cuda.runtime.NativeSession) !void {
        try self.framework.prime(session);
    }
    pub fn witness(self: *Bound, session: *cuda.runtime.NativeSession, views: *const Memory.Views) !void {
        for (views.sources[1]) |column| try session.zeroResidentSlice(u32, .trace_generation, column);
        try self.framework.generateCounters(session, views);
    }
    pub fn interactions(self: *Bound, session: *cuda.runtime.NativeSession, views: *const Memory.Views) !void {
        try self.framework.generateInteractions(session, views);
    }
    pub fn composition(self: *Bound, session: *cuda.runtime.NativeSession, views: *const Memory.Views) !void {
        try self.framework.compose(session, views);
    }
};
