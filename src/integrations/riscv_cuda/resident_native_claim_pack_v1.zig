//! Raw physical GPU claims -> exact original word/field/u64 statement buffers.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Routes = @import("resident_native_claim_routes_v1.zig");
extern fn stwo_native_claim_pack_v1([*]const Routes.Route, u32, [*]const u32, u32, u32, [*]u32, u32, ?[*]u32, u32, ?[*]u64, u32, [*]u32, ?*anyopaque) c_int;
pub const Bindings = struct { routes: common.Words, words: common.Words, fields: common.SecureFields, counts: common.Words, error_flag: common.Words };
pub const Bound = struct {
    plan: *const Routes.Plan,
    views: Bindings,
    primed: bool = false,
    packed_once: bool = false,
    pub fn init(plan: *const Routes.Plan, views: Bindings) !Bound {
        if (views.routes.len != plan.routes.len * @sizeOf(Routes.Route) / 4 or views.words.len != plan.statement.words.len or views.fields.len != plan.statement.felts.len or views.counts.len != plan.access_count * 2 or views.error_flag.len != 1) return error.InvalidNativeClaimBuffers;
        inline for (.{ views.words, views.fields, views.counts, views.error_flag }) |view| {
            if (view.owner != views.routes.owner or view.generation != views.routes.generation) return error.InvalidNativeClaimBuffers;
        }
        return .{ .plan = plan, .views = views };
    }
    pub fn prime(self: *Bound, session: *cuda.runtime.NativeSession) !void {
        if (self.primed) return error.InvalidNativeClaimState;
        try common.requireStage(session, .ingress);
        if (self.plan.routes.len != 0) try session.context.uploadSlice(Routes.Route, try self.views.routes.cast(Routes.Route), self.plan.routes);
        try session.context.uploadSlice(u32, self.views.words, self.plan.statement.words);
        if (self.views.fields.len != 0) try session.zeroResidentSlice(u32, .ingress, try self.views.fields.cast(u32));
        if (self.views.counts.len != 0) try session.zeroResidentSlice(u32, .ingress, self.views.counts);
        self.primed = true;
    }
    pub fn execute(self: *Bound, session: *cuda.runtime.NativeSession, claims: common.SecureFields) !void {
        if (!self.primed or self.packed_once) return error.InvalidNativeClaimState;
        if (claims.len * 4 != self.plan.source_words or claims.owner != self.views.words.owner or claims.generation != self.views.words.generation) return error.InvalidNativeClaimBuffers;
        try common.requireStage(session, .trace_commit);
        if (self.plan.routes.len != 0) {
            const routes = try self.views.routes.cast(Routes.Route);
            const fields = try self.views.fields.cast(u32);
            const counts = try self.views.counts.cast(u64);
            const source = try claims.cast(u32);
            try common.record(session, .trace_commit, stwo_native_claim_pack_v1(try session.context.deviceSlicePointer(Routes.Route, routes, routes.len), @intCast(routes.len), try session.context.deviceSlicePointer(u32, source, source.len), @intCast(source.len), @intCast(self.plan.projection_count * 4), try session.context.deviceSlicePointer(u32, self.views.words, self.views.words.len), @intCast(self.views.words.len), if (fields.len == 0) null else try session.context.deviceSlicePointer(u32, fields, fields.len), @intCast(fields.len), if (counts.len == 0) null else try session.context.deviceSlicePointer(u64, counts, counts.len), @intCast(counts.len), try session.context.deviceSlicePointer(u32, self.views.error_flag, 1), session.context.stream));
        }
        self.packed_once = true;
    }
};

extern fn stwo_native_root_equal_v1([*]const u32, [*]const u32, [*]u32, ?*anyopaque) c_int;
pub fn requireRoot(session: *cuda.runtime.NativeSession, expected: common.Words, actual: common.Words, error_flag: common.Words) !void {
    if (expected.len != 8 or actual.len != 8 or error_flag.len != 1 or actual.owner != expected.owner or error_flag.owner != expected.owner or actual.generation != expected.generation or error_flag.generation != expected.generation) return error.InvalidNativeRootBuffers;
    try common.record(session, .trace_commit, stwo_native_root_equal_v1(try session.context.deviceSlicePointer(u32, expected, 8), try session.context.deviceSlicePointer(u32, actual, 8), try session.context.deviceSlicePointer(u32, error_flag, 1), session.context.stream));
}
