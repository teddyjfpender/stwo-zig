//! Proof-owned raw child transport, canonical GPU validation, original child
//! Fiat-Shamir replay and arithmetic input gathering. No numeric readback.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Packet = @import("resident_parent_child_packet_v1.zig");
const Transcript = @import("resident_parent_child_transcript_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 40960;
pub const Slot = enum(u32) { packet, checks, tasks, refs, output, trace, state, composition_routes, deep_routes, fri_routes };
pub fn id(s: Slot) u32 {
    return FIRST_ID + @intFromEnum(s);
}
extern fn stwo_parent_child_validate_v1([*]const u32, u32, [*]const Packet.Check, u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_parent_child_transcript_v1([*]const Transcript.Task, u32, [*]const Transcript.Ref, u32, [*]const u32, u32, [*]u32, u32, [*]u32, u32, [*]u32, [*]u32, ?*anyopaque) c_int;
extern fn stwo_parent_child_gather_v1([*]const u32, u32, [*]const u32, u32, [*]const u32, u32, u32, [*]const Packet.InputDescriptor, u32, [*]u32, u32, [*]u32, ?*anyopaque) c_int;
pub const Plan = struct {
    packet: *const Packet.Owned,
    transcript: *const Transcript.Owned,
    routes: *const Packet.Routes,
    pub fn requirements(self: Plan, a: std.mem.Allocator) ![]cuda.runtime.arena.Requirement {
        if (!std.meta.eql(self.packet.profile_id, self.transcript.profile_id)) return error.InvalidResidentChildRuntime;
        const sizes = [_]usize{ self.packet.words.len, self.packet.checks.len * @sizeOf(Packet.Check) / 4, self.transcript.tasks.len * @sizeOf(Transcript.Task) / 4, self.transcript.refs.len * @sizeOf(Transcript.Ref) / 4, self.transcript.output_words, self.transcript.trace_words, 11, self.routes.composition.len * @sizeOf(Packet.InputDescriptor) / 4, self.routes.deep.len * @sizeOf(Packet.InputDescriptor) / 4, self.routes.fri.len * @sizeOf(Packet.InputDescriptor) / 4 };
        const out = try a.alloc(cuda.runtime.arena.Requirement, sizes.len);
        errdefer a.free(out);
        for (sizes, out, 0..) |n, *r, i| {
            if (n == 0 or n > std.math.maxInt(u32)) return error.ResidentChildRuntimeLimit;
            r.* = .{ .id = id(@enumFromInt(i)), .words = n, .alignment_words = 64, .live_from = .ingress, .live_through = .trace_generation };
        }
        return out;
    }
};
pub const Bound = struct {
    plan: Plan,
    slots: [10]common.Words,
    primed: bool = false,
    replayed: bool = false,
    gathered: [3]bool = @splat(false),
    pub fn init(plan: Plan, tx: anytype) !Bound {
        var result = Bound{ .plan = plan, .slots = undefined };
        inline for (std.meta.tags(Slot), 0..) |s, i| result.slots[i] = try tx.slot(id(s));
        return result;
    }
    pub fn slot(self: *const Bound, s: Slot) common.Words {
        return self.slots[@intFromEnum(s)];
    }
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.InvalidResidentChildRuntime;
        try common.requireStage(session, .ingress);
        try self.upload(session, u32, .packet, self.plan.packet.words);
        try self.upload(session, Packet.Check, .checks, self.plan.packet.checks);
        try self.upload(session, Transcript.Task, .tasks, self.plan.transcript.tasks);
        try self.upload(session, Transcript.Ref, .refs, self.plan.transcript.refs);
        try self.upload(session, Packet.InputDescriptor, .composition_routes, self.plan.routes.composition);
        try self.upload(session, Packet.InputDescriptor, .deep_routes, self.plan.routes.deep);
        try self.upload(session, Packet.InputDescriptor, .fri_routes, self.plan.routes.fri);
        self.primed = true;
    }
    fn upload(self: *const Bound, s: anytype, comptime T: type, which: Slot, values: []const T) !void {
        const dst = try self.slot(which).cast(T);
        if (dst.len != values.len) return error.InvalidResidentChildRuntime;
        try s.context.uploadSlice(T, dst, values);
    }
    fn typed(self: *const Bound, s: anytype, comptime T: type, which: Slot) ![*]T {
        const dst = try self.slot(which).cast(T);
        return s.context.deviceSlicePointer(T, dst, dst.len);
    }
    pub fn replay(self: *Bound, session: anytype, status: common.Words) !void {
        if (!self.primed or self.replayed or status.len != 1) return error.InvalidResidentChildRuntime;
        try common.requireStage(session, .trace_generation);
        const p = self.plan.packet;
        const t = self.plan.transcript;
        try common.record(session, .trace_generation, stwo_parent_child_validate_v1(try pointer(session, self.slot(.packet)), @intCast(p.words.len), try self.typed(session, Packet.Check, .checks), @intCast(p.checks.len), try pointer(session, status), session.context.stream));
        try common.record(session, .trace_generation, stwo_parent_child_transcript_v1(try self.typed(session, Transcript.Task, .tasks), @intCast(t.tasks.len), try self.typed(session, Transcript.Ref, .refs), @intCast(t.refs.len), try pointer(session, self.slot(.packet)), @intCast(p.words.len), try pointer(session, self.slot(.output)), t.output_words, try pointer(session, self.slot(.trace)), t.trace_words, try pointer(session, self.slot(.state)), try pointer(session, status), session.context.stream));
        self.replayed = true;
    }
    pub const Graph = enum(u2) { composition, deep, fri };
    /// Caller schedules this only after all declared DeviceInputs producers are
    /// complete. FRI expanded layers and DEEP answers are never accepted as CPU
    /// uploads through this owner.
    pub fn gather(self: *Bound, session: anytype, graph: Graph, resident: common.Words, arithmetic_inputs: common.Words, status: common.Words) !void {
        const index = @intFromEnum(graph);
        if (!self.replayed or self.gathered[index] or status.len != 1 or resident.len > std.math.maxInt(u32) or arithmetic_inputs.len > std.math.maxInt(u32)) return error.InvalidResidentChildRuntime;
        try common.requireStage(session, .trace_generation);
        const which: Slot = switch (graph) {
            .composition => .composition_routes,
            .deep => .deep_routes,
            .fri => .fri_routes,
        };
        const metadata = try self.slot(which).cast(Packet.InputDescriptor);
        const p = self.plan.packet;
        const queries = try self.slot(.output).sub(self.plan.transcript.query_first, p.query_count);
        try common.record(session, .trace_generation, stwo_parent_child_gather_v1(try pointer(session, self.slot(.packet)), @intCast(p.words.len), try pointer(session, resident), @intCast(resident.len), try pointer(session, queries), p.query_count, p.domain_log, try session.context.deviceSlicePointer(Packet.InputDescriptor, metadata, metadata.len), @intCast(metadata.len), try pointer(session, arithmetic_inputs), @intCast(arithmetic_inputs.len), try pointer(session, status), session.context.stream));
        self.gathered[index] = true;
    }
    pub fn requireComplete(self: *const Bound) !void {
        if (!self.replayed or !std.mem.allEqual(bool, &self.gathered, true)) return error.IncompleteResidentChildRuntime;
    }
};
fn pointer(s: anytype, w: common.Words) ![*]u32 {
    return s.context.deviceSlicePointer(u32, w, w.len);
}
fn forceNative(b: *Bound, s: *cuda.runtime.NativeSession, w: common.Words) !void {
    try b.prime(s);
    try b.replay(s, w);
    try b.gather(s, .composition, w, w, w);
    try b.requireComplete();
}
test "resident child runtime native full instantiation" {
    std.mem.doNotOptimizeAway(&forceNative);
}
