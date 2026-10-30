//! Proof-arena conditional wire resolution; all private selection is on device.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
pub const Cold = @import("resident_parent_wire_resolve_plan_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 32768;
pub const Slot = enum(u32) { instructions, candidates, requests, scratch, outputs };
pub fn id(s: Slot) u32 {
    return FIRST_ID + @intFromEnum(s);
}
extern fn stwo_resident_parent_wire_resolve_on([*]const Cold.Instruction, [*]const Cold.Candidate, [*]const Cold.Request, u32, [*]const u32, [*]u32, [*]u32, [*]u32, ?*anyopaque) c_int;
pub fn requirements(a: std.mem.Allocator, p: *const Cold.Plan) ![]cuda.runtime.arena.Requirement {
    const counts = [_]usize{ p.instructions.len * @sizeOf(Cold.Instruction) / 4, @max(1, p.candidates.len) * @sizeOf(Cold.Candidate) / 4, p.requests.len * @sizeOf(Cold.Request) / 4, p.scratch_words, p.output_words };
    const out = try a.alloc(cuda.runtime.arena.Requirement, counts.len);
    for (out, counts, 0..) |*r, n, i| r.* = .{ .id = id(@enumFromInt(i)), .words = @max(1, n), .alignment_words = 64, .live_from = .ingress, .live_through = .trace_generation };
    return out;
}
pub const Bound = struct {
    plan: *const Cold.Plan,
    slots: [5]common.Words,
    primed: bool = false,
    next: usize = 0,
    pub fn init(plan: *const Cold.Plan, tx: anytype) !Bound {
        var b = Bound{ .plan = plan, .slots = undefined };
        inline for (std.meta.tags(Slot), 0..) |s, i| b.slots[i] = try tx.slot(id(s));
        return b;
    }
    pub fn slot(self: *const Bound, s: Slot) common.Words {
        return self.slots[@intFromEnum(s)];
    }
    pub fn prime(self: *Bound, session: anytype) !void {
        if (self.primed) return error.InvalidResidentWireResolverState;
        try common.requireStage(session, .ingress);
        try session.context.uploadSlice(Cold.Instruction, try self.slot(.instructions).cast(Cold.Instruction), self.plan.instructions);
        if (self.plan.candidates.len != 0) try session.context.uploadSlice(Cold.Candidate, try self.slot(.candidates).cast(Cold.Candidate), self.plan.candidates);
        try session.context.uploadSlice(Cold.Request, try self.slot(.requests).cast(Cold.Request), self.plan.requests);
        self.primed = true;
    }
    pub fn resolve(self: *Bound, session: anytype, phase: u32, count: usize, main: common.Words, status: common.Words) !void {
        if (!self.primed or count == 0 or self.next > self.plan.requests.len or count > self.plan.requests.len - self.next or main.len < self.plan.main_words or status.len != 1) return error.InvalidResidentWireResolverState;
        for (self.plan.requests[self.next..][0..count]) |request| if (request.phase != phase) return error.InvalidResidentWireResolvePhase;
        try common.requireStage(session, .trace_generation);
        const ins = try self.slot(.instructions).cast(Cold.Instruction);
        const cs = try self.slot(.candidates).cast(Cold.Candidate);
        const rs = try (try self.slot(.requests).cast(Cold.Request)).sub(self.next, count);
        try common.record(session, .trace_generation, stwo_resident_parent_wire_resolve_on(try session.context.deviceSlicePointer(Cold.Instruction, ins, ins.len), try session.context.deviceSlicePointer(Cold.Candidate, cs, cs.len), try session.context.deviceSlicePointer(Cold.Request, rs, rs.len), @intCast(count), try pointer(session, main), try pointer(session, self.slot(.scratch)), try pointer(session, self.slot(.outputs)), try pointer(session, status), session.context.stream));
        self.next += count;
    }
    pub fn requireComplete(self: *const Bound) !void {
        if (self.next != self.plan.requests.len) return error.IncompleteResidentWireResolution;
    }
};
fn pointer(s: anytype, w: common.Words) ![*]u32 {
    return s.context.deviceSlicePointer(u32, w, w.len);
}
fn force(b: *Bound, s: *cuda.runtime.NativeSession, main: common.Words, status: common.Words) !void {
    try b.prime(s);
    try b.resolve(s, 1, 1, main, status);
    try b.requireComplete();
}
test "resident wire resolver native executor typechecks" {
    _ = &force;
}
