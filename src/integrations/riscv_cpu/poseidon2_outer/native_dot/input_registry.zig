//! Exact genuine-QM31 origin authority. Never infer free inputs from missing
//! producers. Constants and dedicated outputs remain independently produced.
const std = @import("std");
const B = @import("stwo_circuit_frontend").builder;
const Context = @import("../context.zig").Context;
const Bits = std.DynamicBitSetUnmanaged;
pub const Dispatch = struct {
    owner: *Context,
    eligible: ?Bits = null,
    remaining: usize = 0,
    pub fn deinit(self: *Dispatch) void {
        if (self.eligible) |*bits| bits.deinit(self.owner.allocator);
    }
    fn initRegistry(self: *Dispatch) !void {
        const owner = self.owner;
        const a = owner.allocator;
        const c = &owner.base.circuit;
        if (owner.native_input_ids.items.len != 0) return error.InvalidWitnessOrigin;
        var forbidden = try Bits.initEmpty(a, c.n_vars);
        defer forbidden.deinit(a);
        inline for (.{ c.add.items, c.sub.items, c.mul.items, c.pointwise_mul.items }) |gates| for (gates) |g| forbidden.set(g.out);
        for (c.m31_to_u32.items) |g| forbidden.set(g.out);
        for (owner.base.constants.values()) |v| forbidden.set(v.idx);
        for (owner.calls.items) |call| for (call.outputs) |id| forbidden.set(id);
        for (owner.native_mul_calls.items) |call| for (call.outputs) |id| forbidden.set(id);
        for (owner.native_dot_calls.items) |call| for (call.outputs) |id| forbidden.set(id);
        var seen = try Bits.initEmpty(a, c.n_vars);
        defer seen.deinit(a);
        var eligible = try Bits.initEmpty(a, c.n_vars);
        errdefer eligible.deinit(a);
        for (owner.base.guessed_vars.items) |guess| {
            const id = switch (guess) {
                .qm31, .m31, .u16 => |v| v.idx,
            };
            if (id <= 2 or id >= c.n_vars or seen.isSet(id)) return error.InvalidWitnessOrigin;
            seen.set(id);
            if (guess == .qm31) {
                if (forbidden.isSet(id)) return error.InvalidWitnessOrigin;
                eligible.set(id);
                self.remaining += 1;
            }
        }
        self.eligible = eligible;
    }
    pub fn emit(raw: ?*anyopaque, algebra: *anyopaque, v: B.Var) B.context.Error!void {
        const self: *Dispatch = @ptrCast(@alignCast(raw orelse return error.InvalidWitnessOrigin));
        if (@intFromPtr(algebra) != @intFromPtr(self.owner.algebra()) or self.owner.isClosed()) return error.InvalidWitnessOrigin;
        if (self.eligible == null) try self.initRegistry();
        const bits = &self.eligible.?;
        if (v.idx >= bits.bit_length or !bits.isSet(v.idx)) return error.InvalidWitnessOrigin;
        // Reserve before retiring eligibility, so OOM preserves the origin's
        // custody. The outer source is poisoned on every finalization error.
        try self.owner.native_input_ids.append(self.owner.allocator, v.idx);
        bits.unset(v.idx);
        self.remaining -= 1;
    }
    pub fn finish(self: *Dispatch) !void {
        if (self.remaining != 0 or self.owner.native_input_origin_seal != null) return error.InvalidWitnessOrigin;
        self.owner.native_input_origin_seal = self.owner.inputOriginIdentity();
    }
};
