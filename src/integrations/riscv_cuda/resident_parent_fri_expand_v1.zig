//! Raw child FRI witness reconstruction. The CPU supplies only bounded spans
//! and public geometry. Queries, DEEP answers, alphas, folds and expanded values
//! remain in the proof arena. This owns no CPU channel/capture implementation.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const common = cuda.runtime.stages.common;
const Packet = @import("resident_parent_child_packet_v1.zig");
const Profile = @import("../../frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
pub const FIRST_ID: u32 = (1 << 28) + 49152;
pub const Slot = enum(u32) { positions0, positions1, values0, values1, count0, count1, scratch };
pub fn id(s: Slot) u32 {
    return FIRST_ID + @intFromEnum(s);
}
pub const Layer = struct { domain_log: u32, fold_log: u32, query_shift: u32, witness: Packet.Span, expanded: Packet.Span };
pub const Plan = struct {
    a: std.mem.Allocator,
    layers: []const Layer,
    query_count: u32,
    raw_words: u32,
    output_words: u32,
    max_width: u32,
    pub fn init(a: std.mem.Allocator, packet: *const Packet.Owned, profile: *const Profile.Owned) !Plan {
        if (!std.meta.eql(packet.profile_id, profile.seal) or packet.query_count == 0 or packet.query_count > 128 or packet.layers.len == 0 or packet.layers.len > 30 or packet.layers.len != profile.shape.widths.len or packet.words.len > std.math.maxInt(u32)) return error.InvalidResidentFriExpansion;
        const layers = try a.alloc(Layer, packet.layers.len);
        errdefer a.free(layers);
        var shift: u32 = 0;
        var offset: u32 = 0;
        var max_width: u32 = 0;
        for (layers, packet.layers, profile.shape.widths) |*out, layer, width| {
            if (width < 2 or width > 32 or !std.math.isPowerOfTwo(width) or layer.witness.count % 4 != 0 or
                @as(u64, layer.witness.first) + layer.witness.count > packet.words.len) return error.InvalidResidentFriExpansion;
            const log: u32 = std.math.log2_int(u32, width);
            if (shift >= packet.domain_log or log > packet.domain_log - shift or layer.witness.count > @as(u64, packet.query_count) * width * 4) return error.InvalidResidentFriExpansion;
            const count = try std.math.mul(u32, try std.math.mul(u32, packet.query_count, width), 4);
            out.* = .{ .domain_log = packet.domain_log - shift, .fold_log = log, .query_shift = shift, .witness = layer.witness, .expanded = .{ .first = offset, .count = count } };
            shift += log;
            offset = try std.math.add(u32, offset, count);
            max_width = @max(max_width, width);
        }
        return .{ .a = a, .layers = layers, .query_count = packet.query_count, .raw_words = @intCast(packet.words.len), .output_words = offset, .max_width = max_width };
    }
    pub fn deinit(self: *Plan) void {
        self.a.free(self.layers);
        self.* = undefined;
    }
    pub fn requirements(self: Plan, a: std.mem.Allocator) ![]cuda.runtime.arena.Requirement {
        const sizes = [_]usize{ 128, 128, 512, 512, 1, 1, 128 * @as(usize, self.max_width) * 4 };
        const out = try a.alloc(cuda.runtime.arena.Requirement, sizes.len);
        errdefer a.free(out);
        for (sizes, out, 0..) |n, *r, i| r.* = .{ .id = id(@enumFromInt(i)), .words = n, .alignment_words = 64, .live_from = .trace_generation, .live_through = .trace_generation };
        return out;
    }
};
extern fn stwo_parent_fri_expand_v1([*]const u32, u32, [*]const u32, [*]const u32, [*]const u32, [*]const u32, [*]const u32, u32, [*]const u32, u32, u32, u32, u32, [*]u32, [*]u32, [*]u32, [*]u32, [*]u32, [*]u32, ?*anyopaque) c_int;
pub const Bound = struct {
    plan: *const Plan,
    slots: [7]common.Words,
    complete: bool = false,
    pub fn init(plan: *const Plan, tx: anytype) !Bound {
        var out = Bound{ .plan = plan, .slots = undefined };
        inline for (std.meta.tags(Slot), 0..) |s, i| out.slots[i] = try tx.slot(id(s));
        return out;
    }
    pub fn slot(self: *const Bound, s: Slot) common.Words {
        return self.slots[@intFromEnum(s)];
    }
    pub fn execute(self: *Bound, session: anytype, raw: common.Words, queries: common.Words, deep: common.Words, alphas: common.Words, expanded: common.Words, status: common.Words) !void {
        const p = self.plan;
        if (self.complete or raw.len != p.raw_words or queries.len != p.query_count or deep.len != p.query_count * 4 or alphas.len != p.layers.len * 4 or expanded.len != p.output_words or status.len != 1) return error.InvalidResidentFriExpansionState;
        try common.requireStage(session, .trace_generation);
        for (p.layers, 0..) |layer, i| {
            const out = i % 2;
            const input = out ^ 1;
            const positions_out = self.slot(if (out == 0) .positions0 else .positions1);
            const positions_in = self.slot(if (input == 0) .positions0 else .positions1);
            const values_out = self.slot(if (out == 0) .values0 else .values1);
            const values_in = self.slot(if (input == 0) .values0 else .values1);
            const count_out = self.slot(if (out == 0) .count0 else .count1);
            const count_in = self.slot(if (input == 0) .count0 else .count1);
            // Zero-length witness uses the raw packet's valid base address. The device
            // checks exact consumption before touching any witness word.
            const witness = if (layer.witness.count == 0) try raw.sub(0, 1) else try raw.sub(layer.witness.first, layer.witness.count);
            const alpha = try alphas.sub(i * 4, 4);
            const destination = try expanded.sub(layer.expanded.first, layer.expanded.count);
            try common.record(session, .trace_generation, stwo_parent_fri_expand_v1(try pointer(session, queries), p.query_count, try pointer(session, deep), try pointer(session, positions_in), try pointer(session, values_in), try pointer(session, count_in), try pointer(session, witness), layer.witness.count / 4, try pointer(session, alpha), layer.domain_log, layer.fold_log, layer.query_shift, @intFromBool(i == 0), try pointer(session, positions_out), try pointer(session, values_out), try pointer(session, count_out), try pointer(session, self.slot(.scratch)), try pointer(session, destination), try pointer(session, status), session.context.stream));
        }
        self.complete = true;
    }
    pub fn requireComplete(self: *const Bound) !void {
        if (!self.complete) return error.IncompleteResidentFriExpansion;
    }
};
fn pointer(s: anytype, w: common.Words) ![*]u32 {
    return s.context.deviceSlicePointer(u32, w, w.len);
}
fn forceNative(b: *Bound, s: *cuda.runtime.NativeSession, w: common.Words) !void {
    try b.execute(s, w, w, w, w, w, w);
    try b.requireComplete();
}
test "resident FRI expansion runtime instantiates without host numeric hooks" {
    std.mem.doNotOptimizeAway(&forceNative);
}
