//! Recover finite compression tasks from independently admitted original G/XOR
//! fixed schedules. Every local edge is matched to canonical compression SSA.
//! Initial words remain named external endpoints, never host witness values.
const std = @import("std");
const core = @import("stwo_core");
const H = @import("resident_parent_hash_plan_v1.zig");
const Rows = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const Topology = @import("../../frontends/riscv/recursion/air/blake3_compression_plan.zig");
pub fn derive(a: std.mem.Allocator, fixed: Rows.FixedTuple(false), limits: H.Limits) !H.Data {
    var g_count: usize = 0;
    inline for (.{ 0, 20, 21, 22 }) |i| g_count = try std.math.add(usize, g_count, fixed[i].len);
    if (g_count == 0 or g_count % 56 != 0 or fixed[1].len % 16 != 0 or g_count / 56 != fixed[1].len / 16) return error.InvalidResidentCompressionRoster;
    const count = g_count / 56;
    if (count > limits.max_calls or count > limits.max_frames or count > std.math.maxInt(u32) / 128) return error.ResidentHashResourceLimit;
    const input_bytes = try std.math.mul(usize, count, 128);
    if (input_bytes > limits.max_input_bytes) return error.ResidentHashResourceLimit;
    const gs = try a.alloc(Rows.FixedRow(Rows.Airs[0]), g_count);
    var cursor: usize = 0;
    inline for (.{ 0, 20, 21, 22 }) |i| {
        for (fixed[i]) |r| {
            gs[cursor] = r;
            cursor += 1;
        }
    }
    const sources = try a.alloc(H.Source, count * 32);
    const calls = try a.alloc(H.Call, count);
    const frames = try a.alloc(H.Frame, count);
    const order = try a.alloc(u32, count);
    const offsets = try a.alloc(u32, 2);
    offsets[0..2].* = .{ 0, @intCast(count) };
    const input_endpoints = try a.alloc(u64, count * 32);
    const output_endpoints = try a.alloc(u64, count * 16);
    const topology = Topology.canonical();
    for (calls, frames, 0..) |*call, *frame, i| {
        var map: [Topology.WIRE_COUNT]?u64 = @splat(null);
        const circuit = gs[i * 56][1].v;
        for (gs[i * 56 ..][0..56], topology.g) |r, t| {
            if (r[0].v != 1 or r[1].v != circuit) return error.InvalidResidentCompressionRoster;
            for (r) |m| if (m.v >= core.fields.m31.Modulus) return error.InvalidResidentCompressionRoster;
            for (t.input, r[2..8]) |local, wire| try bind(&map, local, circuit, wire.v);
            for (t.output, r[8..12]) |local, wire| try bind(&map, local, circuit, wire.v);
        }
        for (fixed[1][i * 16 ..][0..16], topology.xor) |r, t| {
            if (r[0].v != 1 or r[1].v != circuit) return error.InvalidResidentCompressionRoster;
            for (r) |m| if (m.v >= core.fields.m31.Modulus) return error.InvalidResidentCompressionRoster;
            for (t.input, r[2..4]) |local, wire| try bind(&map, local, circuit, wire.v);
            try bind(&map, t.output, circuit, r[4].v);
        }
        for (map) |v| if (v == null) return error.InvalidResidentCompressionRoster;
        call.* = .{ .initial = undefined, .output = undefined, .first_g = @intCast(i * 56), .first_xor = @intCast(i * 16) };
        for (0..32) |j| {
            call.initial[j] = @intCast(i * 48 + j);
            sources[i * 32 + j] = .{ .wire = call.initial[j], .kind = 1, .value = @intCast(i * 128 + j * 4), .length = 4 };
            input_endpoints[i * 32 + j] = map[j].?;
        }
        for (topology.output, 0..) |local, j| {
            call.output[j] = @intCast(i * 48 + 32 + j);
            output_endpoints[i * 16 + j] = map[local].?;
        }
        const levels = try a.alloc(u32, 2);
        levels[0] = @intCast(i);
        levels[1] = @intCast(i + 1);
        frame.* = .{ .input_first = i * 128, .input_bytes = 128, .wire_first = @intCast(i * 48), .digest = call.output[0..8].*, .first_call = i, .calls = 1, .first_source = i * 32, .source_count = 32, .level_offsets = levels };
        order[i] = @intCast(i);
    }
    const g_log: u32 = @intCast(@max(1, std.math.log2_int_ceil(usize, g_count)));
    const x_log: u32 = @intCast(@max(1, std.math.log2_int_ceil(usize, count * 16)));
    if (g_log > 24 or x_log > 24) return error.ResidentHashResourceLimit;
    const output_words = (@as(usize, 82) << @intCast(g_log)) + (@as(usize, 12) << @intCast(x_log));
    const bytes = try std.math.add(usize, try std.math.mul(usize, output_words + count * 48, 4), input_bytes + sources.len * @sizeOf(H.Source) + calls.len * @sizeOf(H.Call) + order.len * 8 + 4);
    if (bytes > limits.max_device_bytes) return error.ResidentHashResourceLimit;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/resident-parent/admitted-compression-roster/v1\x00");
    inline for (.{ 0, 1, 20, 21, 22 }) |i| hash.update(std.mem.sliceAsBytes(fixed[i]));
    hash.update(std.mem.sliceAsBytes(input_endpoints));
    hash.update(std.mem.sliceAsBytes(output_endpoints));
    return .{ .sources = sources, .calls = calls, .level_calls = order, .phase_calls = order, .level_offsets = offsets, .frames = frames, .input_bytes = input_bytes, .wire_count = @intCast(count * 48), .g_log = g_log, .xor_log = x_log, .device_bytes = bytes, .identity = hash.finalResult(), .source_endpoints = input_endpoints, .output_endpoints = output_endpoints };
}
fn bind(map: *[Topology.WIRE_COUNT]?u64, local: u32, circuit: u32, wire: u32) !void {
    const key = (@as(u64, circuit) << 32) | wire;
    if (map[local]) |prior| {
        if (prior != key) return error.InvalidResidentCompressionRoster;
    } else map[local] = key;
}
test "resident fixed compression graph matches every admitted original edge and split" {
    const a = std.testing.allocator;
    const Original = @import("../../frontends/riscv/recursion/air/blake3_hash_plan.zig");
    var original = try Original.build(a, 65);
    defer original.deinit();
    var fixed: Rows.FixedTuple(false) = undefined;
    inline for (Rows.Airs, 0..) |_, i| fixed[i] = &.{};
    const g = try a.alloc(Rows.FixedRow(Rows.Airs[0]), original.g.len);
    defer a.free(g);
    for (g, original.g) |*out, t| {
        var uses: [4]u32 = undefined;
        for (t.output, &uses) |wire, *u| u.* = original.uses[wire];
        out.* = Rows.compactFixed(Rows.Airs[0], try Rows.Airs[0].fixedRow(.{ .circuit = 17, .input = t.input, .output = t.output, .uses = uses }));
    }
    const x = try a.alloc(Rows.FixedRow(Rows.Airs[1]), original.xor.len);
    defer a.free(x);
    for (x, original.xor) |*out, t| out.* = Rows.compactFixed(Rows.Airs[1], try Rows.Airs[1].fixedRow(.{ .circuit = 17, .input = t.input, .output = t.output, .uses = original.uses[t.output] }));
    fixed[0] = g[0..56];
    fixed[20] = g[56..];
    fixed[1] = x;
    const p = try H.Owned.deriveFixed(a, fixed, .{});
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 2), p.view().frames.len);
    for (original.calls, p.view().calls, 0..) |old, new, i| {
        for (old.initial, 0..) |wire, j| try std.testing.expectEqual((@as(u64, 17) << 32) | wire, p.view().source_endpoints[i * 32 + j]);
        for (old.output, 0..) |wire, j| try std.testing.expectEqual((@as(u64, 17) << 32) | wire, p.view().output_endpoints[i * 16 + j]);
        try std.testing.expectEqual(@as(u32, @intCast(i * 48)), new.initial[0]);
    }
    g[5][2] = core.fields.m31.M31.fromCanonical(g[5][2].v + 1);
    try std.testing.expectError(error.InvalidResidentCompressionRoster, H.Owned.deriveFixed(a, fixed, .{}));
}
