//! Cold, input-value-independent BLAKE3 witness routing. Only canonical original
//! hash plans are admitted. Dynamic input bytes and all numeric execution stay
//! on device; this module does not accept CPU compression outputs or MAIN rows.
const std = @import("std");
const Core = @import("stwo_core");
const Hash = @import("../../frontends/riscv/recursion/air/blake3_hash_plan.zig");
pub const Limits = struct { max_frames: usize = 4096, max_input_bytes: usize = 64 << 20, max_calls: usize = 1 << 20, max_device_bytes: usize = 16 << 30 };
pub const Source = extern struct { wire: u32, kind: u32, value: u32, length: u32 };
pub const Call = extern struct { initial: [32]u32, output: [16]u32, first_g: u32, first_xor: u32 };
pub const Frame = struct { input_first: usize, input_bytes: usize, wire_first: u32, digest: [8]u32, first_call: usize, calls: usize, first_source: usize, source_count: usize, level_offsets: []const u32 = &.{} };
pub const Data = struct {
    source_endpoints: []const u64 = &.{},
    output_endpoints: []const u64 = &.{},
    sources: []const Source,
    calls: []const Call,
    level_calls: []const u32,
    phase_calls: []const u32,
    level_offsets: []const u32,
    frames: []const Frame,
    input_bytes: usize,
    wire_count: u32,
    g_log: u32,
    xor_log: u32,
    device_bytes: usize,
    identity: [32]u8,
};
const Storage = struct { backing: std.mem.Allocator, arena: std.heap.ArenaAllocator, data: Data };
pub const Owned = opaque {
    pub fn deriveFixed(backing: std.mem.Allocator, fixed: @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig").FixedTuple(false), limits: Limits) !*Owned {
        const self = try backing.create(Storage);
        errdefer backing.destroy(self);
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const data = try @import("resident_parent_hash_fixed_plan_v1.zig").derive(arena.allocator(), fixed, limits);
        self.* = .{ .backing = backing, .arena = arena, .data = data };
        return @ptrCast(self);
    }
    pub fn derive(backing: std.mem.Allocator, lengths: []const usize, limits: Limits) !*Owned {
        if (lengths.len == 0 or lengths.len > limits.max_frames or limits.max_calls == 0 or limits.max_device_bytes == 0) return error.ResidentHashResourceLimit;
        const self = try backing.create(Storage);
        errdefer backing.destroy(self);
        var arena = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const a = arena.allocator();
        var sources: std.ArrayList(Source) = .empty;
        var calls: std.ArrayList(Call) = .empty;
        var levels: std.ArrayList(u32) = .empty;
        var frames: std.ArrayList(Frame) = .empty;
        var input_bytes: usize = 0;
        var wire_count: usize = 0;
        var maximum_level: u32 = 0;
        for (lengths) |length| {
            const next_input = try std.math.add(usize, input_bytes, length);
            if (next_input > limits.max_input_bytes or next_input > std.math.maxInt(u32)) return error.ResidentHashResourceLimit;
            const expected_calls = try std.math.add(usize, @max(1, length / 64 + @intFromBool(length % 64 != 0)), @max(1, length / 1024 + @intFromBool(length % 1024 != 0)) - 1);
            const expected_total = try std.math.add(usize, calls.items.len, expected_calls);
            if (expected_total > limits.max_calls or expected_total > (@as(usize, 1) << 24) / 56) return error.ResidentHashResourceLimit;
            var plan = try Hash.build(backing, length);
            defer plan.deinit();
            const next_calls = try std.math.add(usize, calls.items.len, plan.calls.len);
            if (next_calls > limits.max_calls or next_calls > std.math.maxInt(u32)) return error.ResidentHashResourceLimit;
            const next_wires = try std.math.add(usize, wire_count, plan.uses.len);
            if (next_wires > std.math.maxInt(u32)) return error.ResidentHashResourceLimit;
            const local_levels = try backing.alloc(?u32, plan.uses.len);
            defer backing.free(local_levels);
            @memset(local_levels, null);
            const first_source = sources.items.len;
            for (plan.sources) |source| {
                const route: Source = switch (source.value) {
                    .constant => |v| .{ .wire = @intCast(wire_count + source.wire), .kind = 0, .value = v, .length = 0 },
                    .input => |v| .{ .wire = @intCast(wire_count + source.wire), .kind = 1, .value = @intCast(input_bytes + v.offset), .length = v.len },
                };
                try sources.append(a, route);
                local_levels[source.wire] = 0;
            }
            var frame: Frame = .{ .input_first = input_bytes, .input_bytes = length, .wire_first = @intCast(wire_count), .digest = undefined, .first_call = calls.items.len, .calls = plan.calls.len, .first_source = first_source, .source_count = plan.sources.len };
            for (plan.output, &frame.digest) |wire, *out| out.* = @intCast(wire_count + wire);
            for (plan.calls) |call| {
                var level: u32 = 0;
                var encoded: Call = .{ .initial = undefined, .output = undefined, .first_g = @intCast(calls.items.len * 56), .first_xor = @intCast(calls.items.len * 16) };
                for (call.initial, &encoded.initial) |wire, *out| {
                    level = @max(level, local_levels[wire] orelse return error.InvalidResidentHashTopology);
                    out.* = @intCast(wire_count + wire);
                }
                for (call.output, &encoded.output) |wire, *out| {
                    if (local_levels[wire] != null) return error.InvalidResidentHashTopology;
                    local_levels[wire] = level + 1;
                    out.* = @intCast(wire_count + wire);
                }
                try calls.append(a, encoded);
                try levels.append(a, level);
                maximum_level = @max(maximum_level, level);
            }
            for (plan.output) |wire| if (local_levels[wire] == null) return error.InvalidResidentHashTopology;
            try frames.append(a, frame);
            input_bytes = next_input;
            wire_count = next_wires;
        }
        const g_log = log(calls.items.len * 56);
        const xor_log = log(calls.items.len * 16);
        if (g_log > 24 or xor_log > 24) return error.ResidentHashResourceLimit;
        const offsets = try a.alloc(u32, @as(usize, maximum_level) + 2);
        @memset(offsets, 0);
        for (levels.items) |level| offsets[level + 1] += 1;
        for (1..offsets.len) |i| offsets[i] += offsets[i - 1];
        const cursors = try a.dupe(u32, offsets[0 .. offsets.len - 1]);
        const order = try a.alloc(u32, calls.items.len);
        for (levels.items, 0..) |level, i| {
            order[cursors[level]] = @intCast(i);
            cursors[level] += 1;
        }
        const phase_order = try a.alloc(u32, calls.items.len);
        for (frames.items) |*frame| {
            const local = levels.items[frame.first_call..][0..frame.calls];
            var max: u32 = 0;
            for (local) |level| max = @max(max, level);
            const boundaries = try a.alloc(u32, max + 2);
            @memset(boundaries, 0);
            for (local) |level| boundaries[level + 1] += 1;
            boundaries[0] = @intCast(frame.first_call);
            for (1..boundaries.len) |i| boundaries[i] += boundaries[i - 1];
            const positions = try a.dupe(u32, boundaries[0 .. boundaries.len - 1]);
            for (local, 0..) |level, i| {
                phase_order[positions[level]] = @intCast(frame.first_call + i);
                positions[level] += 1;
            }
            frame.level_offsets = boundaries;
        }
        const output_words = try std.math.add(usize, try std.math.mul(usize, 82, pow(g_log)), try std.math.mul(usize, 12, pow(xor_log)));
        var bytes = try std.math.mul(usize, try std.math.add(usize, output_words, wire_count), 4);
        for ([_]usize{ input_bytes, sources.items.len * @sizeOf(Source), calls.items.len * @sizeOf(Call), order.len * 4, phase_order.len * 4, 4 }) |n| bytes = try std.math.add(usize, bytes, n);
        if (bytes > limits.max_device_bytes) return error.ResidentHashResourceLimit;
        const source_slice = try sources.toOwnedSlice(a);
        const call_slice = try calls.toOwnedSlice(a);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo/resident-parent/hash-witness-plan/v1");
        h.update(@embedFile("../../frontends/riscv/recursion/air/blake3_hash_plan.zig"));
        h.update(std.mem.sliceAsBytes(source_slice));
        h.update(std.mem.sliceAsBytes(call_slice));
        h.update(std.mem.sliceAsBytes(order));
        h.update(std.mem.sliceAsBytes(offsets));
        h.update(std.mem.sliceAsBytes(phase_order));
        h.update(@embedFile("resident_parent_hash_plan_v1.zig"));
        self.* = .{ .backing = backing, .arena = arena, .data = .{ .sources = source_slice, .calls = call_slice, .level_calls = order, .phase_calls = phase_order, .level_offsets = offsets, .frames = try frames.toOwnedSlice(a), .input_bytes = input_bytes, .wire_count = @intCast(wire_count), .g_log = g_log, .xor_log = xor_log, .device_bytes = bytes, .identity = h.finalResult() } };
        return @ptrCast(self);
    }
    pub fn view(self: *const Owned) *const Data {
        const storage: *const Storage = @ptrCast(@alignCast(self));
        return &storage.data;
    }
    pub fn deinit(self: *Owned) void {
        const storage: *Storage = @ptrCast(@alignCast(self));
        const backing = storage.backing;
        storage.arena.deinit();
        backing.destroy(storage);
    }
};
fn log(n: usize) u32 {
    return @intCast(@max(1, std.math.log2_int_ceil(usize, @max(2, n))));
}
fn pow(n: u32) usize {
    return @as(usize, 1) << @intCast(n);
}

test "resident hash cold plan binds dependencies and whole-device cap" {
    const a = std.testing.allocator;
    const owned = try Owned.derive(a, &.{ 0, 1, 64, 65, 1024, 1025, 4096 }, .{});
    defer owned.deinit();
    const p = owned.view();
    try std.testing.expectEqual(@as(usize, 7), p.frames.len);
    const levels = try a.alloc(u32, p.calls.len);
    defer a.free(levels);
    for (0..p.level_offsets.len - 1) |level| for (p.level_calls[p.level_offsets[level]..p.level_offsets[level + 1]]) |call| {
        levels[call] = @intCast(level);
    };
    const producer = try a.alloc(?u32, p.wire_count);
    defer a.free(producer);
    @memset(producer, null);
    for (p.calls, 0..) |call, i| for (call.output) |wire| {
        producer[wire] = @intCast(i);
    };
    for (p.calls, 0..) |call, i| for (call.initial) |wire| if (producer[wire]) |prior| {
        try std.testing.expect(levels[prior] < levels[i]);
    };
    try std.testing.expectError(error.ResidentHashResourceLimit, Owned.derive(a, &.{65}, .{ .max_device_bytes = 1 }));
    try std.testing.expectError(error.ResidentHashResourceLimit, Owned.derive(a, &.{65}, .{ .max_input_bytes = 64 }));
    try std.testing.expectError(error.ResidentHashResourceLimit, Owned.derive(a, &.{65}, .{ .max_calls = 1 }));
}
