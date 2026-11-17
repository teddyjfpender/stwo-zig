//! Placeholder-clock substitution over the service shard's canonical RAM states.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Checkpoint = front.rv64.checkpoint.Checkpoint;
const Shard = @import("collector.zig").Shard;

fn containsState(comptime T: type) bool {
    if (T == A.memory.closed_ram.types.State) return true;
    return switch (@typeInfo(T)) {
        .@"struct" => |info| blk: {
            inline for (info.fields) |field| if (containsState(field.type)) break :blk true;
            break :blk false;
        },
        .array => |info| containsState(info.child),
        .pointer => |info| info.size == .slice and containsState(info.child),
        else => false,
    };
}
fn patchValue(comptime T: type, value: *T, global: []const A.memory.closed_ram.types.State) void {
    if (comptime !containsState(T)) return;
    if (T == A.memory.closed_ram.types.State) {
        if (value.epoch == 0 and value.tick != 0) {
            const g = global[value.tick - 1];
            value.epoch = g.epoch;
            value.tick = g.tick;
        }
        return;
    }
    switch (@typeInfo(T)) {
        .@"struct" => |info| inline for (info.fields) |field| patchValue(field.type, &@field(value, field.name), global),
        .array => |info| for (value) |*item| patchValue(info.child, item, global),
        .pointer => |info| for (value.*) |*item| patchValue(info.child, item, global),
        else => {},
    }
}
/// Replaces every placeholder clock in `shard` (every `State` field, found by
/// reflection) with the clock of the global state it stands for.
pub fn patchShard(shard: *Shard, global: []const A.memory.closed_ram.types.State) void {
    patchValue(Shard, shard, global);
}

pub fn startWord(cp: *const Checkpoint, address: u64) u64 {
    const P: u64 = front.rv64.memory.PAGE_SIZE;
    var bytes: [8]u8 = undefined;
    if (address % P <= P - 8) {
        const page = cp.find(address / P) orelse return 0;
        const offset: usize = @intCast(address % P);
        return std.mem.readInt(u64, page[offset..][0..8], .little);
    }
    for (&bytes, 0..) |*byte, i| {
        const at = address +% i;
        byte.* = if (cp.find(at / P)) |page| page[@intCast(at % P)] else 0;
    }
    return std.mem.readInt(u64, &bytes, .little);
}
