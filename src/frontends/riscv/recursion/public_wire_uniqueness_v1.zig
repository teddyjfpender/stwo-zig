//! Bounded duplicate detection without mutating transcript order or allocating.
//! Canonical sorted schedules take one pass; arbitrary legacy order remains
//! accepted and uses deterministic heap sorting of compact private indices.
const std = @import("std");

pub fn For(comptime Wire: type, comptime capacity: usize) type {
    if (capacity == 0 or capacity > 65536) @compileError("public wire index capacity exceeds u16");
    return struct {
        fn key(wire: Wire) u64 {
            return (@as(u64, wire.circuit) << 32) | wire.wire;
        }
        fn lessThan(wires: []const Wire, left: u16, right: u16) bool {
            return key(wires[left]) < key(wires[right]);
        }
        pub fn unique(wires: []const Wire) bool {
            if (wires.len > capacity) return false;
            var sorted = true;
            for (wires, 0..) |wire, i| {
                if (i > 0 and key(wires[i - 1]) >= key(wire)) {
                    sorted = false;
                    break;
                }
            }
            if (sorted) return true;
            var storage: [capacity]u16 = undefined;
            const indices = storage[0..wires.len];
            for (indices, 0..) |*index, i| index.* = @intCast(i);
            std.sort.heap(u16, indices, wires, lessThan);
            for (indices[1..], indices[0 .. indices.len - 1]) |right, left| {
                if (key(wires[left]) == key(wires[right])) return false;
            }
            return true;
        }
    };
}
