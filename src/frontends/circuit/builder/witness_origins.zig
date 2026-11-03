//! Optional witness-generation metadata; this never defines constraints.
//! The original Circuit remains the only gate/topology authority. Explicit
//! origins distinguish external inputs from deterministic, constrained hints.
const std = @import("std");
pub const Kind = enum { seed, inverse, divide, pointwise_inverse_or_zero, pointwise_lsb };
pub const Origin = struct { out: u32, kind: Kind = .seed, a: u32 = 0, b: u32 = 0 };
pub const Permutation = enum(u8) { sort_by_u_coordinate };
pub const Metadata = struct {
    origins: std.ArrayListUnmanaged(Origin) = .empty,
    permutations: std.ArrayListUnmanaged(Permutation) = .empty,
    pub fn deinit(self: *Metadata, a: std.mem.Allocator) void {
        self.origins.deinit(a);
        self.permutations.deinit(a);
        self.* = undefined;
    }
    pub fn hint(self: *Metadata, out: u32, kind: Kind, a: u32, b: u32) !void {
        if (kind == .seed) return error.InvalidWitnessOrigin;
        var lo: usize = 0;
        var hi = self.origins.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.origins.items[mid].out < out) lo = mid + 1 else hi = mid;
        }
        if (lo == self.origins.items.len or self.origins.items[lo].out != out or self.origins.items[lo].kind != .seed) return error.InvalidWitnessOrigin;
        self.origins.items[lo] = .{ .out = out, .kind = kind, .a = a, .b = b };
    }
};
