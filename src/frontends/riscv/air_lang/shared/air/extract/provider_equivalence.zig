//! Shared cold comparison of typed provider roots and ordered lookup events.
const std = @import("std");
const symbolic = @import("symbolic.zig");
const expressions = @import("canonical_digest.zig");
const S = symbolic.Scalar;
pub const Error = error{ProviderSpecializationMismatch};
pub const Comparison = struct {
    allocator: std.mem.Allocator,
    digests: [][32]u8,
    pub fn init(allocator: std.mem.Allocator, arena: *const symbolic.Arena) !Comparison {
        try arena.checkAllocation();
        return .{ .allocator = allocator, .digests = try expressions.commutativeExpressions(allocator, arena.nodes.items, arena.names.items.len) };
    }
    pub fn deinit(self: *Comparison) void {
        self.allocator.free(self.digests);
        self.* = undefined;
    }
    pub fn require(self: *const Comparison, actual: S, expected: S) Error!void {
        if (actual.id >= self.digests.len or expected.id >= self.digests.len or
            !std.mem.eql(u8, &self.digests[actual.id], &self.digests[expected.id])) return error.ProviderSpecializationMismatch;
    }
    pub fn roots(self: *const Comparison, actual: []const S, expected: []const S) Error!void {
        if (actual.len != expected.len) return error.ProviderSpecializationMismatch;
        for (actual, expected) |a, e| try self.require(a, e);
    }
    pub fn lookups(self: *const Comparison, actual: anytype, expected: @TypeOf(actual)) Error!void {
        if (actual.len != expected.len or actual.batch_size != expected.batch_size) return error.ProviderSpecializationMismatch;
        for (actual.entries[0..actual.len], expected.entries[0..expected.len]) |a, e| {
            if (a.domain != e.domain or a.arity != e.arity or a.role != e.role or a.access_ordinal != e.access_ordinal) return error.ProviderSpecializationMismatch;
            try self.require(a.numerator, e.numerator);
            try self.roots(a.values[0..a.arity], e.values[0..e.arity]);
        }
    }
};
