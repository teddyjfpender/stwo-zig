//! Borrowed immutable fact-source capability for the opt-in checkpoint prover.
//! The callback is thread-safe, joins within the prover, and may write only its
//! output spans. It must use bounded scratch and preserve canonical field data.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
pub const Error = error{ OutOfMemory, ShapeMismatch, InvalidLayerStructure };
pub fn ForField(comptime S: type) type {
    return struct {
        context: *const anyopaque,
        variables: u32,
        read_fn: *const fn (*const anyopaque, usize, []M, []S) Error!void,
        pub fn validate(self: @This()) Error!void {
            if (self.variables == 0 or self.variables > 30) return error.InvalidLayerStructure;
        }
        pub fn len(self: @This()) usize {
            return @as(usize, 1) << @intCast(self.variables);
        }
        pub fn read(self: @This(), first: usize, n: []M, d: []S) Error!void {
            try self.validate();
            const end = std.math.add(usize, first, n.len) catch return error.ShapeMismatch;
            if (n.len != d.len or end > self.len()) return error.ShapeMismatch;
            try self.read_fn(self.context, first, n, d);
        }
    };
}
