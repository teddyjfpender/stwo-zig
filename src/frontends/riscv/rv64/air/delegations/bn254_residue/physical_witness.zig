//! Source-owned physical banks; keeps logical witness/values in the caller.
const std = @import("std");
const S = @import("spec.zig");
const P = @import("physical_spec.zig");
const W = @import("witness.zig");
const Generic = @import("../bn254_dense/row.zig");
pub const SQUARE_ROWS = S.SQUARE_ROWS + S.FROBENIUS_ROWS;
pub const MULTIPLY_ROWS = S.MULTIPLY_ROWS;
pub fn Layout(comptime kind: P.Kind) type {
    return Generic.LayoutFor(P, kind);
}
pub const Physical = struct {
    allocator: std.mem.Allocator,
    logical: *const W.Witness,
    frobenius_square: []u32,
    pub fn init(a: std.mem.Allocator, logical: *const W.Witness) !Physical {
        const out = try a.alloc(u32, S.FROBENIUS_ROWS * Layout(.square).MAIN);
        errdefer a.free(out);
        inline for (0..36) |index| {
            const node = W.ROM.frobenius[index];
            var input: [12]u256 = @splat(0);
            for (node.input[0..4], input[0..4]) |id, *value| value.* = logical.values[id];
            const row = Layout(.square).fill(12 + index, &input);
            if (Layout(.square).read(&row, Layout(.square).OUTPUT, 32) != logical.values[node.writer]) return error.FrobeniusRematerializationMismatch;
            @memcpy(out[index * Layout(.square).MAIN ..][0..Layout(.square).MAIN], &row);
        }
        return .{ .allocator = a, .logical = logical, .frobenius_square = out };
    }
    pub fn deinit(self: *Physical) void {
        self.allocator.free(self.frobenius_square);
        self.* = undefined;
    }
    pub fn main(self: *const Physical, comptime kind: P.Kind, row: usize, column: usize) u32 {
        if (kind == .multiply) return if (row < S.MULTIPLY_ROWS) self.logical.multiply_main[row * Layout(.multiply).MAIN + column] else 0;
        if (row < S.SQUARE_ROWS) return self.logical.square_main[row * Layout(.square).MAIN + column];
        return if (row < SQUARE_ROWS) self.frobenius_square[(row - S.SQUARE_ROWS) * Layout(.square).MAIN + column] else 0;
    }
    pub fn nodeAt(comptime kind: P.Kind, row: usize) S.Node {
        if (kind == .multiply) return W.ROM.multiplies[row];
        if (row < S.SQUARE_ROWS) return W.ROM.squares[row];
        var source = W.ROM.frobenius[row - S.SQUARE_ROWS];
        source.opcode += 12;
        return source;
    }
};
