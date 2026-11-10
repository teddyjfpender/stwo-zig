//! Canonical writer witnesses for the immutable quadratic transition program.
//! Public input canonicality is checked here only as fixture construction; a
//! production source must prove it at its authenticated initial frontier.
const std = @import("std");
const S = @import("spec.zig");
const Generic = @import("../bn254_dense/row.zig");
pub fn Layout(comptime kind: S.Kind) type {
    return Generic.LayoutFor(S, kind);
}
pub fn Witness(comptime kind: S.Kind) type {
    return struct {
        pub const R = Layout(kind);
        initial: [S.initialCount(kind)]u256,
        values: [S.MAX_VALUES]u256,
        arithmetic: [S.rows(kind)]R.Row,
        pub fn init(input_point: S.Point, q: [2]S.FQ2) !@This() {
            var self: @This() = undefined;
            self.values = @splat(0);
            for (input_point, 0..) |p, i| for (p, 0..) |v, j| {
                if (v >= S.B.BN254_P) return error.NonCanonicalG2FixtureInput;
                self.initial[2 * i + j] = v;
            };
            if (kind == .doubling) {
                self.initial[6] = (S.B.BN254_P + 1) / 2;
                self.initial[7] = S.TWIST_B[0];
                self.initial[8] = S.TWIST_B[1];
            } else {
                for (q, 0..) |p, i| for (p, 0..) |v, j| {
                    if (v >= S.B.BN254_P) return error.NonCanonicalG2FixtureInput;
                    self.initial[6 + 2 * i + j] = v;
                };
            }
            @memcpy(self.values[0..S.initialCount(kind)], &self.initial);
            const program = comptime S.program(kind);
            inline for (0..comptime S.rows(kind)) |step| {
                const input = self.operands(step);
                self.arithmetic[step] = R.fill(step, &input);
                self.values[program.operations[step].writer] = R.output(step, &input);
            }
            return self;
        }
        pub fn operands(self: *const @This(), comptime step: usize) [S.inputs(kind)]u256 {
            var input: [S.inputs(kind)]u256 = @splat(0);
            for (comptime S.operandIds(kind, step), &input) |id, *value| if (id != S.UNUSED) {
                value.* = self.values[id];
            };
            return input;
        }
        pub fn point(self: *const @This()) S.Point {
            var out: S.Point = undefined;
            for (S.program(kind).point, 0..) |id, i| out[i / 2][i % 2] = self.values[id];
            return out;
        }
        pub fn line(self: *const @This()) [3]S.FQ2 {
            const p = S.program(kind);
            var out: [3]S.FQ2 = undefined;
            for (p.line, 0..) |id, i| {
                const coefficient = p.line_scale[i / 2];
                const scaled = @as(S.B.Big, self.values[id]) * @as(u32, @intCast(@abs(coefficient))) % S.B.BN254_P;
                out[i / 2][i % 2] = @intCast(if (coefficient < 0 and scaled != 0) S.B.BN254_P - scaled else scaled);
            }
            return out;
        }
    };
}
