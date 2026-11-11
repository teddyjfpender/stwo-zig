//! Source witness for the positive residue certificate. Free private values are
//! canonical hint writers; inverse/product predicates and literal SSA reads are
//! separate obligations. No native correction or host result bit is authority.
const std = @import("std");
const S = @import("spec.zig");
const Generic = @import("../bn254_dense/row.zig");
const H = @import("../bn254_hint/source.zig");
const HW = @import("../bn254_hint/witness.zig");
pub const ROM = S.program();
pub fn Layout(comptime kind: S.Kind) type {
    return Generic.LayoutFor(S, kind);
}
pub const Input = struct { z: [12]u256, seed: [12]u256, c: [6]u256, inverse2: [12]u256 };
pub const Witness = struct {
    allocator: std.mem.Allocator,
    input: Input,
    initial: [S.INITIAL]u256,
    values: [S.VALUES]u256,
    hints: [S.PRIVATE_HINTS]H.Row,
    square_main: []u32,
    multiply_main: []u32,
    frobenius_main: []u32,
    pub fn init(a: std.mem.Allocator, input: Input) !Witness {
        const square = try a.alloc(u32, S.SQUARE_ROWS * Layout(.square).MAIN);
        errdefer a.free(square);
        const multiply = try a.alloc(u32, S.MULTIPLY_ROWS * Layout(.multiply).MAIN);
        errdefer a.free(multiply);
        const frobenius = try a.alloc(u32, S.FROBENIUS_ROWS * Layout(.frobenius).MAIN);
        errdefer a.free(frobenius);
        var self = Witness{ .allocator = a, .input = input, .initial = undefined, .values = @splat(0), .hints = undefined, .square_main = square, .multiply_main = multiply, .frobenius_main = frobenius };
        for (input.z, 0..) |value, i| {
            if (value >= S.B.BN254_P) return error.NonCanonicalResidueZ;
            self.initial[i] = value;
        }
        @memcpy(self.initial[12..], &S.Frobenius.POOL);
        @memcpy(self.values[0..S.INITIAL], &self.initial);
        var hint_values: [S.PRIVATE_HINTS]u256 = undefined;
        @memcpy(hint_values[0..12], &input.seed);
        @memcpy(hint_values[12..18], &input.c);
        @memcpy(hint_values[18..30], &input.inverse2);
        for (hint_values, &self.hints, 0..) |value, *row, i| {
            row.* = try HW.fill(value);
            self.values[S.INITIAL + i] = value;
        }
        self.execute();
        return self;
    }
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.square_main);
        self.allocator.free(self.multiply_main);
        self.allocator.free(self.frobenius_main);
        self.* = undefined;
    }
    pub fn bank(self: *const Witness, comptime kind: S.Kind) []u32 {
        return switch (kind) {
            .square => self.square_main,
            .multiply => self.multiply_main,
            .frobenius => self.frobenius_main,
        };
    }
    fn operands(self: *const Witness, comptime kind: S.Kind, node: S.Node) [S.inputs(kind)]u256 {
        var input: [S.inputs(kind)]u256 = undefined;
        for (node.input[0..S.inputs(kind)], &input) |id, *value| value.* = self.values[id];
        return input;
    }
    fn write(self: *Witness, comptime kind: S.Kind, comptime opcode: usize, index: usize, input: *const [S.inputs(kind)]u256) void {
        const nodes = switch (kind) {
            .square => ROM.squares[0..],
            .multiply => ROM.multiplies[0..],
            .frobenius => ROM.frobenius[0..],
        };
        const node = nodes[index];
        std.debug.assert(node.opcode == opcode);
        const L = Layout(kind);
        const row = L.fill(opcode, input);
        @memcpy(self.bank(kind)[index * L.MAIN ..][0..L.MAIN], &row);
        self.values[node.writer] = @intCast(L.read(&row, L.OUTPUT, 32));
    }
    fn operation(self: *Witness, comptime kind: S.Kind, op: S.Operation, scale_override: ?*const [12]u256) void {
        const nodes = switch (kind) {
            .square => ROM.squares[0..],
            .multiply => ROM.multiplies[0..],
            .frobenius => ROM.frobenius[0..],
        };
        inline for (0..12) |coordinate| {
            const index = op.row_start + coordinate;
            const node = nodes[index];
            var input = self.operands(kind, node);
            if (kind == .multiply) if (scale_override) |scale| {
                @memcpy(input[12..24], scale);
            };
            if (kind == .frobenius) {
                // Power is source-owned and there are exactly three calls.
                switch (op.frobenius_power) {
                    1 => self.write(kind, coordinate, index, &input),
                    2 => self.write(kind, 12 + coordinate, index, &input),
                    3 => self.write(kind, 24 + coordinate, index, &input),
                    else => unreachable,
                }
            } else self.write(kind, coordinate, index, &input);
        }
    }
    fn execute(self: *Witness) void {
        for (ROM.operations) |op| switch (op.kind) {
            .square => self.operation(.square, op, null),
            .multiply => self.operation(.multiply, op, null),
            .frobenius => self.operation(.frobenius, op, null),
        };
    }
    /// Complete off-subfield attack: all field products and both ONE endpoints
    /// remain valid, but c_high bytes falsely read the immutable ZERO SSA IDs.
    pub fn injectOffSubfieldForTesting(self: *Witness, full_scale: *const [12]u256) void {
        if (!@import("builtin").is_test) @compileError("test-only off-subfield injection");
        for (ROM.operations) |op| switch (op.kind) {
            .square => self.operation(.square, op, null),
            .frobenius => self.operation(.frobenius, op, null),
            .multiply => self.operation(.multiply, op, if (op.output[0] == ROM.scaled[0]) full_scale else null),
        };
    }
    pub fn rowAt(self: *const Witness, comptime kind: S.Kind, index: usize) Layout(kind).Row {
        const L = Layout(kind);
        var row_: L.Row = undefined;
        @memcpy(&row_, self.bank(kind)[index * L.MAIN ..][0..L.MAIN]);
        return row_;
    }
    pub fn output(self: *const Witness, ids: S.Vector) [12]u256 {
        var out: [12]u256 = undefined;
        for (ids, &out) |id, *value| value.* = self.values[id];
        return out;
    }
    pub fn one(value: [12]u256) bool {
        if (value[0] != 1) return false;
        for (value[1..]) |v| if (v != 0) return false;
        return true;
    }
    pub fn endpointsOne(self: *const Witness) bool {
        return one(self.output(ROM.inverse_check)) and one(self.output(ROM.final));
    }
    pub fn hintsCanonical(self: *const Witness) bool {
        for (&self.hints, 0..) |*row_, i| if (!HW.valid(row_, .{ 1, @intCast(S.INITIAL + i), 1 })) return false;
        return true;
    }
    pub fn sourceReadsConsistent(self: *const Witness) bool {
        if (self.values[S.ZERO] != 0 or self.values[S.ONE] != 1) return false;
        inline for (.{ S.Kind.square, S.Kind.multiply, S.Kind.frobenius }) |kind| {
            const nodes = switch (kind) {
                .square => ROM.squares[0..],
                .multiply => ROM.multiplies[0..],
                .frobenius => ROM.frobenius[0..],
            };
            const L = Layout(kind);
            for (nodes, 0..) |node, index| {
                const row_ = self.rowAt(kind, index);
                for (node.input[0..S.inputs(kind)], 0..) |id, slot| if (L.read(&row_, L.INPUT + 32 * slot, 32) != self.values[id]) return false;
                if (L.read(&row_, L.OUTPUT, 32) != self.values[node.writer]) return false;
            }
        }
        return true;
    }
    pub fn arithmeticValid(self: *const Witness) bool {
        inline for (.{ S.Kind.square, S.Kind.multiply, S.Kind.frobenius }) |kind| {
            const nodes = switch (kind) {
                .square => ROM.squares[0..],
                .multiply => ROM.multiplies[0..],
                .frobenius => ROM.frobenius[0..],
            };
            inline for (0..comptime S.rows(kind)) |opcode| for (nodes, 0..) |node, index| if (node.opcode == opcode) {
                const row_ = self.rowAt(kind, index);
                if (!Layout(kind).valid(opcode, &row_)) return false;
            };
        }
        return true;
    }
    pub fn satisfied(self: *const Witness) bool {
        return self.hintsCanonical() and self.sourceReadsConsistent() and self.arithmeticValid() and self.endpointsOne();
    }
};
