//! Owned complete preparation witness. Builds both arithmetic tables in the
//! true immutable transition order while retaining one shared global value DAG.
const std = @import("std");
const S = @import("spec.zig");
const Generic = @import("../../bn254_dense/row.zig");
pub const ROM = S.program();
pub fn Layout(comptime kind: S.Kind) type {
    return Generic.LayoutFor(S, kind);
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    initial: [S.INITIAL]u256,
    values: [S.VALUES]u256,
    double_main: []u32,
    add_main: []u32,
    pub fn init(a: std.mem.Allocator, q: [2]S.FQ2) !Witness {
        const initial = try S.initialValues(q);
        const double_main = try a.alloc(u32, S.DOUBLE_ROWS * Layout(.doubling).MAIN);
        errdefer a.free(double_main);
        const add_main = try a.alloc(u32, S.ADD_ROWS * Layout(.addition).MAIN);
        errdefer a.free(add_main);
        var self = Witness{ .allocator = a, .initial = initial, .values = @splat(0), .double_main = double_main, .add_main = add_main };
        @memcpy(self.values[0..S.INITIAL], &initial);
        inline for (0..S.PREFIX) |opcode| self.write(.doubling, opcode, opcode);
        for (ROM.transitions) |step_| switch (step_.kind) {
            .doubling => self.transition(.doubling, step_.row_start),
            .addition => self.transition(.addition, step_.row_start),
        };
        return self;
    }
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.double_main);
        self.allocator.free(self.add_main);
        self.* = undefined;
    }
    fn operands(self: *const Witness, comptime kind: S.Kind, node: S.Node) [S.inputs(kind)]u256 {
        var input: [S.inputs(kind)]u256 = @splat(0);
        for (node.input[0..S.inputs(kind)], &input) |id, *value| if (id != S.UNUSED) {
            value.* = self.values[id];
        };
        return input;
    }
    fn write(self: *Witness, comptime kind: S.Kind, comptime opcode: usize, row_index: usize) void {
        const node = if (kind == .doubling) ROM.doubles[row_index] else ROM.adds[row_index];
        std.debug.assert(node.opcode == opcode);
        const input = self.operands(kind, node);
        const L = Layout(kind);
        const encoded_row = L.fill(opcode, &input);
        const target = if (kind == .doubling) self.double_main else self.add_main;
        @memcpy(target[row_index * L.MAIN ..][0..L.MAIN], &encoded_row);
        self.values[node.writer] = L.output(opcode, &input);
    }
    fn transition(self: *Witness, comptime kind: S.Kind, row_start: usize) void {
        inline for (0..comptime S.Base.rows(kind)) |step| self.write(kind, if (kind == .doubling) S.PREFIX + step else step, row_start + step);
    }
    pub fn row(self: *const Witness, comptime kind: S.Kind, index: usize) Layout(kind).Row {
        const L = Layout(kind);
        const main = if (kind == .doubling) self.double_main else self.add_main;
        var result: L.Row = undefined;
        @memcpy(&result, main[index * L.MAIN ..][0..L.MAIN]);
        return result;
    }
    /// Coherent field-congruence forgery control: propagate the noncanonical
    /// negative-Q writer into every later read, preserving all modular outputs.
    pub fn corruptPrefixForTesting(self: *Witness) void {
        if (!@import("builtin").is_test) @compileError("test-only canonicality attack");
        const node = ROM.doubles[0];
        const input = self.operands(.doubling, node);
        const L = Layout(.doubling);
        const forged = L.congruentForgeryForTesting(0, &input);
        @memcpy(self.double_main[0..L.MAIN], &forged);
        self.values[node.writer] += S.B.BN254_P;
        inline for (1..S.PREFIX) |opcode| self.write(.doubling, opcode, opcode);
        for (ROM.transitions) |step_| switch (step_.kind) {
            .doubling => self.transition(.doubling, step_.row_start),
            .addition => self.transition(.addition, step_.row_start),
        };
    }
    pub fn finalPoint(self: *const Witness) S.Base.Point {
        var out: S.Base.Point = undefined;
        for (ROM.final_point, 0..) |id, i| out[i / 2][i % 2] = self.values[id];
        return out;
    }
    pub fn line(self: *const Witness, index: usize) [3]S.FQ2 {
        const transition_ = ROM.transitions[index];
        var out: [3]S.FQ2 = undefined;
        for (transition_.line, 0..) |id, i| {
            const coefficient = transition_.line_scale[i / 2];
            const magnitude = @as(S.B.Big, self.values[id]) * @as(u32, @intCast(@abs(coefficient))) % S.B.BN254_P;
            out[i / 2][i % 2] = @intCast(if (coefficient < 0 and magnitude != 0) S.B.BN254_P - magnitude else magnitude);
        }
        return out;
    }
    pub fn linesDigest(self: *const Witness) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (0..S.TRANSITIONS) |index| for (self.line(index)) |pair| for (pair) |value| {
            var bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &bytes, value, .little);
            h.update(&bytes);
        };
        return h.finalResult();
    }
};
