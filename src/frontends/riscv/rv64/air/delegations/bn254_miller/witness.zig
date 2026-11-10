//! Canonical scalar source interpreter; no wide physical banks or native flags.
const std = @import("std");
const S = @import("spec.zig");
pub const ROM = S.program();
pub fn opcodes(comptime kind: S.Kind) usize {
    return switch (kind) {
        .g1 => 4,
        .scale => 3,
        .prep_double => S.Prep.rows(.doubling),
        .prep_add => S.Prep.rows(.addition),
        .square, .sparse => 12,
    };
}
fn evaluate(comptime kind: S.Kind, comptime opcode: usize, values: []const u256, node: S.Node) u256 {
    var pos: S.B.Big = 0;
    var neg: S.B.Big = 0;
    inline for (comptime S.terms(kind, opcode)) |term| if (term.a == .in) {
        const a = values[node.input[term.a.in]];
        const b = if (term.b) |operand| values[node.input[operand.in]] else 1;
        const magnitude = @as(S.B.Big, a) * b * @as(u32, @intCast(@abs(term.coef)));
        if (term.coef > 0) pos += magnitude else neg += magnitude;
    };
    return @intCast((pos % S.B.BN254_P + S.B.BN254_P - neg % S.B.BN254_P) % S.B.BN254_P);
}
pub fn output(values: []const u256, node: S.Node) u256 {
    @setEvalBranchQuota(1_000_000);
    inline for (comptime std.meta.tags(S.Kind)) |kind| if (node.kind == kind) {
        inline for (0..comptime opcodes(kind)) |opcode| if (node.opcode == opcode) return evaluate(kind, opcode, values, node);
    };
    unreachable;
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    initial: [S.INITIAL]u256,
    values: []u256,
    pub fn init(a: std.mem.Allocator, input: S.Input) !Witness {
        const initial = try S.initialValues(input);
        const values = try a.alloc(u256, S.VALUES);
        errdefer a.free(values);
        @memcpy(values[0..S.INITIAL], &initial);
        for (ROM.nodes) |node| values[node.writer] = output(values, node);
        return .{ .allocator = a, .initial = initial, .values = values };
    }
    pub fn deinit(w: *Witness) void {
        w.allocator.free(w.values);
        w.* = undefined;
    }
    pub const Mutation = enum { line_order, line_sign, preparation_state };
    /// Coherently replay every later writer after one source-authority forgery.
    /// The ordinary checker still evaluates the immutable unmodified ROM.
    pub fn corruptSourceForTesting(w: *Witness, mutation: Mutation) void {
        if (!@import("builtin").is_test) @compileError("test-only source forgery");
        const target = if (mutation == .preparation_state) ROM.prep_base[0] else ROM.lines[0].scaled[0];
        for (ROM.nodes) |node| {
            var forged = node;
            if (node.writer == target) switch (mutation) {
                .line_order => forged.input[0] = ROM.lines[4].raw[0],
                .line_sign => forged.opcode = 2,
                .preparation_state => {},
            };
            w.values[node.writer] = output(w.values, forged);
            if (mutation == .preparation_state and node.writer == target) w.values[node.writer] = (w.values[node.writer] + 1) % S.B.BN254_P;
        }
    }
    pub fn result(w: *const Witness) [12]u256 {
        var out: [12]u256 = undefined;
        for (ROM.output, &out) |id, *v| v.* = w.values[id];
        return out;
    }
    pub fn satisfied(w: *const Witness) bool {
        if (!std.mem.eql(u256, w.values[0..S.INITIAL], &w.initial)) return false;
        for (ROM.nodes) |node| {
            if (w.values[node.writer] >= S.B.BN254_P or output(w.values, node) != w.values[node.writer]) return false;
            if (node.must_zero and w.values[node.writer] != 0) return false;
        }
        return true;
    }
};
