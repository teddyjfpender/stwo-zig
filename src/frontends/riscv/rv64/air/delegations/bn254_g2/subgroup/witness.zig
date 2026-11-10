//! Source-only checked witness interpreter. Canonical hints are existential
//! writers; no hint is valid until immutable zero assertions are checked.
const std = @import("std");
const S = @import("spec.zig");
const Generic = @import("../../bn254_dense/row.zig");
pub const ROM = S.program();
pub const Layout = Generic.LayoutFor(S, .quadratic);
fn inverse(value: u256) !u256 {
    if (value == 0) return error.SubgroupZeroDenominator;
    var t: i512 = 0;
    var next: i512 = 1;
    var r: u256 = S.B.BN254_P;
    var nr = value;
    while (nr != 0) {
        const q = r / nr;
        const replacement = t - @as(i512, q) * next;
        t = next;
        next = replacement;
        const rest = r % nr;
        r = nr;
        nr = rest;
    }
    if (r != 1) return error.SubgroupZeroDenominator;
    return @intCast(@mod(t, @as(i512, S.B.BN254_P)));
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    initial: [S.INITIAL]u256,
    values: [S.INITIAL + S.MAX_NODES]u256,
    rows: []u32,
    pub fn init(a: std.mem.Allocator, q: [2][2]u256) !Witness {
        var result = try build(a, q, null);
        errdefer result.deinit();
        try result.validate(q);
        return result;
    }
    pub fn candidateForTesting(a: std.mem.Allocator, q: [2][2]u256) !Witness {
        if (!@import("builtin").is_test) @compileError("unchecked candidate fixture is test-only");
        return build(a, q, null);
    }
    pub fn withHintsForTesting(a: std.mem.Allocator, q: [2][2]u256, hints: []const u256) !Witness {
        if (!@import("builtin").is_test) @compileError("unchecked hint fixture is test-only");
        return build(a, q, hints);
    }
    fn build(a: std.mem.Allocator, q: [2][2]u256, hints: ?[]const u256) !Witness {
        const initial = try S.initialValues(q);
        if (hints) |given| if (given.len != ROM.hints) return error.SubgroupHintCount;
        const data = try a.alloc(u32, ROM.count * Layout.MAIN);
        errdefer a.free(data);
        @memset(data, 0);
        var self = Witness{ .allocator = a, .initial = initial, .values = @splat(0), .rows = data };
        @memcpy(self.values[0..S.INITIAL], &initial);
        var at: usize = 0;
        for (ROM.nodes[0..ROM.count], 0..) |node, index| {
            if (node.op == .hint_norm_inverse) {
                const value = if (hints) |given| given[at] else try inverse(self.values[node.input[0]]);
                if (value >= S.B.BN254_P) return error.NonCanonicalSubgroupHint;
                self.values[node.writer] = value;
                at += 1;
            } else self.write(node, index);
        }
        std.debug.assert(at == ROM.hints);
        return self;
    }
    fn operands(self: *const Witness, node: S.Node) [7]u256 {
        var values: [7]u256 = @splat(0);
        for (node.input[0..S.arity(node.op)], 0..) |id, i| values[i] = self.values[id];
        return values;
    }
    fn write(self: *Witness, node: S.Node, index: usize) void {
        const input = self.operands(node);
        switch (node.op) {
            .hint_norm_inverse => unreachable,
            inline else => |opcode| {
                const encoded = Layout.fill(@intFromEnum(opcode), &input);
                @memcpy(self.rows[index * Layout.MAIN ..][0..Layout.MAIN], &encoded);
                self.values[node.writer] = Layout.output(@intFromEnum(opcode), &input);
            },
        }
    }
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }
    pub fn row(self: *const Witness, index: usize) Layout.Row {
        var out: Layout.Row = undefined;
        @memcpy(&out, self.rows[index * Layout.MAIN ..][0..Layout.MAIN]);
        return out;
    }
    pub fn validateRows(self: *const Witness) !void {
        for (self.initial) |value| if (value >= S.B.BN254_P) return error.NonCanonicalSubgroupInput;
        for (ROM.nodes[0..ROM.count], 0..) |node, index| {
            if (node.op == .hint_norm_inverse) {
                // Source contract: future physical hint row must enforce BYTE,
                // canonical distance+borrow, exact writer ID and immutable fanout.
                if (self.values[node.writer] >= S.B.BN254_P) return error.NonCanonicalSubgroupHint;
                continue;
            }
            const encoded = self.row(index);
            const input = self.operands(node);
            for (input, 0..) |value, i| if (Layout.read(&encoded, Layout.INPUT + 32 * i, 32) != value) return error.SubgroupSsaReadMismatch;
            if (Layout.read(&encoded, Layout.OUTPUT, 32) != self.values[node.writer]) return error.SubgroupSsaWriterMismatch;
            switch (node.op) {
                .hint_norm_inverse => unreachable,
                inline else => |opcode| if (!Layout.valid(@intFromEnum(opcode), &encoded)) return error.SubgroupArithmeticConstraint,
            }
        }
    }
    pub fn validate(self: *const Witness, expected_q: [2][2]u256) !void {
        const expected = try S.initialValues(expected_q);
        if (!std.mem.eql(u256, &expected, &self.initial) or !std.mem.eql(u256, &expected, self.values[0..S.INITIAL])) return error.SubgroupInitialAuthority;
        try self.validateRows();
        for (ROM.assertions[0..ROM.assertion_count]) |id| if (self.values[id] != 0) return error.SubgroupZeroAssertion;
    }
    pub fn finalPoint(self: *const Witness) [2][2]u256 {
        var result: [2][2]u256 = undefined;
        for (ROM.final_point, &result) |ids, *pair| {
            for (ids, pair) |id, *value| value.* = self.values[id];
        }
        return result;
    }
    pub fn hintDigest(self: *const Witness) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        for (ROM.nodes[0..ROM.count]) |node| if (node.op == .hint_norm_inverse) {
            var bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &bytes, self.values[node.writer], .little);
            h.update(&bytes);
        };
        return h.finalResult();
    }
    /// All later arithmetic is coherently regenerated after a field-congruent
    /// slope+P forgery. Canonical writer constraints still reject its first row.
    pub fn corruptSlopeForTesting(self: *Witness) !void {
        if (!@import("builtin").is_test) @compileError("test-only forgery");
        var found = false;
        for (ROM.nodes[0..ROM.count], 0..) |node, index| {
            if (!found) {
                if (node.op != .lambda_double_real) continue;
                const input = self.operands(node);
                const forged = Layout.congruentForgeryForTesting(@intFromEnum(S.Op.lambda_double_real), &input);
                @memcpy(self.rows[index * Layout.MAIN ..][0..Layout.MAIN], &forged);
                self.values[node.writer] += S.B.BN254_P;
                found = true;
            } else if (node.op == .hint_norm_inverse) self.values[node.writer] = try inverse(self.values[node.input[0]]) else self.write(node, index);
        }
        std.debug.assert(found);
    }
};
