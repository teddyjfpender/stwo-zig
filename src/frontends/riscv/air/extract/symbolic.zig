//! A scalar type that records the polynomial instead of evaluating it.
//!
//! `Scalar` satisfies exactly the interface the opcode semantics use -- `zero`,
//! `one`, `fromBase`, `add`, `sub`, `mul`, `neg` -- so `semantics.Families` and
//! `entry.Builder` instantiate over it unchanged. Running the shipped source
//! over this type is what makes the SMT model an extraction rather than a
//! transcription: there is no second description of the constraints to drift.
//!
//! The recorded DAG has six node kinds, matching the IR that
//! `scripts/air_uniqueness_lib/ir.py` consumes. There is deliberately no
//! division node: no constraint in `air/semantics/` inverts a value, and that
//! absence is the property that makes the polynomial encoding possible at all.
//!
//! Ownership: the caller owns an `Arena` and installs it with `begin`; every
//! `Scalar` is a *borrowed* handle into that arena and is invalid after `end`.
//! The arena is a process-global because the scalar interface has no room to
//! thread one through `S.zero()`. This is tooling, single-threaded by
//! construction, and `begin` asserts no arena is already installed.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

pub const Op = enum(u8) { constant, column, add, sub, mul, neg };

pub const Node = struct {
    op: Op,
    lhs: u32 = 0,
    rhs: u32 = 0,
    /// `constant`: the canonical M31 representative. `column`: the column index.
    value: u32 = 0,
};

pub const Arena = struct {
    nodes: std.ArrayList(Node),
    /// Column names, indexed by the `value` of a `column` node. Borrowed:
    /// every name is a comptime string literal owned by the extractor.
    names: std.ArrayList([]const u8),
    interned: std.AutoHashMap(Node, u32),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Arena {
        return .{
            .nodes = .empty,
            .names = .empty,
            .interned = std.AutoHashMap(Node, u32).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Arena) void {
        self.nodes.deinit(self.allocator);
        self.names.deinit(self.allocator);
        self.interned.deinit();
    }

    /// Hash-consed insertion. `derive()` results are reused across many
    /// constraints, so interning is what keeps the emitted DAG the size of the
    /// source rather than the size of its unfolding.
    fn intern(self: *Arena, node: Node) u32 {
        if (self.interned.get(node)) |existing| return existing;
        const id: u32 = @intCast(self.nodes.items.len);
        self.nodes.append(self.allocator, node) catch @panic("symbolic arena OOM");
        self.interned.put(node, id) catch @panic("symbolic arena OOM");
        return id;
    }

    pub fn column(self: *Arena, name: []const u8) Scalar {
        const index: u32 = @intCast(self.names.items.len);
        self.names.append(self.allocator, name) catch @panic("symbolic arena OOM");
        return .{ .id = self.intern(.{ .op = .column, .value = index }) };
    }
};

/// The installed arena. `Scalar` methods take no allocator and no context, so
/// the arena cannot be a parameter; see the module comment.
var installed: ?*Arena = null;

pub fn begin(arena: *Arena) void {
    std.debug.assert(installed == null);
    installed = arena;
}

pub fn end() void {
    std.debug.assert(installed != null);
    installed = null;
}

fn current() *Arena {
    return installed orelse @panic("symbolic scalar used outside begin/end");
}

pub const Scalar = struct {
    id: u32,

    pub fn zero() Scalar {
        return constant(0);
    }

    pub fn one() Scalar {
        return constant(1);
    }

    pub fn fromBase(value: M31) Scalar {
        return constant(value.v);
    }

    pub fn constant(value: u32) Scalar {
        return .{ .id = current().intern(.{ .op = .constant, .value = value }) };
    }

    pub fn add(self: Scalar, other: Scalar) Scalar {
        return binary(.add, self, other);
    }

    pub fn sub(self: Scalar, other: Scalar) Scalar {
        return binary(.sub, self, other);
    }

    pub fn mul(self: Scalar, other: Scalar) Scalar {
        return binary(.mul, self, other);
    }

    pub fn neg(self: Scalar) Scalar {
        return .{ .id = current().intern(.{ .op = .neg, .lhs = self.id }) };
    }

    fn binary(op: Op, lhs: Scalar, rhs: Scalar) Scalar {
        return .{ .id = current().intern(.{ .op = op, .lhs = lhs.id, .rhs = rhs.id }) };
    }
};

/// Replay every recorded node over concrete base-field column values.
///
/// This is the numeric side of the differential check: the same DAG that is
/// exported to the solver is replayed here and compared against the direct
/// QM31 run of the same source. Without it, a broken extraction would emit a
/// smaller system that the solver happily reports as unique.
///
/// One bottom-up pass, not recursion per node: interning makes the DAG heavily
/// shared, and `args` always index strictly earlier nodes, so index order is a
/// topological order. `out` is caller-owned and indexed by node id.
pub fn replay(arena: *const Arena, columns: []const M31, out: []M31) void {
    std.debug.assert(out.len == arena.nodes.items.len);
    for (arena.nodes.items, out, 0..) |node, *slot, index| {
        slot.* = switch (node.op) {
            .constant => M31.fromU64(node.value),
            .column => columns[node.value],
            .add => out[node.lhs].add(out[node.rhs]),
            .sub => out[node.lhs].sub(out[node.rhs]),
            .mul => out[node.lhs].mul(out[node.rhs]),
            .neg => M31.zero().sub(out[node.lhs]),
        };
        std.debug.assert(node.lhs < index or node.op == .constant or node.op == .column);
    }
}

test "symbolic scalar interns structurally equal subexpressions once" {
    var arena = Arena.init(std.testing.allocator);
    defer arena.deinit();
    begin(&arena);
    defer end();

    const x = arena.column("x");
    const y = arena.column("y");
    const first = x.mul(y).add(Scalar.one());
    const second = x.mul(y).add(Scalar.one());
    try std.testing.expectEqual(first.id, second.id);
    // x, y, x*y, 1, x*y+1 -- five distinct nodes for two written expressions.
    try std.testing.expectEqual(@as(usize, 5), arena.nodes.items.len);
}

test "symbolic replay reproduces field arithmetic including wraparound" {
    var arena = Arena.init(std.testing.allocator);
    defer arena.deinit();
    begin(&arena);
    defer end();

    const x = arena.column("x");
    const y = arena.column("y");
    // (x - y) * (x + y) == x^2 - y^2, checked at a point that wraps mod p.
    const expr = x.sub(y).mul(x.add(y));
    const values = [_]M31{ M31.fromCanonical(2_000_000_000), M31.fromCanonical(3) };
    const expected = values[0].mul(values[0]).sub(values[1].mul(values[1]));

    const out = try std.testing.allocator.alloc(M31, arena.nodes.items.len);
    defer std.testing.allocator.free(out);
    replay(&arena, &values, out);
    try std.testing.expect(out[expr.id].eql(expected));
}
