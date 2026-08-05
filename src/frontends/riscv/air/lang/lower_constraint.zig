//! Fallible `compat-v1` lowering of typed direct constraints.
//!
//! The target node vocabulary is the exact six-operation production symbolic
//! DAG, but construction does not use its process-global, panic-on-OOM arena.
//! Inputs are emitted in physical main-column order followed by `is_active`;
//! only the dependency closure of ordered direct roots is lowered. Add and
//! multiply operands are canonicalized so comparison does not depend on the
//! production builder's incidental commutative operand order.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const m31 = @import("stwo_core").fields.m31;
const symbolic = @import("../extract/symbolic.zig");
const compat_layout = @import("compat_layout.zig");
const shadow_program = @import("shadow_program.zig");
const types = @import("types.zig");

const no_node = std.math.maxInt(u32);

pub const ValidationError = error{
    DuplicateNode,
    InvalidColumnLayout,
    InvalidConstant,
    InvalidNode,
    InvalidRoot,
    NonCanonicalNode,
};

pub const LowerError = compat_layout.Error || std.mem.Allocator.Error || ValidationError || error{
    CountOverflow,
    MissingOperand,
    UnmappedInput,
    UnsupportedNode,
};

pub const ReplayError = ValidationError || error{
    InvalidReplayBuffer,
    InvalidReplayColumns,
};

pub const Program = struct {
    allocator: std.mem.Allocator,
    nodes: []symbolic.Node,
    roots: []u32,
    column_count: usize,

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.roots);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn columnCount(self: *const Program) usize {
        return self.column_count;
    }

    /// Allocation-free structural validation independent of constructor
    /// success. Canonical uniqueness is quadratic in node count by design;
    /// validation is cold and current family DAGs contain fewer than 500 nodes.
    pub fn validate(self: *const Program) ValidationError!void {
        if (self.column_count < 2 or
            self.nodes.len < self.column_count or
            self.roots.len == 0)
        {
            return error.InvalidColumnLayout;
        }
        for (self.nodes, 0..) |node, index| {
            if (index < self.column_count) {
                const expected = symbolic.Node{
                    .op = .column,
                    .value = @intCast(index),
                };
                if (!std.meta.eql(node, expected))
                    return error.InvalidColumnLayout;
            } else switch (node.op) {
                .column => return error.InvalidColumnLayout,
                .constant => if (node.value >= m31.Modulus)
                    return error.InvalidConstant,
                .add, .sub, .mul => {
                    if (node.lhs >= index or node.rhs >= index)
                        return error.InvalidNode;
                    if ((node.op == .add or node.op == .mul) and
                        node.rhs < node.lhs)
                    {
                        return error.NonCanonicalNode;
                    }
                },
                .neg => if (node.lhs >= index)
                    return error.InvalidNode,
            }
            for (self.nodes[0..index]) |prior| {
                if (std.meta.eql(node, prior)) return error.DuplicateNode;
            }
        }
        for (self.roots) |root| {
            if (root >= self.nodes.len) return error.InvalidRoot;
        }
    }

    pub fn replay(
        self: *const Program,
        columns: []const M31,
        out: []M31,
    ) ReplayError!void {
        try self.validate();
        if (columns.len != self.columnCount())
            return error.InvalidReplayColumns;
        if (out.len != self.nodes.len) return error.InvalidReplayBuffer;
        for (self.nodes, out) |node, *value| {
            value.* = switch (node.op) {
                .constant => M31.fromCanonical(node.value),
                .column => columns[node.value],
                .add => out[node.lhs].add(out[node.rhs]),
                .sub => out[node.lhs].sub(out[node.rhs]),
                .mul => out[node.lhs].mul(out[node.rhs]),
                .neg => out[node.lhs].neg(),
            };
        }
    }
};

pub fn lower(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) LowerError!Program {
    try layout.validate(imported);
    const typed_nodes = imported.imported.arena.nodesView();
    const reachable = try allocator.alloc(bool, typed_nodes.len);
    defer allocator.free(reachable);
    @memset(reachable, false);
    const mapped = try allocator.alloc(u32, typed_nodes.len);
    defer allocator.free(mapped);
    @memset(mapped, no_node);

    for (imported.direct_constraints) |constraint_id| {
        const constraint = imported.imported.arena.constraint(constraint_id) orelse
            return error.InvalidConstraintMap;
        reachable[types.idIndex(constraint.root)] = true;
    }
    var reverse = typed_nodes.len;
    while (reverse > 0) {
        reverse -= 1;
        if (!reachable[reverse]) continue;
        const op = typed_nodes[reverse].key.op;
        switch (op) {
            .constant, .input, .hint_output, .call_output => {},
            .add, .sub, .mul => |binary| {
                try markOperand(reachable, reverse, binary.lhs);
                try markOperand(reachable, reverse, binary.rhs);
            },
            .neg => |value| try markOperand(reachable, reverse, value),
            .select => |selection| {
                try markOperand(reachable, reverse, selection.selector);
                try markOperand(reachable, reverse, selection.when_true);
                try markOperand(reachable, reverse, selection.when_false);
            },
        }
    }

    var target = CanonicalArena.init(allocator);
    defer target.deinit();
    for (layout.main()) |column| {
        const lowered = try target.intern(.{
            .op = .column,
            .value = column.reference.local_index,
        });
        const value_index = types.idIndex(column.value);
        if (value_index >= mapped.len or mapped[value_index] != no_node)
            return error.InvalidMainLayout;
        mapped[value_index] = lowered;
    }
    const selector_column = std.math.cast(u32, layout.main().len) orelse
        return error.CountOverflow;
    const lowered_selector = try target.intern(.{
        .op = .column,
        .value = selector_column,
    });
    const selector_index = types.idIndex(imported.selector);
    if (selector_index >= mapped.len or mapped[selector_index] != no_node)
        return error.InvalidPreprocessedLayout;
    mapped[selector_index] = lowered_selector;

    for (typed_nodes, 0..) |node, index| {
        if (!reachable[index] or mapped[index] != no_node) continue;
        mapped[index] = switch (node.key.op) {
            .constant => |constant| try target.intern(.{
                .op = .constant,
                .value = switch (constant) {
                    .field => |value| value,
                    .unsigned => |value| if (node.key.ty.isFieldScalar())
                        value
                    else
                        return error.UnsupportedNode,
                },
            }),
            .input => return error.UnmappedInput,
            .add => |binary| try target.binary(
                .add,
                try operand(mapped, binary.lhs),
                try operand(mapped, binary.rhs),
            ),
            .sub => |binary| try target.binary(
                .sub,
                try operand(mapped, binary.lhs),
                try operand(mapped, binary.rhs),
            ),
            .mul => |binary| try target.binary(
                .mul,
                try operand(mapped, binary.lhs),
                try operand(mapped, binary.rhs),
            ),
            .neg => |value| try target.intern(.{
                .op = .neg,
                .lhs = try operand(mapped, value),
            }),
            .select => |selection| try target.select(
                try operand(mapped, selection.selector),
                try operand(mapped, selection.when_true),
                try operand(mapped, selection.when_false),
            ),
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }

    const roots = try allocator.alloc(u32, imported.direct_constraints.len);
    errdefer allocator.free(roots);
    for (imported.direct_constraints, roots) |constraint_id, *root| {
        const constraint = imported.imported.arena.constraint(constraint_id) orelse
            return error.InvalidConstraintMap;
        root.* = try operand(mapped, constraint.root);
    }
    const nodes = try target.nodes.toOwnedSlice(allocator);
    errdefer allocator.free(nodes);
    const column_count = std.math.add(usize, layout.main().len, 1) catch
        return error.CountOverflow;
    var result = Program{
        .allocator = allocator,
        .nodes = nodes,
        .roots = roots,
        .column_count = column_count,
    };
    try result.validate();
    return result;
}

fn markOperand(
    reachable: []bool,
    current: usize,
    value: types.ValueId,
) error{MissingOperand}!void {
    const index = types.idIndex(value);
    if (index >= current or index >= reachable.len) return error.MissingOperand;
    reachable[index] = true;
}

fn operand(mapped: []const u32, value: types.ValueId) error{MissingOperand}!u32 {
    const index = types.idIndex(value);
    if (index >= mapped.len or mapped[index] == no_node)
        return error.MissingOperand;
    return mapped[index];
}

const CanonicalArena = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(symbolic.Node),
    interned: std.AutoHashMap(symbolic.Node, u32),

    fn init(allocator: std.mem.Allocator) CanonicalArena {
        return .{
            .allocator = allocator,
            .nodes = .empty,
            .interned = std.AutoHashMap(symbolic.Node, u32).init(allocator),
        };
    }

    fn deinit(self: *CanonicalArena) void {
        self.interned.deinit();
        self.nodes.deinit(self.allocator);
    }

    fn intern(
        self: *CanonicalArena,
        node: symbolic.Node,
    ) (std.mem.Allocator.Error || error{CountOverflow})!u32 {
        if (self.interned.get(node)) |existing| return existing;
        const id = std.math.cast(u32, self.nodes.items.len) orelse
            return error.CountOverflow;
        try self.nodes.append(self.allocator, node);
        errdefer _ = self.nodes.pop();
        try self.interned.put(node, id);
        return id;
    }

    fn binary(
        self: *CanonicalArena,
        op: symbolic.Op,
        lhs: u32,
        rhs: u32,
    ) (std.mem.Allocator.Error || error{CountOverflow})!u32 {
        var node = symbolic.Node{ .op = op, .lhs = lhs, .rhs = rhs };
        if ((op == .add or op == .mul) and node.rhs < node.lhs)
            std.mem.swap(u32, &node.lhs, &node.rhs);
        return self.intern(node);
    }

    fn select(
        self: *CanonicalArena,
        selector: u32,
        when_true: u32,
        when_false: u32,
    ) (std.mem.Allocator.Error || error{CountOverflow})!u32 {
        const difference = try self.binary(.sub, when_true, when_false);
        const selected = try self.binary(.mul, selector, difference);
        return self.binary(.add, when_false, selected);
    }
};
