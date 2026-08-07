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
const expr = @import("expr.zig");
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

/// Physical input prefix required by a lowered root set. Lookup expressions
/// depend only on main columns; direct placement constraints additionally read
/// the external active selector.
pub const ColumnSet = enum {
    main,
    main_and_selector,
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
        if (self.column_count == 0 or self.nodes.len < self.column_count) {
            return error.InvalidColumnLayout;
        }
        if (self.roots.len == 0) return error.InvalidRoot;
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
                .constant => {
                    if (node.lhs != 0 or node.rhs != 0)
                        return error.NonCanonicalNode;
                    if (node.value >= m31.Modulus)
                        return error.InvalidConstant;
                },
                .add, .sub, .mul => {
                    if (node.value != 0) return error.NonCanonicalNode;
                    if (node.lhs >= index or node.rhs >= index)
                        return error.InvalidNode;
                    if ((node.op == .add or node.op == .mul) and
                        node.rhs < node.lhs)
                    {
                        return error.NonCanonicalNode;
                    }
                },
                .neg => {
                    if (node.rhs != 0 or node.value != 0)
                        return error.NonCanonicalNode;
                    if (node.lhs >= index) return error.InvalidNode;
                },
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
    const roots = try allocator.alloc(
        types.ValueId,
        imported.direct_constraints.len,
    );
    defer allocator.free(roots);
    for (imported.direct_constraints, roots) |constraint_id, *root| {
        const constraint = imported.imported.arena.constraint(constraint_id) orelse
            return error.InvalidConstraintMap;
        root.* = constraint.root;
    }
    return lowerValues(
        allocator,
        imported,
        layout,
        roots,
        .main_and_selector,
    );
}

/// Lowers an ordered value-root set through the same canonical expression
/// machinery used by direct constraints. This is the shared seam for lookup
/// numerators/fields and later runtime or formal exporters.
pub fn lowerValues(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
    roots: []const types.ValueId,
    column_set: ColumnSet,
) LowerError!Program {
    try layout.validate(imported);
    const typed_nodes = imported.imported.arena.nodesView();
    const reachable = try allocator.alloc(bool, typed_nodes.len);
    defer allocator.free(reachable);
    @memset(reachable, false);
    const mapped = try allocator.alloc(u32, typed_nodes.len);
    defer allocator.free(mapped);
    @memset(mapped, no_node);

    for (roots) |root| {
        const index = types.idIndex(root);
        if (index >= typed_nodes.len) return error.MissingOperand;
        reachable[index] = true;
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
            .machine_derived => |derived| switch (derived) {
                .register_address => |address| try markOperand(
                    reachable,
                    reverse,
                    address.index,
                ),
                .access_clock => |clock| try markOperand(
                    reachable,
                    reverse,
                    clock.instruction_clock,
                ),
                .strict_clock_gap => |gap| {
                    try markOperand(reachable, reverse, gap.current_clock);
                    try markOperand(reachable, reverse, gap.previous_clock);
                },
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
    if (column_set == .main_and_selector) {
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
    }

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
            .machine_derived => |derived| try lowerMachineDerived(
                &target,
                derived,
                mapped,
            ),
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }

    const lowered_roots = try allocator.alloc(u32, roots.len);
    var roots_owned = true;
    errdefer if (roots_owned) allocator.free(lowered_roots);
    for (roots, lowered_roots) |root, *lowered_root| {
        lowered_root.* = try operand(mapped, root);
    }
    const nodes = try target.nodes.toOwnedSlice(allocator);
    var nodes_owned = true;
    errdefer if (nodes_owned) allocator.free(nodes);
    const column_count = std.math.add(
        usize,
        layout.main().len,
        @intFromBool(column_set == .main_and_selector),
    ) catch
        return error.CountOverflow;
    var result = Program{
        .allocator = allocator,
        .nodes = nodes,
        .roots = lowered_roots,
        .column_count = column_count,
    };
    roots_owned = false;
    nodes_owned = false;
    errdefer result.deinit();
    try canonicalize(&result);
    try result.validate();
    return result;
}

const Candidate = struct {
    old_index: u32,
    node: symbolic.Node,
};

/// Re-labels a valid topological DAG independently of source insertion order.
/// Columns retain their physical prefix. Remaining nodes are ordered by
/// dependency height and then by a stable structural key over already-remapped
/// operands. This makes lookup-only and complete-program construction converge
/// even when dead sibling work first interned a shared constant.
fn canonicalize(program: *Program) (std.mem.Allocator.Error || error{CountOverflow})!void {
    const allocator = program.allocator;
    const heights = try allocator.alloc(u32, program.nodes.len);
    defer allocator.free(heights);
    var maximum_height: u32 = 0;
    for (program.nodes, 0..) |node, index| {
        heights[index] = switch (node.op) {
            .constant, .column => 0,
            .add, .sub, .mul => std.math.add(
                u32,
                @max(heights[node.lhs], heights[node.rhs]),
                1,
            ) catch return error.CountOverflow,
            .neg => std.math.add(u32, heights[node.lhs], 1) catch
                return error.CountOverflow,
        };
        maximum_height = @max(maximum_height, heights[index]);
    }

    const remapped = try allocator.alloc(u32, program.nodes.len);
    defer allocator.free(remapped);
    @memset(remapped, no_node);
    const candidates = try allocator.alloc(Candidate, program.nodes.len);
    defer allocator.free(candidates);
    var canonical: std.ArrayList(symbolic.Node) = .empty;
    defer canonical.deinit(allocator);
    try canonical.ensureTotalCapacity(allocator, program.nodes.len);

    for (program.nodes[0..program.column_count], 0..) |node, index| {
        canonical.appendAssumeCapacity(node);
        remapped[index] = @intCast(index);
    }

    var height: u32 = 0;
    while (height <= maximum_height) : (height += 1) {
        var count: usize = 0;
        for (program.nodes[program.column_count..], program.column_count..) |node, old_index| {
            if (heights[old_index] != height) continue;
            candidates[count] = .{
                .old_index = @intCast(old_index),
                .node = try remapNode(node, remapped),
            };
            count += 1;
        }
        std.mem.sort(Candidate, candidates[0..count], {}, candidateLessThan);
        for (candidates[0..count]) |candidate| {
            if (canonical.items.len > program.column_count and
                std.meta.eql(canonical.items[canonical.items.len - 1], candidate.node))
            {
                remapped[candidate.old_index] = @intCast(canonical.items.len - 1);
                continue;
            }
            const new_index = std.math.cast(u32, canonical.items.len) orelse
                return error.CountOverflow;
            canonical.appendAssumeCapacity(candidate.node);
            remapped[candidate.old_index] = new_index;
        }
        if (height == maximum_height) break;
    }

    for (program.roots) |*root| {
        if (root.* >= remapped.len or remapped[root.*] == no_node)
            return error.CountOverflow;
        root.* = remapped[root.*];
    }
    const canonical_nodes = try canonical.toOwnedSlice(allocator);
    allocator.free(program.nodes);
    program.nodes = canonical_nodes;
}

fn remapNode(
    source_node: symbolic.Node,
    remapped: []const u32,
) error{CountOverflow}!symbolic.Node {
    var node = source_node;
    switch (node.op) {
        .constant => {},
        .column => return error.CountOverflow,
        .add, .sub, .mul => {
            if (node.lhs >= remapped.len or node.rhs >= remapped.len or
                remapped[node.lhs] == no_node or remapped[node.rhs] == no_node)
            {
                return error.CountOverflow;
            }
            node.lhs = remapped[node.lhs];
            node.rhs = remapped[node.rhs];
            if ((node.op == .add or node.op == .mul) and node.rhs < node.lhs)
                std.mem.swap(u32, &node.lhs, &node.rhs);
        },
        .neg => {
            if (node.lhs >= remapped.len or remapped[node.lhs] == no_node)
                return error.CountOverflow;
            node.lhs = remapped[node.lhs];
        },
    }
    return node;
}

fn candidateLessThan(_: void, lhs: Candidate, rhs: Candidate) bool {
    const lhs_op = @intFromEnum(lhs.node.op);
    const rhs_op = @intFromEnum(rhs.node.op);
    if (lhs_op != rhs_op) return lhs_op < rhs_op;
    if (lhs.node.value != rhs.node.value) return lhs.node.value < rhs.node.value;
    if (lhs.node.lhs != rhs.node.lhs) return lhs.node.lhs < rhs.node.lhs;
    if (lhs.node.rhs != rhs.node.rhs) return lhs.node.rhs < rhs.node.rhs;
    return lhs.old_index < rhs.old_index;
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

fn lowerMachineDerived(
    target: *CanonicalArena,
    derived: expr.MachineDerived,
    mapped: []const u32,
) LowerError!u32 {
    return switch (derived) {
        .register_address => |address| operand(mapped, address.index),
        .access_clock => |clock| blk: {
            const one = try target.intern(.{ .op = .constant, .value = 1 });
            const four = try target.intern(.{ .op = .constant, .value = 4 });
            const ordinal = try target.intern(.{
                .op = .constant,
                .value = @intFromEnum(clock.ordinal),
            });
            const shifted = try target.binary(
                .sub,
                try operand(mapped, clock.instruction_clock),
                one,
            );
            const scaled = try target.binary(.mul, shifted, four);
            break :blk target.binary(.add, scaled, ordinal);
        },
        .strict_clock_gap => |gap| blk: {
            const one = try target.intern(.{ .op = .constant, .value = 1 });
            const delta = try target.binary(
                .sub,
                try operand(mapped, gap.current_clock),
                try operand(mapped, gap.previous_clock),
            );
            break :blk target.binary(.sub, delta, one);
        },
    };
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
