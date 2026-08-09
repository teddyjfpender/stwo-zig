//! Canonical feasibility authority for experimental materialization cut sets.
//!
//! This module chooses no optimization policy. It owns and authenticates an
//! arbitrary set of materialized scalar values so search policies can add,
//! remove, or exchange cuts without weakening the degree-three boundary. The
//! accepted H-003 plan is one possible input, not a mutable global default.

const std = @import("std");
const digest = @import("digest.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const types = @import("types.zig");
const validator = @import("validate.zig");

pub const Degree = materializer.Degree;
pub const Policy = materializer.Policy;
pub const Request = materializer.Request;
pub const CutIndex = enum(u32) { _ };
const no_cut = std.math.maxInt(u32);

pub const DependencyRange = struct {
    start: u32,
    len: u32,

    pub fn slice(
        self: DependencyRange,
        dependencies: []const CutIndex,
    ) ?[]const CutIndex {
        const start: usize = self.start;
        const end = std.math.add(usize, start, self.len) catch return null;
        if (end > dependencies.len) return null;
        return dependencies[start..end];
    }
};

pub const Entry = struct {
    dependencies: DependencyRange,
    body_degree: Degree,
    equality_degree: Degree,
    context_degree: Degree,
    constraint_degree: Degree,
};

pub const Edit = union(enum) {
    add: types.ValueId,
    remove: types.ValueId,
    swap: struct { remove: types.ValueId, add: types.ValueId },
};

pub const ValidationError = error{
    CountOverflow,
    DegreeOverflow,
    DuplicateSelection,
    EmptyRoots,
    ImpossibleDegreeBudget,
    InfeasibleEquality,
    InvalidDependency,
    InvalidEdit,
    InvalidGate,
    InvalidGateType,
    InvalidRoot,
    InvalidRootType,
    InvalidSelection,
    InvalidStoredDegree,
    MissingEditValue,
    MissingRoot,
    GateMismatch,
    PolicyMismatch,
    ProgramDigestMismatch,
    RequestMismatch,
    SelectionNotCanonical,
    SelectionUnreachable,
    UnsupportedGateExpression,
};
pub const Error = std.mem.Allocator.Error || validator.Error || ValidationError;

/// Owned canonical selection. `values` is strictly increasing by `ValueId`;
/// `entries[i]` describes the equality for `values[i]`, and every dependency
/// index is strictly increasing and smaller than `i`.
pub const CutSet = struct {
    allocator: std.mem.Allocator,
    program_digest_format: u16,
    program_digest: digest.Digest,
    gate: ?types.ValueId,
    policy: Policy,
    roots: []types.ValueId,
    values: []types.ValueId,
    entries: []Entry,
    dependencies: []CutIndex,

    pub fn deinit(self: *CutSet) void {
        self.allocator.free(self.dependencies);
        self.allocator.free(self.entries);
        self.allocator.free(self.values);
        self.allocator.free(self.roots);
        self.* = undefined;
    }

    pub fn indexOf(self: *const CutSet, value: types.ValueId) ?CutIndex {
        var low: usize = 0;
        var high = self.values.len;
        const wanted = types.idIndex(value);
        while (low < high) {
            const middle = low + (high - low) / 2;
            const actual = types.idIndex(self.values[middle]);
            if (actual < wanted) low = middle + 1 else high = middle;
        }
        if (low == self.values.len or self.values[low] != value) return null;
        return @enumFromInt(std.math.cast(u32, low) orelse return null);
    }

    pub fn contains(self: *const CutSet, value: types.ValueId) bool {
        return self.indexOf(value) != null;
    }

    pub fn dependenciesFor(
        self: *const CutSet,
        index: CutIndex,
    ) ?[]const CutIndex {
        const raw = types.idIndex(index);
        if (raw >= self.entries.len) return null;
        return self.entries[raw].dependencies.slice(self.dependencies);
    }

    /// Rebuilds every identity, degree, and dependency field from the arena and
    /// authoritative request. Stored diagnostics are never trusted in place.
    pub fn validateAgainst(
        self: *const CutSet,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        request: Request,
    ) Error!void {
        try validator.validate(arena);
        const actual_identity = try digest.computeIdentity(arena);
        if (self.program_digest_format != actual_identity.format_version or
            !std.mem.eql(u8, &self.program_digest, &actual_identity.bytes))
        {
            return error.ProgramDigestMismatch;
        }
        if (self.gate != request.gate) return error.GateMismatch;
        if (!std.meta.eql(self.policy, request.policy)) return error.PolicyMismatch;
        if (!std.mem.eql(types.ValueId, self.roots, request.roots))
            return error.RequestMismatch;
        try validateStoredShape(self);

        var expected = try build(allocator, arena, request, self.values);
        defer expected.deinit();
        if (!std.mem.eql(types.ValueId, self.values, expected.values))
            return error.SelectionNotCanonical;
        if (!std.mem.eql(CutIndex, self.dependencies, expected.dependencies))
            return error.InvalidDependency;
        for (self.entries, expected.entries) |actual, wanted| {
            if (!std.meta.eql(actual.dependencies, wanted.dependencies))
                return error.InvalidDependency;
            if (actual.body_degree != wanted.body_degree or
                actual.equality_degree != wanted.equality_degree or
                actual.context_degree != wanted.context_degree or
                actual.constraint_degree != wanted.constraint_degree)
            {
                return error.InvalidStoredDegree;
            }
        }
    }

    /// Applies one canonical search edit and returns a newly authenticated set.
    /// Removing an absent value, adding an existing value, or producing an
    /// infeasible set fails rather than becoming a no-op.
    pub fn edited(
        self: *const CutSet,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        request: Request,
        edit: Edit,
    ) Error!CutSet {
        try self.validateAgainst(allocator, arena, request);
        return self.editedTrusted(allocator, arena, request, edit);
    }

    /// Applies an edit after the caller has authenticated `self` against this
    /// exact arena and request. The parent is not revalidated, but the returned
    /// cut is always rebuilt from the arena through `build` and therefore gets
    /// the complete canonicality, reachability, type, and degree checks.
    pub fn editedTrusted(
        self: *const CutSet,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        request: Request,
        edit: Edit,
    ) Error!CutSet {
        const new_len = switch (edit) {
            .add => |value| blk: {
                if (self.contains(value)) return error.DuplicateSelection;
                break :blk std.math.add(usize, self.values.len, 1) catch
                    return error.CountOverflow;
            },
            .remove => |value| blk: {
                if (!self.contains(value)) return error.MissingEditValue;
                break :blk self.values.len - 1;
            },
            .swap => |change| blk: {
                if (change.add == change.remove) return error.InvalidEdit;
                if (!self.contains(change.remove)) return error.MissingEditValue;
                if (self.contains(change.add)) return error.DuplicateSelection;
                break :blk self.values.len;
            },
        };
        const selected = try allocator.alloc(types.ValueId, new_len);
        defer allocator.free(selected);
        var cursor: usize = 0;
        for (self.values) |value| {
            const omit = switch (edit) {
                .remove => |removed| value == removed,
                .swap => |change| value == change.remove,
                .add => false,
            };
            if (!omit) {
                selected[cursor] = value;
                cursor += 1;
            }
        }
        switch (edit) {
            .add => |value| selected[cursor] = value,
            .swap => |change| selected[cursor] = change.add,
            .remove => {},
        }
        return build(allocator, arena, request, selected);
    }
};

/// Constructs a canonical owned cut set from an arbitrary input order.
pub fn build(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    request: Request,
    selected_values: []const types.ValueId,
) Error!CutSet {
    try validator.validate(arena);
    if (request.roots.len == 0) return error.EmptyRoots;
    const program_identity = try digest.computeIdentity(arena);
    const context_degree = try validateContext(arena, request.gate, request.policy);
    const node_count = arena.nodeCount();

    const roots = try allocator.dupe(types.ValueId, request.roots);
    errdefer allocator.free(roots);
    try validateRoots(arena, roots);

    const values = try allocator.dupe(types.ValueId, selected_values);
    errdefer allocator.free(values);
    std.mem.sort(types.ValueId, values, {}, valueLessThan);
    for (values, 0..) |value, index| {
        const node = arena.node(value) orelse return error.InvalidSelection;
        if (!node.key.ty.isFieldScalar()) return error.InvalidSelection;
        if (index != 0 and values[index - 1] == value)
            return error.DuplicateSelection;
    }
    for (roots) |root| if (!containsSorted(values, root)) return error.MissingRoot;

    const reachable = try allocator.alloc(bool, node_count);
    defer allocator.free(reachable);
    try markReachable(arena, roots, reachable);
    for (values) |value| if (!reachable[types.idIndex(value)])
        return error.SelectionUnreachable;

    const selected_by_node = try allocator.alloc(u32, node_count);
    defer allocator.free(selected_by_node);
    @memset(selected_by_node, no_cut);
    for (values, 0..) |value, index| {
        selected_by_node[types.idIndex(value)] = std.math.cast(u32, index) orelse
            return error.CountOverflow;
    }

    const entries = try allocator.alloc(Entry, values.len);
    errdefer allocator.free(entries);
    var dependencies: std.ArrayList(CutIndex) = .empty;
    defer dependencies.deinit(allocator);
    const closure = try allocator.alloc(bool, node_count);
    defer allocator.free(closure);
    const frontier = try allocator.alloc(bool, node_count);
    defer allocator.free(frontier);
    const degrees = try allocator.alloc(Degree, node_count);
    defer allocator.free(degrees);

    for (values, entries, 0..) |value, *entry, index| {
        markClosure(arena, value, selected_by_node, closure, frontier);
        const dependency_start = dependencies.items.len;
        for (values[0..index], 0..) |candidate, dependency_index| {
            if (!frontier[types.idIndex(candidate)]) continue;
            try dependencies.append(
                allocator,
                @enumFromInt(std.math.cast(u32, dependency_index) orelse
                    return error.CountOverflow),
            );
            frontier[types.idIndex(candidate)] = false;
        }
        for (frontier) |is_dependency| if (is_dependency)
            return error.InvalidDependency;

        const body_degree = try computeBodyDegree(
            arena,
            value,
            selected_by_node,
            closure,
            degrees,
        );
        const equality_degree = @max(@as(Degree, 1), body_degree);
        const constraint_degree = std.math.add(
            Degree,
            equality_degree,
            context_degree,
        ) catch return error.DegreeOverflow;
        if (constraint_degree > request.policy.maximum_constraint_degree)
            return error.InfeasibleEquality;
        const dependency_len = dependencies.items.len - dependency_start;
        entry.* = .{
            .dependencies = .{
                .start = std.math.cast(u32, dependency_start) orelse
                    return error.CountOverflow,
                .len = std.math.cast(u32, dependency_len) orelse
                    return error.CountOverflow,
            },
            .body_degree = body_degree,
            .equality_degree = equality_degree,
            .context_degree = context_degree,
            .constraint_degree = constraint_degree,
        };
    }
    const owned_dependencies = try dependencies.toOwnedSlice(allocator);
    return .{
        .allocator = allocator,
        .program_digest_format = program_identity.format_version,
        .program_digest = program_identity.bytes,
        .gate = request.gate,
        .policy = request.policy,
        .roots = roots,
        .values = values,
        .entries = entries,
        .dependencies = owned_dependencies,
    };
}

/// Imports the exact selected values and ordered roots of an authenticated
/// H-003 plan. The result has its own storage and policy-neutral identity.
pub fn fromDegree3Plan(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    plan: *const materializer.Plan,
) !CutSet {
    try plan.validate(allocator, arena);
    const roots = try allocator.alloc(types.ValueId, plan.outputs.len);
    defer allocator.free(roots);
    for (plan.outputs, roots) |output, *root| root.* = output.root;
    const selected = try allocator.alloc(types.ValueId, plan.materializations.len);
    defer allocator.free(selected);
    for (plan.materializations, selected) |item, *value| value.* = item.source_value;
    return build(allocator, arena, .{
        .roots = roots,
        .gate = plan.gate,
        .policy = plan.policy,
    }, selected);
}

fn validateStoredShape(self: *const CutSet) ValidationError!void {
    if (self.values.len != self.entries.len) return error.InvalidSelection;
    var dependency_cursor: usize = 0;
    for (self.values, 0..) |value, index| {
        if (index != 0) {
            if (self.values[index - 1] == value) return error.DuplicateSelection;
            if (!valueLessThan({}, self.values[index - 1], value))
                return error.SelectionNotCanonical;
        }
        if (@as(usize, self.entries[index].dependencies.start) != dependency_cursor)
            return error.InvalidDependency;
        const stored = self.entries[index].dependencies.slice(self.dependencies) orelse
            return error.InvalidDependency;
        var prior: ?usize = null;
        for (stored) |dependency| {
            const dependency_index = types.idIndex(dependency);
            if (dependency_index >= index or
                (prior != null and prior.? >= dependency_index))
            {
                return error.InvalidDependency;
            }
            prior = dependency_index;
        }
        dependency_cursor += stored.len;
    }
    if (dependency_cursor != self.dependencies.len) return error.InvalidDependency;
}

fn validateRoots(arena: *const ir.Arena, roots: []const types.ValueId) ValidationError!void {
    for (roots) |root| {
        const node = arena.node(root) orelse return error.InvalidRoot;
        if (!node.key.ty.isFieldScalar()) return error.InvalidRootType;
    }
}

fn validateContext(
    arena: *const ir.Arena,
    gate: ?types.ValueId,
    policy: Policy,
) ValidationError!Degree {
    var gate_degree: Degree = 0;
    if (gate) |value| {
        const node = arena.node(value) orelse return error.InvalidGate;
        if (!node.key.ty.isSelector()) return error.InvalidGateType;
        gate_degree = switch (node.key.op) {
            .constant => 0,
            .input, .hint_output, .call_output => 1,
            else => return error.UnsupportedGateExpression,
        };
    }
    const context = std.math.add(Degree, gate_degree, policy.row_mask_degree) catch
        return error.DegreeOverflow;
    if (policy.maximum_constraint_degree < context or
        policy.maximum_constraint_degree - context < 1)
    {
        return error.ImpossibleDegreeBudget;
    }
    return context;
}

fn markReachable(
    arena: *const ir.Arena,
    roots: []const types.ValueId,
    reachable: []bool,
) ValidationError!void {
    @memset(reachable, false);
    for (roots) |root| {
        const index = types.idIndex(root);
        if (index >= reachable.len) return error.InvalidRoot;
        reachable[index] = true;
    }
    var reverse = reachable.len;
    while (reverse > 0) {
        reverse -= 1;
        if (!reachable[reverse]) continue;
        for (operands(arena.nodesView()[reverse].key.op)) |optional| {
            const operand = optional orelse continue;
            const index = types.idIndex(operand);
            if (index >= reverse) return error.InvalidSelection;
            reachable[index] = true;
        }
    }
}

fn markClosure(
    arena: *const ir.Arena,
    root: types.ValueId,
    selected_by_node: []const u32,
    closure: []bool,
    frontier: []bool,
) void {
    @memset(closure, false);
    @memset(frontier, false);
    const root_index = types.idIndex(root);
    closure[root_index] = true;
    var reverse = root_index + 1;
    while (reverse > 0) {
        reverse -= 1;
        if (!closure[reverse]) continue;
        if (reverse != root_index and selected_by_node[reverse] != no_cut) {
            frontier[reverse] = true;
            continue;
        }
        for (operands(arena.nodesView()[reverse].key.op)) |optional| {
            const operand = optional orelse continue;
            closure[types.idIndex(operand)] = true;
        }
    }
}

fn computeBodyDegree(
    arena: *const ir.Arena,
    root: types.ValueId,
    selected_by_node: []const u32,
    closure: []const bool,
    degrees: []Degree,
) ValidationError!Degree {
    const root_index = types.idIndex(root);
    for (arena.nodesView()[0 .. root_index + 1], 0..) |node, index| {
        if (!closure[index]) continue;
        if (index != root_index and selected_by_node[index] != no_cut) {
            degrees[index] = 1;
            continue;
        }
        degrees[index] = switch (node.key.op) {
            .constant => 0,
            .input, .hint_output, .call_output => 1,
            .add, .sub => |binary| @max(
                degrees[types.idIndex(binary.lhs)],
                degrees[types.idIndex(binary.rhs)],
            ),
            .mul => |binary| std.math.add(
                Degree,
                degrees[types.idIndex(binary.lhs)],
                degrees[types.idIndex(binary.rhs)],
            ) catch return error.DegreeOverflow,
            .neg => |value| degrees[types.idIndex(value)],
            .select => |selection| std.math.add(
                Degree,
                degrees[types.idIndex(selection.selector)],
                @max(
                    degrees[types.idIndex(selection.when_true)],
                    degrees[types.idIndex(selection.when_false)],
                ),
            ) catch return error.DegreeOverflow,
            .machine_derived => |derived| switch (derived) {
                .register_address => |address| degrees[types.idIndex(address.index)],
                .aligned_word_address => |address| degrees[types.idIndex(address.word_index)],
                .access_clock => |clock| degrees[types.idIndex(clock.instruction_clock)],
                .strict_clock_gap => |gap| @max(
                    degrees[types.idIndex(gap.current_clock)],
                    degrees[types.idIndex(gap.previous_clock)],
                ),
            },
        };
    }
    return degrees[root_index];
}

fn operands(op: expr.Op) [3]?types.ValueId {
    return switch (op) {
        .constant, .input, .hint_output, .call_output => .{ null, null, null },
        .add, .sub, .mul => |binary| .{ binary.lhs, binary.rhs, null },
        .neg => |value| .{ value, null, null },
        .select => |selection| .{
            selection.selector,
            selection.when_true,
            selection.when_false,
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| .{ address.index, null, null },
            .aligned_word_address => |address| .{ address.word_index, null, null },
            .access_clock => |clock| .{ clock.instruction_clock, null, null },
            .strict_clock_gap => |gap| .{
                gap.current_clock,
                gap.previous_clock,
                null,
            },
        },
    };
}

fn containsSorted(values: []const types.ValueId, wanted: types.ValueId) bool {
    var low: usize = 0;
    var high = values.len;
    const target = types.idIndex(wanted);
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (types.idIndex(values[middle]) < target) low = middle + 1 else high = middle;
    }
    return low < values.len and values[low] == wanted;
}

fn valueLessThan(_: void, lhs: types.ValueId, rhs: types.ValueId) bool {
    return types.idIndex(lhs) < types.idIndex(rhs);
}
