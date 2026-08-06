//! Deterministic structural costs for proposed materialization cut sets.
//!
//! This module measures a candidate; it does not choose one and it does not
//! mutate the semantic arena. Candidate values are a canonical, strictly
//! increasing `ValueId` set. Each equality is lowered after all preceding
//! values have become committed leaves, and all equalities share one target
//! arena. The resulting counts therefore describe a globally hash-consed
//! direct polynomial DAG rather than a sum of independently expanded syntax.
//! Semantic selection uses the production-compatible
//! `false + selector * (true - false)` expansion.
//!
//! Fixed component algebra, when present, is an explicit authenticated SSA
//! program lowered into that same target arena before and after the candidate
//! equalities. A positive row-mask degree is represented by one shared opaque
//! preprocessed leaf. If both gate and mask are present, their product is
//! shared before it is multiplied into every materialization equality.

const std = @import("std");
const direct_model = @import("materialization_cost_direct.zig");
const identity = @import("degree3_materializer_identity.zig");
const expr = @import("expr.zig");
const fixed_direct = @import("materialization_fixed_direct.zig");
const ir = @import("ir.zig");
const types = @import("types.zig");
const validator = @import("validate.zig");

pub const Policy = identity.Policy;
pub const Degree = identity.Degree;

/// Physical geometry that is independent of the candidate cut set.
pub const Geometry = struct {
    preprocessed_columns: u64 = 0,
    base_main_columns: u64 = 19,
    fixed_direct_roots: u64 = 0,
    interaction_columns: u64 = 8,
    field_element_bytes: u64 = 4,
};

pub const Request = struct {
    roots: []const types.ValueId,
    gate: ?types.ValueId,
    policy: Policy = .{},
    /// Strictly increasing, unique, root-complete candidate cut set.
    selected: []const types.ValueId,
    geometry: Geometry = .{},
    /// Explicit non-candidate algebra evaluated before and after the selected
    /// equality roots. Its root count must exactly match `geometry`.
    fixed_direct_program: ?fixed_direct.Program = null,
    /// Strictly increasing scenario order; each size denotes `2^log_size` rows.
    log_sizes: []const u8 = &.{},
};

pub const CostVector = struct {
    materialization_count: u64,
    base_main_columns: u64,
    candidate_main_columns: u64,
    direct_roots: u64,
    interaction_columns: u64,
    canonical_direct_nodes: u64,
    canonical_direct_additions: u64,
    canonical_direct_subtractions: u64,
    canonical_direct_negations: u64,
    canonical_direct_multiplications: u64,
    unique_committed_column_reads: u64,
    /// Idealized first-intern streaming order: roots fold at explicit ordered
    /// events and a node is released after its final operand or root use.
    /// This is a schedule property of the modeled proposal DAG, not observed
    /// production-backend memory. A retained-node interpreter for this exact
    /// DAG would require `canonical_direct_nodes` values; the production
    /// Poseidon component currently uses a separate static evaluator.
    canonical_streaming_peak_live_nodes: u64,
    semantic_witness_nodes: u64,
};

pub const ScenarioCost = struct {
    log_size: u8,
    rows: u64,
    main_cells: u64,
    interaction_cells: u64,
    committed_cells: u64,
    main_bytes: u64,
    interaction_bytes: u64,
    committed_bytes: u64,
};

pub const Report = struct {
    allocator: std.mem.Allocator,
    vector: CostVector,
    scenarios: []ScenarioCost,

    pub fn deinit(self: *Report) void {
        self.allocator.free(self.scenarios);
        self.* = undefined;
    }

    /// Exact structural and scenario equality; allocator identity is ignored.
    pub fn eql(self: *const Report, other: *const Report) bool {
        if (!std.meta.eql(self.vector, other.vector) or
            self.scenarios.len != other.scenarios.len)
        {
            return false;
        }
        for (self.scenarios, other.scenarios) |lhs, rhs| {
            if (!std.meta.eql(lhs, rhs)) return false;
        }
        return true;
    }

    /// Pareto dominance. Scenarios must describe the same ordered row sizes.
    pub fn dominates(self: *const Report, other: *const Report) bool {
        if (self.scenarios.len != other.scenarios.len) return false;
        for (self.scenarios, other.scenarios) |lhs, rhs| {
            if (lhs.log_size != rhs.log_size or lhs.rows != rhs.rows) return false;
        }

        var strictly_better = false;
        inline for (std.meta.fields(CostVector)) |field| {
            const lhs = @field(self.vector, field.name);
            const rhs = @field(other.vector, field.name);
            if (lhs > rhs) return false;
            strictly_better = strictly_better or lhs < rhs;
        }
        for (self.scenarios, other.scenarios) |lhs, rhs| {
            inline for (.{
                "main_cells",
                "interaction_cells",
                "committed_cells",
                "main_bytes",
                "interaction_bytes",
                "committed_bytes",
            }) |field_name| {
                const lhs_value = @field(lhs, field_name);
                const rhs_value = @field(rhs, field_name);
                if (lhs_value > rhs_value) return false;
                strictly_better = strictly_better or lhs_value < rhs_value;
            }
        }
        return strictly_better;
    }

    /// Total lexicographic order used only for canonical retention/output.
    pub fn canonicalOrder(self: *const Report, other: *const Report) std.math.Order {
        inline for (std.meta.fields(CostVector)) |field| {
            const result = std.math.order(
                @field(self.vector, field.name),
                @field(other.vector, field.name),
            );
            if (result != .eq) return result;
        }
        const shared = @min(self.scenarios.len, other.scenarios.len);
        for (self.scenarios[0..shared], other.scenarios[0..shared]) |lhs, rhs| {
            inline for (std.meta.fields(ScenarioCost)) |field| {
                const result = std.math.order(
                    @field(lhs, field.name),
                    @field(rhs, field.name),
                );
                if (result != .eq) return result;
            }
        }
        return std.math.order(self.scenarios.len, other.scenarios.len);
    }
};

pub fn canonicalLessThan(_: void, lhs: Report, rhs: Report) bool {
    return lhs.canonicalOrder(&rhs) == .lt;
}

pub const ValidationError = error{
    CountOverflow,
    DegreeOverflow,
    EmptyRoots,
    FixedColumnOutOfBounds,
    FixedColumnAliasesMaterialization,
    FixedDegreeExceedsBudget,
    FixedRootCountMismatch,
    GeometryOverflow,
    ImpossibleDegreeBudget,
    InfeasibleSelection,
    InvalidCellWidth,
    InvalidGate,
    InvalidGateType,
    InvalidLogSize,
    MissingDirectOperand,
    MissingFixedGate,
    InvalidRoot,
    InvalidRootType,
    InvalidScenarioOrder,
    InvalidSelectedValue,
    InvalidSelectedValueType,
    MissingSelectedRoot,
    NonCanonicalSelection,
    SelectedValueOutsideRootClosure,
    UnsupportedGateExpression,
};

pub const Error = std.mem.Allocator.Error ||
    validator.Error ||
    fixed_direct.Error ||
    ValidationError;

/// Recomputes candidate feasibility and returns its complete integer report.
pub fn analyze(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    request: Request,
) Error!Report {
    try validator.validate(arena);
    if (request.roots.len == 0) return error.EmptyRoots;
    if (request.geometry.field_element_bytes == 0) return error.InvalidCellWidth;
    try validateScenarioOrder(request.log_sizes);

    const context_degree = try validateContext(arena, request.gate, request.policy);
    const nodes = arena.nodesView();
    const reachable = try allocator.alloc(bool, nodes.len);
    defer allocator.free(reachable);
    try markReachable(arena, request.roots, reachable);

    const selected_flags = try allocator.alloc(bool, nodes.len);
    defer allocator.free(selected_flags);
    @memset(selected_flags, false);
    try validateSelection(arena, request.roots, request.selected, reachable, selected_flags);

    const semantic_witness_nodes = try countFlags(reachable);
    const materialization_count = std.math.cast(u64, request.selected.len) orelse
        return error.CountOverflow;
    const candidate_main_columns = try checkedAdd(
        request.geometry.base_main_columns,
        materialization_count,
    );
    const fixed_root_count: u64 = if (request.fixed_direct_program) |program|
        try program.fixedRootCount()
    else
        0;
    if (fixed_root_count != request.geometry.fixed_direct_roots)
        return error.FixedRootCountMismatch;
    if (request.fixed_direct_program) |program| {
        const materialization_end = try checkedAdd(
            program.materialization_column_start,
            materialization_count,
        );
        const materialization_bound = switch (program.materialization_tree) {
            .preprocessed => request.geometry.preprocessed_columns,
            .main => candidate_main_columns,
            .interaction => request.geometry.interaction_columns,
        };
        if (materialization_end > materialization_bound)
            return error.FixedColumnOutOfBounds;
        if (try program.maximumRootDegree(allocator) >
            request.policy.maximum_constraint_degree)
            return error.FixedDegreeExceedsBudget;
        for (program.columns) |column| {
            const resolved = try column.placement.resolve(materialization_count);
            const bound = switch (column.tree) {
                .preprocessed => request.geometry.preprocessed_columns,
                .main => candidate_main_columns,
                .interaction => request.geometry.interaction_columns,
            };
            if (resolved >= bound) return error.FixedColumnOutOfBounds;
            if (column.tree == program.materialization_tree) {
                if (resolved >= program.materialization_column_start and
                    resolved < materialization_end)
                {
                    return error.FixedColumnAliasesMaterialization;
                }
            }
        }
    }
    const degrees = try allocator.alloc(Degree, nodes.len);
    defer allocator.free(degrees);
    const available = try allocator.alloc(bool, nodes.len);
    defer allocator.free(available);
    @memset(available, false);

    var direct = direct_model.Arena.init(allocator);
    defer direct.deinit();
    const mapped = try allocator.alloc(u32, nodes.len);
    defer allocator.free(mapped);
    @memset(mapped, no_direct_node);
    const needed = try allocator.alloc(bool, nodes.len);
    defer allocator.free(needed);
    var direct_roots: std.ArrayList(direct_model.RootUse) = .empty;
    defer direct_roots.deinit(allocator);
    const total_roots = std.math.add(
        usize,
        request.selected.len,
        std.math.cast(usize, fixed_root_count) orelse return error.CountOverflow,
    ) catch return error.CountOverflow;
    try direct_roots.ensureTotalCapacity(allocator, total_roots);

    const context = try lowerContext(&direct, arena, request.gate, request.policy, mapped);
    var fixed_lowering: ?fixed_direct.Lowering = if (request.fixed_direct_program) |program|
        try fixed_direct.Lowering.init(allocator, program, materialization_count)
    else
        null;
    defer if (fixed_lowering) |*lowering| lowering.deinit();
    var fixed_emitter = FixedEmitter{
        .direct = &direct,
        .gate = if (request.gate) |gate| mapped[types.idIndex(gate)] else null,
    };
    if (fixed_lowering) |*lowering| {
        const roots = try allocator.alloc(u32, lowering.program.prefix_roots.len);
        defer allocator.free(roots);
        try lowering.lowerPrefix(&fixed_emitter, roots);
        for (roots) |root|
            direct_roots.appendAssumeCapacity(try direct.recordRoot(root));
    }
    for (request.selected) |value| {
        try computeDegrees(arena, reachable, available, degrees);
        const body_degree = degrees[types.idIndex(value)];
        const equality_degree = @max(@as(Degree, 1), body_degree);
        const constraint_degree = std.math.add(
            Degree,
            equality_degree,
            context_degree,
        ) catch return error.DegreeOverflow;
        if (constraint_degree > request.policy.maximum_constraint_degree)
            return error.InfeasibleSelection;

        const body = try lowerValue(&direct, arena, value, mapped, needed);
        const column = try direct.committed(value, true);
        const equality = try direct.binary(.sub, column, body);
        const root = if (context) |context_node|
            try direct.binary(.mul, equality, context_node)
        else
            equality;
        direct_roots.appendAssumeCapacity(try direct.recordRoot(root));
        mapped[types.idIndex(value)] = column;
        available[types.idIndex(value)] = true;
    }
    if (fixed_lowering) |*lowering| {
        const roots = try allocator.alloc(u32, lowering.program.suffix_roots.len);
        defer allocator.free(roots);
        try lowering.lowerSuffix(&fixed_emitter, roots);
        for (roots) |root|
            direct_roots.appendAssumeCapacity(try direct.recordRoot(root));
    }

    const direct_root_count = try checkedAdd(materialization_count, fixed_root_count);
    const operation_counts = try direct.operationCounts();
    const direct_node_count = std.math.cast(u64, direct.nodeCount()) orelse
        return error.CountOverflow;
    const peak_live = try direct.peakLiveNodes(allocator, direct_roots.items);

    const scenarios = try allocator.alloc(ScenarioCost, request.log_sizes.len);
    var scenarios_owned = true;
    errdefer if (scenarios_owned) allocator.free(scenarios);
    for (request.log_sizes, scenarios) |log_size, *scenario| {
        scenario.* = try scenarioCost(
            log_size,
            candidate_main_columns,
            request.geometry.interaction_columns,
            request.geometry.field_element_bytes,
        );
    }

    const result = Report{
        .allocator = allocator,
        .vector = .{
            .materialization_count = materialization_count,
            .base_main_columns = request.geometry.base_main_columns,
            .candidate_main_columns = candidate_main_columns,
            .direct_roots = direct_root_count,
            .interaction_columns = request.geometry.interaction_columns,
            .canonical_direct_nodes = direct_node_count,
            .canonical_direct_additions = operation_counts.additions,
            .canonical_direct_subtractions = operation_counts.subtractions,
            .canonical_direct_negations = operation_counts.negations,
            .canonical_direct_multiplications = operation_counts.multiplications,
            .unique_committed_column_reads = operation_counts.committed,
            .canonical_streaming_peak_live_nodes = peak_live,
            .semantic_witness_nodes = semantic_witness_nodes,
        },
        .scenarios = scenarios,
    };
    scenarios_owned = false;
    return result;
}

fn validateSelection(
    arena: *const ir.Arena,
    roots: []const types.ValueId,
    selected: []const types.ValueId,
    reachable: []const bool,
    selected_flags: []bool,
) ValidationError!void {
    var previous: ?usize = null;
    for (selected) |value| {
        const index = types.idIndex(value);
        if (index >= arena.nodeCount()) return error.InvalidSelectedValue;
        if (previous) |prior| if (index <= prior) return error.NonCanonicalSelection;
        previous = index;
        const node = arena.node(value).?;
        if (!node.key.ty.isFieldScalar()) return error.InvalidSelectedValueType;
        if (!reachable[index]) return error.SelectedValueOutsideRootClosure;
        selected_flags[index] = true;
    }
    for (roots) |root| {
        const index = types.idIndex(root);
        if (index >= selected_flags.len or !selected_flags[index])
            return error.MissingSelectedRoot;
    }
}

fn validateScenarioOrder(log_sizes: []const u8) ValidationError!void {
    for (log_sizes, 0..) |log_size, index| {
        if (log_size >= @bitSizeOf(u64)) return error.InvalidLogSize;
        if (index != 0 and log_sizes[index - 1] >= log_size)
            return error.InvalidScenarioOrder;
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
    const context_degree = std.math.add(
        Degree,
        gate_degree,
        policy.row_mask_degree,
    ) catch return error.DegreeOverflow;
    if (policy.maximum_constraint_degree < context_degree or
        policy.maximum_constraint_degree - context_degree < 1)
    {
        return error.ImpossibleDegreeBudget;
    }
    return context_degree;
}

fn markReachable(
    arena: *const ir.Arena,
    roots: []const types.ValueId,
    reachable: []bool,
) ValidationError!void {
    @memset(reachable, false);
    for (roots) |root| {
        const node = arena.node(root) orelse return error.InvalidRoot;
        if (!node.key.ty.isFieldScalar()) return error.InvalidRootType;
        reachable[types.idIndex(root)] = true;
    }
    var reverse = arena.nodeCount();
    while (reverse > 0) {
        reverse -= 1;
        if (!reachable[reverse]) continue;
        markOperands(reachable, arena.nodesView()[reverse].key.op);
    }
}

fn markOperands(flags: []bool, op: expr.Op) void {
    switch (op) {
        .constant, .input, .hint_output, .call_output => {},
        .add, .sub, .mul => |binary| {
            flags[types.idIndex(binary.lhs)] = true;
            flags[types.idIndex(binary.rhs)] = true;
        },
        .neg => |value| flags[types.idIndex(value)] = true,
        .select => |selection| {
            flags[types.idIndex(selection.selector)] = true;
            flags[types.idIndex(selection.when_true)] = true;
            flags[types.idIndex(selection.when_false)] = true;
        },
    }
}

fn computeDegrees(
    arena: *const ir.Arena,
    reachable: []const bool,
    available: []const bool,
    degrees: []Degree,
) ValidationError!void {
    for (arena.nodesView(), 0..) |node, index| {
        if (!reachable[index]) {
            degrees[index] = 0;
            continue;
        }
        if (available[index]) {
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
        };
    }
}

const no_direct_node = std.math.maxInt(u32);
const FixedEmitter = struct {
    direct: *direct_model.Arena,
    gate: ?u32,

    pub fn constant(self: *FixedEmitter, value: u32) Error!u32 {
        return self.direct.intern(.{ .op = .constant, .value = value });
    }

    pub fn column(
        self: *FixedEmitter,
        namespace_digest: *const fixed_direct.Digest,
        column_value: *const fixed_direct.Column,
        resolved: u64,
    ) Error!u32 {
        return switch (column_value.binding) {
            .gate => self.gate orelse error.MissingFixedGate,
            .component => self.direct.fixedCommitted(
                namespace_digest.*,
                column_value.tree,
                resolved,
            ),
        };
    }

    pub fn binary(
        self: *FixedEmitter,
        op: fixed_direct.BinaryOp,
        lhs: u32,
        rhs: u32,
    ) Error!u32 {
        return self.direct.binary(switch (op) {
            .add => .add,
            .sub => .sub,
            .mul => .mul,
        }, lhs, rhs);
    }

    pub fn neg(self: *FixedEmitter, value: u32) Error!u32 {
        return self.direct.intern(.{ .op = .neg, .lhs = value });
    }
};

fn lowerContext(
    direct: *direct_model.Arena,
    arena: *const ir.Arena,
    gate: ?types.ValueId,
    policy: Policy,
    mapped: []u32,
) Error!?u32 {
    var context: ?u32 = null;
    if (gate) |value| {
        const node = arena.node(value) orelse return error.InvalidGate;
        const lowered = switch (node.key.op) {
            .constant => |constant| try direct.intern(.{
                .op = .constant,
                .value = constantValue(constant),
            }),
            .input, .hint_output, .call_output => try direct.committed(value, false),
            else => return error.UnsupportedGateExpression,
        };
        mapped[types.idIndex(value)] = lowered;
        context = lowered;
    }
    if (policy.row_mask_degree != 0) {
        const mask = try direct.intern(.{
            .op = .row_mask,
            .value = policy.row_mask_degree,
        });
        context = if (context) |prior|
            try direct.binary(.mul, prior, mask)
        else
            mask;
    }
    return context;
}

fn lowerValue(
    direct: *direct_model.Arena,
    arena: *const ir.Arena,
    root: types.ValueId,
    mapped: []u32,
    needed: []bool,
) Error!u32 {
    const root_index = types.idIndex(root);
    if (mapped[root_index] != no_direct_node) return mapped[root_index];
    @memset(needed, false);
    needed[root_index] = true;
    const root_end = std.math.add(usize, root_index, 1) catch
        return error.CountOverflow;
    var reverse = root_end;
    while (reverse > 0) {
        reverse -= 1;
        if (!needed[reverse] or mapped[reverse] != no_direct_node) continue;
        markOperands(needed, arena.nodesView()[reverse].key.op);
    }

    for (arena.nodesView()[0..root_end], 0..) |node, index| {
        if (!needed[index] or mapped[index] != no_direct_node) continue;
        mapped[index] = switch (node.key.op) {
            .constant => |constant| try direct.intern(.{
                .op = .constant,
                .value = constantValue(constant),
            }),
            .input, .hint_output, .call_output => try direct.committed(
                @enumFromInt(index),
                false,
            ),
            .add => |binary| try direct.binary(
                .add,
                try directOperand(mapped, binary.lhs),
                try directOperand(mapped, binary.rhs),
            ),
            .sub => |binary| try direct.binary(
                .sub,
                try directOperand(mapped, binary.lhs),
                try directOperand(mapped, binary.rhs),
            ),
            .mul => |binary| try direct.binary(
                .mul,
                try directOperand(mapped, binary.lhs),
                try directOperand(mapped, binary.rhs),
            ),
            .neg => |value| try direct.intern(.{
                .op = .neg,
                .lhs = try directOperand(mapped, value),
            }),
            .select => |selection| blk: {
                const selector = try directOperand(mapped, selection.selector);
                const when_true = try directOperand(mapped, selection.when_true);
                const when_false = try directOperand(mapped, selection.when_false);
                const difference = try direct.binary(.sub, when_true, when_false);
                const selected = try direct.binary(.mul, selector, difference);
                break :blk try direct.binary(.add, when_false, selected);
            },
        };
    }
    return directOperand(mapped, root);
}

fn directOperand(
    mapped: []const u32,
    value: types.ValueId,
) ValidationError!u32 {
    const index = types.idIndex(value);
    if (index >= mapped.len or mapped[index] == no_direct_node)
        return error.MissingDirectOperand;
    const result = mapped[index];
    return result;
}

fn constantValue(constant: expr.Constant) u64 {
    return switch (constant) {
        .field => |value| value,
        .unsigned => |value| value,
    };
}

fn scenarioCost(
    log_size: u8,
    main_columns: u64,
    interaction_columns: u64,
    cell_bytes: u64,
) ValidationError!ScenarioCost {
    if (log_size >= @bitSizeOf(u64)) return error.InvalidLogSize;
    const rows = @as(u64, 1) << @intCast(log_size);
    const main_cells = try checkedMul(main_columns, rows);
    const interaction_cells = try checkedMul(interaction_columns, rows);
    const committed_cells = try checkedAdd(main_cells, interaction_cells);
    const main_bytes = try checkedMul(main_cells, cell_bytes);
    const interaction_bytes = try checkedMul(interaction_cells, cell_bytes);
    const committed_bytes = try checkedAdd(main_bytes, interaction_bytes);
    return .{
        .log_size = log_size,
        .rows = rows,
        .main_cells = main_cells,
        .interaction_cells = interaction_cells,
        .committed_cells = committed_cells,
        .main_bytes = main_bytes,
        .interaction_bytes = interaction_bytes,
        .committed_bytes = committed_bytes,
    };
}

fn countFlags(flags: []const bool) ValidationError!u64 {
    var count: u64 = 0;
    for (flags) |set| if (set) {
        count = try checkedCountAdd(count, 1);
    };
    return count;
}

fn checkedCountAdd(lhs: u64, rhs: u64) ValidationError!u64 {
    return std.math.add(u64, lhs, rhs) catch error.CountOverflow;
}

fn checkedAdd(lhs: u64, rhs: u64) ValidationError!u64 {
    return std.math.add(u64, lhs, rhs) catch error.GeometryOverflow;
}

fn checkedMul(lhs: u64, rhs: u64) ValidationError!u64 {
    return std.math.mul(u64, lhs, rhs) catch error.GeometryOverflow;
}
