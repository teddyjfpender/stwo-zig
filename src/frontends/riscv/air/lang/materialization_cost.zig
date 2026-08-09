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
const direct_program = @import("materialization_direct_program.zig");
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
    direct_program.Error ||
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
        available[types.idIndex(value)] = true;
    }

    const materialization_column_start: u64 = if (request.fixed_direct_program) |program|
        program.materialization_column_start
    else
        request.geometry.base_main_columns;
    var lowered = try direct_program.extractValidated(allocator, arena, .{
        .gate = request.gate,
        .policy = request.policy,
        .selected = request.selected,
        .materialization_column_start = materialization_column_start,
        .fixed_direct_program = request.fixed_direct_program,
    });
    defer lowered.deinit();

    const direct_root_count = try checkedAdd(materialization_count, fixed_root_count);
    if (lowered.counts.root_uses != direct_root_count)
        return error.CountOverflow;

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
            .canonical_direct_nodes = lowered.counts.nodes,
            .canonical_direct_additions = lowered.counts.additions,
            .canonical_direct_subtractions = lowered.counts.subtractions,
            .canonical_direct_negations = lowered.counts.negations,
            .canonical_direct_multiplications = lowered.counts.multiplications,
            .unique_committed_column_reads = lowered.counts.unique_committed_column_reads,
            .canonical_streaming_peak_live_nodes = lowered.counts.streaming_peak_live_nodes,
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
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| flags[types.idIndex(address.index)] = true,
            .aligned_word_address => |address| flags[types.idIndex(address.word_index)] = true,
            .access_clock => |clock| flags[types.idIndex(clock.instruction_clock)] = true,
            .strict_clock_gap => |gap| {
                flags[types.idIndex(gap.current_clock)] = true;
                flags[types.idIndex(gap.previous_clock)] = true;
            },
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
