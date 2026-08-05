//! Deterministic degree-bounded materialization for typed scalar AIR graphs.
//!
//! It does not mutate the semantic arena: each descriptor binds a committed
//! value to its logical expression with earlier descriptors as degree-one
//! leaves, forming one lowering seam for every later interpreter.

const std = @import("std");
const digest = @import("digest.zig");
const identity = @import("degree3_materializer_identity.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validator = @import("validate.zig");

pub const policy_id = "stwo.typed-air.materialize.degree-bounded-v1";
pub const policy_version: u16 = 1;
pub const Degree = identity.Degree;
pub const Policy = identity.Policy;
pub const SourceOp = identity.SourceOp;
pub const StableName = identity.StableName;
pub const MaterializationId = enum(u32) { _ };
const no_materialization = std.math.maxInt(u32);
pub const Request = struct {
    roots: []const types.ValueId,
    gate: ?types.ValueId,
    policy: Policy = .{},
};
pub const Reason = enum(u8) { degree, output };

pub const DependencyRange = struct {
    start: u32,
    len: u32,
    fn slice(
        self: DependencyRange,
        values: []const MaterializationId,
    ) ?[]const MaterializationId {
        const start: usize = self.start;
        const end = std.math.add(usize, start, self.len) catch return null;
        if (end > values.len) return null;
        return values[start..end];
    }
};

pub const Materialization = struct {
    source_value: types.ValueId,
    source_op: SourceOp,
    source_span: source.SourceSpan,
    stable_name: StableName,
    fingerprint: digest.Digest,
    reason: Reason,
    structural_use_count: u32,
    dependencies: DependencyRange,
    body_degree: Degree,
    equality_degree: Degree,
    context_degree: Degree,
    constraint_degree: Degree,
};

pub const Output = struct {
    root: types.ValueId,
    materialization: MaterializationId,
};
pub const ValidationError = error{
    CountOverflow,
    DegreeOverflow,
    DuplicateMaterialization,
    EmptyRoots,
    ImpossibleDegreeBudget,
    InvalidDependency,
    InvalidGate,
    InvalidGateType,
    InvalidMaterialization,
    InvalidMaterializationDegree,
    InvalidMaterializationName,
    InvalidMaterializationOrder,
    InvalidOutput,
    InvalidRoot,
    InvalidRootType,
    InvalidStableName,
    ProgramDigestMismatch,
    UnsupportedGateExpression,
};
pub const Error = std.mem.Allocator.Error || validator.Error || ValidationError;

/// Owned policy result. It borrows no arena memory.
pub const Plan = struct {
    allocator: std.mem.Allocator,
    program_digest: digest.Digest,
    gate: ?types.ValueId,
    policy: Policy,
    materializations: []Materialization,
    outputs: []Output,
    dependencies: []MaterializationId,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.dependencies);
        self.allocator.free(self.outputs);
        self.allocator.free(self.materializations);
        self.* = undefined;
    }

    pub fn dependenciesFor(
        self: *const Plan,
        id: MaterializationId,
    ) ?[]const MaterializationId {
        const index = types.idIndex(id);
        if (index >= self.materializations.len) return null;
        const item = self.materializations[index];
        return item.dependencies.slice(self.dependencies);
    }

    /// Re-establishes all degree, dependency, naming, and ordering invariants.
    pub fn validate(
        self: *const Plan,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
    ) Error!void {
        try validator.validate(arena);
        const actual_digest = try digest.compute(arena);
        if (!std.mem.eql(u8, &self.program_digest, &actual_digest))
            return error.ProgramDigestMismatch;
        const context_degree = try validateContext(arena, self.gate, self.policy);
        if (self.outputs.len == 0) return error.EmptyRoots;
        if (self.materializations.len == 0) return error.InvalidOutput;

        const node_count = arena.nodeCount();
        const flags = try allocator.alloc(bool, try multipliedCount(node_count, 7));
        defer allocator.free(flags);
        @memset(flags, false);
        const selected = flags[0 * node_count .. 1 * node_count];
        const emitted = flags[1 * node_count .. 2 * node_count];
        const available = flags[2 * node_count .. 3 * node_count];
        const root_flags = flags[3 * node_count .. 4 * node_count];
        const reachable = flags[4 * node_count .. 5 * node_count];
        const walk = flags[5 * node_count .. 6 * node_count];
        const frontier = flags[6 * node_count .. 7 * node_count];
        const use_counts = try allocator.alloc(u32, node_count);
        defer allocator.free(use_counts);
        const degrees = try allocator.alloc(Degree, node_count);
        defer allocator.free(degrees);

        for (self.materializations) |item| {
            const index = types.idIndex(item.source_value);
            const node = arena.node(item.source_value) orelse
                return error.InvalidMaterialization;
            if (!node.key.ty.isFieldScalar())
                return error.InvalidMaterialization;
            if (selected[index]) return error.DuplicateMaterialization;
            selected[index] = true;
        }
        for (self.outputs) |output| {
            const node = arena.node(output.root) orelse return error.InvalidOutput;
            if (!node.key.ty.isFieldScalar()) return error.InvalidOutput;
            root_flags[types.idIndex(output.root)] = true;
        }
        try analyzeReachability(arena, self.outputs, reachable, use_counts);

        var expected_selector = Selector{
            .arena = arena,
            .reachable = reachable,
            .selected = available,
            .degrees = degrees,
            .use_counts = use_counts,
            .body_limit = self.policy.maximum_constraint_degree - context_degree,
        };
        for (self.outputs) |output| {
            try expected_selector.makeBodyAdmissible(output.root);
            available[types.idIndex(output.root)] = true;
        }
        if (!std.mem.eql(bool, selected, available))
            return error.InvalidMaterialization;
        @memset(available, false);

        var dependency_cursor: usize = 0;
        for (self.materializations) |item| {
            const source_index = types.idIndex(item.source_value);
            if (!reachable[source_index]) return error.InvalidMaterialization;
            const expected_value = try chooseNext(
                arena,
                selected,
                emitted,
                root_flags,
                self.outputs,
                frontier,
                walk,
            );
            if (expected_value != item.source_value)
                return error.InvalidMaterializationOrder;

            const node = arena.node(item.source_value).?;
            if (item.source_op != identity.sourceOp(node.key.op) or
                !std.meta.eql(item.source_span, node.primary_source) or
                item.structural_use_count != use_counts[source_index])
            {
                return error.InvalidMaterialization;
            }
            const expected_reason: Reason = if (root_flags[source_index])
                .output
            else
                .degree;
            if (item.reason != expected_reason) return error.InvalidMaterialization;
            const expected_fingerprint = identity.fingerprint(
                self.program_digest,
                item.source_value,
                self.gate,
                self.policy,
            );
            if (!std.mem.eql(u8, &item.fingerprint, &expected_fingerprint) or
                !identity.validName(
                    item.stable_name,
                    item.source_op,
                    item.source_span,
                    expected_fingerprint,
                ))
            {
                return error.InvalidMaterializationName;
            }

            if (@as(usize, item.dependencies.start) != dependency_cursor)
                return error.InvalidDependency;
            const stored_dependencies = item.dependencies.slice(self.dependencies) orelse
                return error.InvalidDependency;
            try expectDependencies(
                arena,
                item.source_value,
                available,
                self.materializations,
                stored_dependencies,
                frontier,
                walk,
            );
            dependency_cursor += stored_dependencies.len;

            try computeDegrees(arena, reachable, available, degrees);
            const body_degree = degrees[source_index];
            const equality_degree = @max(@as(Degree, 1), body_degree);
            const constraint_degree = try addDegree(equality_degree, context_degree);
            if (body_degree != item.body_degree or
                equality_degree != item.equality_degree or
                context_degree != item.context_degree or
                constraint_degree != item.constraint_degree)
            {
                return error.InvalidMaterializationDegree;
            }
            if (constraint_degree > self.policy.maximum_constraint_degree)
                return error.InvalidMaterializationDegree;
            available[source_index] = true;
            emitted[source_index] = true;
        }
        if (dependency_cursor != self.dependencies.len)
            return error.InvalidDependency;
        for (self.outputs) |output| {
            const index = types.idIndex(output.materialization);
            if (index >= self.materializations.len or
                self.materializations[index].source_value != output.root)
            {
                return error.InvalidOutput;
            }
        }
    }
};

/// Selects and owns a deterministic plan without changing `arena`.
pub fn plan(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    request: Request,
) Error!Plan {
    try validator.validate(arena);
    if (request.roots.len == 0) return error.EmptyRoots;
    const program_digest = try digest.compute(arena);
    const context_degree = try validateContext(arena, request.gate, request.policy);
    const body_limit = request.policy.maximum_constraint_degree - context_degree;
    const node_count = arena.nodeCount();

    const reachable = try allocator.alloc(bool, node_count);
    defer allocator.free(reachable);
    const use_counts = try allocator.alloc(u32, node_count);
    defer allocator.free(use_counts);
    try analyzeReachability(arena, request.roots, reachable, use_counts);
    const selected = try allocator.alloc(bool, node_count);
    defer allocator.free(selected);
    @memset(selected, false);
    const degrees = try allocator.alloc(Degree, node_count);
    defer allocator.free(degrees);

    var selector = Selector{
        .arena = arena,
        .reachable = reachable,
        .selected = selected,
        .degrees = degrees,
        .use_counts = use_counts,
        .body_limit = body_limit,
    };
    for (request.roots) |root| {
        const node = arena.node(root) orelse return error.InvalidRoot;
        if (!node.key.ty.isFieldScalar()) return error.InvalidRootType;
        try selector.makeBodyAdmissible(root);
        selected[types.idIndex(root)] = true;
    }

    var selected_count: usize = 0;
    for (selected) |item| selected_count += @intFromBool(item);
    const ordered_values = try allocator.alloc(types.ValueId, selected_count);
    defer allocator.free(ordered_values);
    const flags = try allocator.alloc(bool, try multipliedCount(node_count, 4));
    defer allocator.free(flags);
    @memset(flags, false);
    const emitted = flags[0 * node_count .. 1 * node_count];
    const root_flags = flags[1 * node_count .. 2 * node_count];
    const walk = flags[2 * node_count .. 3 * node_count];
    const frontier = flags[3 * node_count .. 4 * node_count];
    for (request.roots) |root| root_flags[types.idIndex(root)] = true;
    for (ordered_values) |*value| {
        value.* = try chooseNext(
            arena,
            selected,
            emitted,
            root_flags,
            request.roots,
            frontier,
            walk,
        );
        emitted[types.idIndex(value.*)] = true;
    }

    const materializations = try allocator.alloc(Materialization, selected_count);
    var materializations_owned = true;
    errdefer if (materializations_owned) allocator.free(materializations);
    const outputs = try allocator.alloc(Output, request.roots.len);
    var outputs_owned = true;
    errdefer if (outputs_owned) allocator.free(outputs);
    const available = emitted;
    @memset(available, false);
    var dependencies: std.ArrayList(MaterializationId) = .empty;
    defer dependencies.deinit(allocator);
    const by_value = try allocator.alloc(u32, node_count);
    defer allocator.free(by_value);
    @memset(by_value, no_materialization);

    for (ordered_values, materializations, 0..) |value, *item, index| {
        try computeDegrees(arena, reachable, available, degrees);
        const body_degree = degrees[types.idIndex(value)];
        const equality_degree = @max(@as(Degree, 1), body_degree);
        const constraint_degree = try addDegree(equality_degree, context_degree);
        if (constraint_degree > request.policy.maximum_constraint_degree)
            return error.ImpossibleDegreeBudget;
        const dependency_start = dependencies.items.len;
        try appendDependencies(
            allocator,
            arena,
            value,
            available,
            by_value,
            &dependencies,
            dependency_start,
            frontier,
            walk,
        );
        const dependency_len = dependencies.items.len - dependency_start;
        const node = arena.node(value).?;
        const fingerprint = identity.fingerprint(
            program_digest,
            value,
            request.gate,
            request.policy,
        );
        item.* = .{
            .source_value = value,
            .source_op = identity.sourceOp(node.key.op),
            .source_span = node.primary_source,
            .stable_name = try identity.makeName(
                identity.sourceOp(node.key.op),
                node.primary_source,
                fingerprint,
            ),
            .fingerprint = fingerprint,
            .reason = if (root_flags[types.idIndex(value)]) .output else .degree,
            .structural_use_count = use_counts[types.idIndex(value)],
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
        by_value[types.idIndex(value)] = std.math.cast(u32, index) orelse
            return error.CountOverflow;
        available[types.idIndex(value)] = true;
    }
    for (request.roots, outputs) |root, *output| {
        const mapped = by_value[types.idIndex(root)];
        if (mapped == no_materialization) return error.InvalidOutput;
        output.* = .{ .root = root, .materialization = @enumFromInt(mapped) };
    }
    const owned_dependencies = try dependencies.toOwnedSlice(allocator);
    var result = Plan{
        .allocator = allocator,
        .program_digest = program_digest,
        .gate = request.gate,
        .policy = request.policy,
        .materializations = materializations,
        .outputs = outputs,
        .dependencies = owned_dependencies,
    };
    materializations_owned = false;
    outputs_owned = false;
    errdefer result.deinit();
    try result.validate(allocator, arena);
    return result;
}

const Selector = struct {
    arena: *const ir.Arena,
    reachable: []const bool,
    selected: []bool,
    degrees: []Degree,
    use_counts: []const u32,
    body_limit: Degree,

    fn makeBodyAdmissible(self: *Selector, value: types.ValueId) Error!void {
        while (true) {
            try computeDegrees(
                self.arena,
                self.reachable,
                self.selected,
                self.degrees,
            );
            if (self.degrees[types.idIndex(value)] <= self.body_limit) return;
            const candidate = chooseOperand(
                self.arena.node(value).?.key.op,
                self.selected,
                self.degrees,
                self.use_counts,
                self.body_limit,
            ) orelse return error.ImpossibleDegreeBudget;
            const candidate_was_over =
                self.degrees[types.idIndex(candidate)] > self.body_limit;
            try self.makeBodyAdmissible(candidate);
            try computeDegrees(
                self.arena,
                self.reachable,
                self.selected,
                self.degrees,
            );
            if (self.degrees[types.idIndex(value)] <= self.body_limit) continue;
            switch (self.arena.node(value).?.key.op) {
                .add, .sub, .neg => continue,
                .select => if (candidate_was_over) continue,
                else => {},
            }
            const index = types.idIndex(candidate);
            if (self.selected[index]) return error.ImpossibleDegreeBudget;
            self.selected[index] = true;
        }
    }
};

fn chooseOperand(
    op: expr.Op,
    selected: []const bool,
    degrees: []const Degree,
    use_counts: []const u32,
    limit: Degree,
) ?types.ValueId {
    var candidates: [3]?types.ValueId = .{ null, null, null };
    switch (op) {
        .add, .sub => |binary| {
            const maximum = @max(degreeOf(degrees, binary.lhs), degreeOf(degrees, binary.rhs));
            if (degreeOf(degrees, binary.lhs) == maximum) candidates[0] = binary.lhs;
            if (degreeOf(degrees, binary.rhs) == maximum) candidates[1] = binary.rhs;
        },
        .mul => |binary| {
            candidates[0] = binary.lhs;
            candidates[1] = binary.rhs;
        },
        .neg => |value| candidates[0] = value,
        .select => |selection| {
            candidates[0] = selection.selector;
            const branch_max = @max(
                degreeOf(degrees, selection.when_true),
                degreeOf(degrees, selection.when_false),
            );
            if (degreeOf(degrees, selection.when_true) == branch_max)
                candidates[1] = selection.when_true;
            if (degreeOf(degrees, selection.when_false) == branch_max)
                candidates[2] = selection.when_false;
        },
        .constant, .input, .hint_output, .call_output => return null,
    }
    var best: ?types.ValueId = null;
    for (candidates) |optional| {
        const candidate = optional orelse continue;
        const index = types.idIndex(candidate);
        if (selected[index] or degrees[index] <= 1) continue;
        if (best == null or betterCandidate(
            candidate,
            best.?,
            degrees,
            use_counts,
            limit,
        )) best = candidate;
    }
    return best;
}

fn betterCandidate(
    lhs: types.ValueId,
    rhs: types.ValueId,
    degrees: []const Degree,
    use_counts: []const u32,
    limit: Degree,
) bool {
    const lhs_index = types.idIndex(lhs);
    const rhs_index = types.idIndex(rhs);
    const lhs_excess = degrees[lhs_index] -| limit;
    const rhs_excess = degrees[rhs_index] -| limit;
    if (lhs_excess != rhs_excess) return lhs_excess > rhs_excess;
    if (use_counts[lhs_index] != use_counts[rhs_index])
        return use_counts[lhs_index] > use_counts[rhs_index];
    return lhs_index < rhs_index;
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
    const context = try addDegree(gate_degree, policy.row_mask_degree);
    if (policy.maximum_constraint_degree < context or
        policy.maximum_constraint_degree - context < 1)
    {
        return error.ImpossibleDegreeBudget;
    }
    return context;
}

fn analyzeReachability(
    arena: *const ir.Arena,
    roots: anytype,
    reachable: []bool,
    use_counts: []u32,
) ValidationError!void {
    @memset(reachable, false);
    @memset(use_counts, 0);
    for (roots) |root_item| {
        const root = rootValue(root_item);
        const node = arena.node(root) orelse return error.InvalidRoot;
        if (!node.key.ty.isFieldScalar()) return error.InvalidRootType;
        reachable[types.idIndex(root)] = true;
        use_counts[types.idIndex(root)] = std.math.add(
            u32,
            use_counts[types.idIndex(root)],
            1,
        ) catch return error.CountOverflow;
    }
    var reverse = arena.nodeCount();
    while (reverse > 0) {
        reverse -= 1;
        if (!reachable[reverse]) continue;
        for (operands(arena.nodesView()[reverse].key.op)) |optional| {
            const operand = optional orelse continue;
            const index = types.idIndex(operand);
            reachable[index] = true;
            use_counts[index] = std.math.add(u32, use_counts[index], 1) catch
                return error.CountOverflow;
        }
    }
}

fn computeDegrees(
    arena: *const ir.Arena,
    reachable: []const bool,
    materialized: []const bool,
    degrees: []Degree,
) ValidationError!void {
    for (arena.nodesView(), 0..) |node, index| {
        if (!reachable[index]) {
            degrees[index] = 0;
            continue;
        }
        if (materialized[index]) {
            degrees[index] = 1;
            continue;
        }
        degrees[index] = switch (node.key.op) {
            .constant => 0,
            .input, .hint_output, .call_output => 1,
            .add, .sub => |binary| @max(degreeOf(degrees, binary.lhs), degreeOf(degrees, binary.rhs)),
            .mul => |binary| try addDegree(degreeOf(degrees, binary.lhs), degreeOf(degrees, binary.rhs)),
            .neg => |value| degreeOf(degrees, value),
            .select => |selection| try addDegree(
                degreeOf(degrees, selection.selector),
                @max(
                    degreeOf(degrees, selection.when_true),
                    degreeOf(degrees, selection.when_false),
                ),
            ),
        };
    }
}

fn chooseNext(
    arena: *const ir.Arena,
    selected: []const bool,
    emitted: []const bool,
    root_flags: []const bool,
    roots: anytype,
    frontier: []bool,
    walk: []bool,
) ValidationError!types.ValueId {
    for (selected, 0..) |is_selected, index| {
        if (!is_selected or emitted[index] or root_flags[index]) continue;
        const value = types.idFromIndex(types.ValueId, index) catch
            return error.CountOverflow;
        if (dependenciesEmitted(arena, value, selected, emitted, frontier, walk))
            return value;
    }
    for (roots) |root_item| {
        const value = rootValue(root_item);
        const index = types.idIndex(value);
        if (!selected[index] or emitted[index]) continue;
        if (dependenciesEmitted(arena, value, selected, emitted, frontier, walk))
            return value;
    }
    return error.InvalidMaterializationOrder;
}

fn dependenciesEmitted(
    arena: *const ir.Arena,
    root: types.ValueId,
    selected: []const bool,
    emitted: []const bool,
    frontier: []bool,
    walk: []bool,
) bool {
    markFrontier(arena, root, selected, frontier, walk);
    for (frontier, emitted) |is_dependency, is_emitted| {
        if (is_dependency and !is_emitted) return false;
    }
    return true;
}

fn markFrontier(
    arena: *const ir.Arena,
    root: types.ValueId,
    boundaries: []const bool,
    frontier: []bool,
    walk: []bool,
) void {
    @memset(frontier, false);
    @memset(walk, false);
    const root_index = types.idIndex(root);
    walk[root_index] = true;
    var reverse = root_index + 1;
    while (reverse > 0) {
        reverse -= 1;
        if (!walk[reverse]) continue;
        if (reverse != root_index and boundaries[reverse]) {
            frontier[reverse] = true;
            continue;
        }
        for (operands(arena.nodesView()[reverse].key.op)) |optional| {
            const operand = optional orelse continue;
            walk[types.idIndex(operand)] = true;
        }
    }
}

fn appendDependencies(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    root: types.ValueId,
    available: []const bool,
    by_value: []const u32,
    output: *std.ArrayList(MaterializationId),
    start: usize,
    frontier: []bool,
    walk: []bool,
) Error!void {
    markFrontier(arena, root, available, frontier, walk);
    for (frontier, by_value) |is_dependency, mapped| {
        if (!is_dependency) continue;
        if (mapped == no_materialization) return error.InvalidDependency;
        try output.append(allocator, @enumFromInt(mapped));
    }
    std.mem.sort(MaterializationId, output.items[start..], {}, materializationIdLessThan);
}

fn expectDependencies(
    arena: *const ir.Arena,
    root: types.ValueId,
    available: []const bool,
    materializations: []const Materialization,
    stored: []const MaterializationId,
    frontier: []bool,
    walk: []bool,
) ValidationError!void {
    markFrontier(arena, root, available, frontier, walk);
    var prior: ?MaterializationId = null;
    for (stored) |id| {
        const index = types.idIndex(id);
        if (index >= materializations.len or
            (prior != null and types.idIndex(prior.?) >= index))
        {
            return error.InvalidDependency;
        }
        const source_index = types.idIndex(materializations[index].source_value);
        if (!frontier[source_index]) return error.InvalidDependency;
        frontier[source_index] = false;
        prior = id;
    }
    for (frontier) |remaining| if (remaining) return error.InvalidDependency;
}

fn materializationIdLessThan(_: void, lhs: MaterializationId, rhs: MaterializationId) bool {
    return types.idIndex(lhs) < types.idIndex(rhs);
}

fn rootValue(item: anytype) types.ValueId {
    return if (@TypeOf(item) == Output) item.root else item;
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
    };
}

fn degreeOf(degrees: []const Degree, value: types.ValueId) Degree {
    return degrees[types.idIndex(value)];
}
fn addDegree(lhs: Degree, rhs: Degree) ValidationError!Degree {
    return std.math.add(Degree, lhs, rhs) catch error.DegreeOverflow;
}

fn multipliedCount(count: usize, factor: usize) ValidationError!usize {
    return std.math.mul(usize, count, factor) catch error.CountOverflow;
}
