//! Prepared host evaluation for authenticated variable-partition lookup
//! polynomial programs.
//!
//! All fallible validation and scratch allocation happens in `init`. A caller
//! retains one evaluator per worker lane; `evaluateRow` then performs no
//! allocation, hashing, symbolic dispatch, or partition search.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const component_prover = @import("component_prover.zig");
const prepared_domain = @import("prepared_domain.zig");
const task_graph = @import("../task_graph.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Program = component_prover.OwnedLookupPolynomialProgramV2;
const Authority = component_prover.LookupPolynomialAuthorityV2;
const Capability = component_prover.LookupPolynomialCapabilityV2;

pub const MAX_MAIN_COLUMNS: usize = 128;
pub const MAX_PROGRAM_NODES: usize = 8192;
pub const MAX_LOOKUP_ENTRIES: usize = 64;
pub const MAX_LOOKUP_BATCHES: usize = 64;
pub const EVALUATE_ROW_ALLOCATION_COUNT: usize = 0;

pub const PreparedEvaluator = struct {
    allocator: std.mem.Allocator,
    layout: component_prover.LookupPolynomialLayoutV2,
    nodes: []const component_prover.BasePolynomialNode,
    entries: []const component_prover.LookupPolynomialEntry,
    batches: []const component_prover.LookupPolynomialBatchV2,
    parameters: []const QM31,
    relation_parameter_count: usize,
    node_values: []M31,
    denominators: []QM31,
    constraints: []QM31,
    scratch_bytes: usize,

    /// `program` and `parameters` remain borrowed and immutable until deinit.
    /// Scratch is private to this evaluator, so separate worker lanes cannot
    /// race even when they share the same authenticated program owner.
    pub fn init(
        allocator: std.mem.Allocator,
        program: *const Program,
        authority: *const Authority,
        parameters: []const QM31,
    ) !PreparedEvaluator {
        try program.validateAgainst(authority);
        if (@as(usize, program.layout.column_count) > MAX_MAIN_COLUMNS or
            program.nodes.len > MAX_PROGRAM_NODES or
            program.entries.len > MAX_LOOKUP_ENTRIES or
            program.batches.len > MAX_LOOKUP_BATCHES)
        {
            return error.InvalidPreparedCapacity;
        }
        const parameter_count = try program.parameterCount();
        if (parameters.len != parameter_count or
            parameters.len < program.batches.len)
        {
            return error.InvalidParameterCount;
        }
        const scratch_bytes = try evaluatorScratchBytes(
            program.nodes.len,
            program.entries.len,
            program.batches.len,
        );
        const node_values = try allocator.alloc(M31, program.nodes.len);
        errdefer allocator.free(node_values);
        const denominators = try allocator.alloc(QM31, program.entries.len);
        errdefer allocator.free(denominators);
        const constraints = try allocator.alloc(QM31, program.batches.len);
        errdefer allocator.free(constraints);
        return .{
            .allocator = allocator,
            .layout = program.layout,
            .nodes = program.nodes,
            .entries = program.entries,
            .batches = program.batches,
            .parameters = parameters,
            .relation_parameter_count = parameters.len - program.batches.len,
            .node_values = node_values,
            .denominators = denominators,
            .constraints = constraints,
            .scratch_bytes = scratch_bytes,
        };
    }

    pub fn deinit(self: *PreparedEvaluator) void {
        const allocator = self.allocator;
        allocator.free(self.constraints);
        allocator.free(self.denominators);
        allocator.free(self.node_values);
        self.* = undefined;
    }

    pub fn resources(self: *const PreparedEvaluator) task_graph.ResourceReservation {
        return .{
            .shared_resident_bytes = self.scratch_bytes,
            .worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        };
    }

    /// Returns a borrowed slice overwritten by the next call. Setup has
    /// already authenticated every node root and batch range; the hot path
    /// retains only exact input-shape checks before straight-line DAG replay.
    pub fn evaluateRow(
        self: *PreparedEvaluator,
        main: []const M31,
        current: []const QM31,
        previous: []const QM31,
        selector: M31,
    ) ![]const QM31 {
        if (main.len != @as(usize, self.layout.column_count) or
            current.len != self.batches.len or
            previous.len != self.batches.len)
        {
            return error.InvalidPreparedInputShape;
        }

        for (self.nodes, 0..) |node, index| {
            self.node_values[index] = switch (node.op) {
                .constant => M31.fromCanonical(node.value),
                .column => main[node.value],
                .add => self.node_values[node.lhs].add(self.node_values[node.rhs]),
                .sub => self.node_values[node.lhs].sub(self.node_values[node.rhs]),
                .mul => self.node_values[node.lhs].mul(self.node_values[node.rhs]),
                .neg => M31.zero().sub(self.node_values[node.lhs]),
            };
            std.debug.assert(node.op == .constant or node.op == .column or
                node.lhs < index);
        }

        var parameter_cursor: usize = 0;
        for (self.entries, self.denominators) |entry, *denominator| {
            denominator.* = QM31.zero();
            for (entry.values[0..entry.arity], 0..) |root, value_index| {
                denominator.* = denominator.add(
                    self.parameters[parameter_cursor + 1 + value_index]
                        .mulM31(self.node_values[root]),
                );
            }
            denominator.* = denominator.sub(self.parameters[parameter_cursor]);
            parameter_cursor += 1 + entry.arity;
        }
        std.debug.assert(parameter_cursor == self.relation_parameter_count);

        for (self.batches, self.constraints, 0..) |batch, *constraint, index| {
            const first: usize = @as(usize, batch.first_entry);
            const claim = self.parameters[self.relation_parameter_count + index];
            const delta = current[index].sub(previous[index]).add(
                claim.mulM31(selector),
            );
            const first_numerator = self.node_values[self.entries[first].numerator];
            if (batch.entry_count == 1) {
                constraint.* = delta.mul(self.denominators[first]).sub(
                    QM31.fromBase(first_numerator),
                );
                continue;
            }
            const second = first + 1;
            const second_numerator =
                self.node_values[self.entries[second].numerator];
            constraint.* = delta.mul(self.denominators[first])
                .mul(self.denominators[second])
                .sub(self.denominators[second].mulM31(first_numerator))
                .sub(self.denominators[first].mulM31(second_numerator));
        }
        return self.constraints;
    }
};

/// Cold owner produced from the backend capability. It proves exporter,
/// authority, geometry, and parameter agreement before exposing the
/// allocation-free row evaluator.
pub const PreparedCapability = struct {
    allocator: std.mem.Allocator,
    authority: Authority,
    program: Program,
    parameters: []QM31,
    evaluator: PreparedEvaluator,
    resident_bytes: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        ctx: *const anyopaque,
        capability: Capability,
        expected_constraint_count: usize,
    ) !PreparedCapability {
        try capability.authority.validate();
        _ = std.math.add(
            usize,
            capability.first_main_column,
            capability.main_column_count,
        ) catch return error.InvalidCapabilityGeometry;
        _ = std.math.add(
            usize,
            capability.first_interaction_column,
            capability.interaction_column_count,
        ) catch return error.InvalidCapabilityGeometry;
        if (capability.trace_log_size == 0 or
            capability.main_column_count == 0 or
            capability.interaction_column_count == 0 or
            expected_constraint_count !=
                @as(usize, capability.authority.batch_count) or
            capability.interaction_column_count !=
                @as(usize, capability.authority.interaction_column_count))
        {
            return error.InvalidCapabilityGeometry;
        }

        var program = try capability.export_program(ctx, allocator);
        var program_owned = true;
        defer if (program_owned) program.deinit();
        try program.validateAgainst(capability.authority);
        if (@as(usize, program.layout.column_count) !=
            capability.main_column_count or
            program.batchCount() != expected_constraint_count or
            program.interactionColumnCount() !=
                capability.interaction_column_count)
        {
            return error.InvalidCapabilityGeometry;
        }

        const parameters = try capability.export_parameters(ctx, allocator);
        var parameters_owned = true;
        defer if (parameters_owned) allocator.free(parameters);
        if (parameters.len != try program.parameterCount())
            return error.InvalidParameterCount;

        var evaluator = try PreparedEvaluator.init(
            allocator,
            &program,
            capability.authority,
            parameters,
        );
        var evaluator_owned = true;
        defer if (evaluator_owned) evaluator.deinit();
        const resident_bytes = try capabilityResidentBytes(
            &program,
            parameters.len,
            evaluator.scratch_bytes,
        );
        program_owned = false;
        parameters_owned = false;
        evaluator_owned = false;
        return .{
            .allocator = allocator,
            .authority = capability.authority.*,
            .program = program,
            .parameters = parameters,
            .evaluator = evaluator,
            .resident_bytes = resident_bytes,
        };
    }

    pub fn deinit(self: *PreparedCapability) void {
        const allocator = self.allocator;
        self.evaluator.deinit();
        allocator.free(self.parameters);
        self.program.deinit();
        self.* = undefined;
    }

    pub fn resources(self: *const PreparedCapability) task_graph.ResourceReservation {
        return .{
            .shared_resident_bytes = self.resident_bytes,
            .worker_stack_bytes = prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        };
    }
};

pub fn evaluatorScratchBytes(
    node_count: usize,
    entry_count: usize,
    batch_count: usize,
) !usize {
    const nodes = std.math.mul(usize, node_count, @sizeOf(M31)) catch
        return error.ResourceReservationOverflow;
    const denominators = std.math.mul(usize, entry_count, @sizeOf(QM31)) catch
        return error.ResourceReservationOverflow;
    const constraints = std.math.mul(usize, batch_count, @sizeOf(QM31)) catch
        return error.ResourceReservationOverflow;
    const first = std.math.add(usize, nodes, denominators) catch
        return error.ResourceReservationOverflow;
    const total = std.math.add(usize, first, constraints) catch
        return error.ResourceReservationOverflow;
    if (node_count == 0 or entry_count == 0 or batch_count == 0 or
        node_count > MAX_PROGRAM_NODES or entry_count > MAX_LOOKUP_ENTRIES or
        batch_count > MAX_LOOKUP_BATCHES)
    {
        return error.InvalidPreparedCapacity;
    }
    return total;
}

pub fn capabilityResidentBytes(
    program: *const Program,
    parameter_count: usize,
    scratch_bytes: usize,
) !usize {
    var total = scratch_bytes;
    inline for (.{
        .{ program.nodes.len, @sizeOf(component_prover.BasePolynomialNode) },
        .{ program.entries.len, @sizeOf(component_prover.LookupPolynomialEntry) },
        .{ program.event_degrees.len, @sizeOf(component_prover.LookupPolynomialEventDegreeV2) },
        .{ program.batches.len, @sizeOf(component_prover.LookupPolynomialBatchV2) },
        .{ parameter_count, @sizeOf(QM31) },
    }) |term| {
        const bytes = std.math.mul(usize, term[0], term[1]) catch
            return error.ResourceReservationOverflow;
        total = std.math.add(usize, total, bytes) catch
            return error.ResourceReservationOverflow;
    }
    return total;
}
