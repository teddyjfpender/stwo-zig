//! Internal verifier arithmetic lowering authority shard; use verifier_arithmetic_lowering.zig publicly.

const dependency_0 = @import("verifier_arithmetic_lowering_reference.zig");

const AddressRange = dependency_0.AddressRange;
const Counts = dependency_0.Counts;
const Error = dependency_0.Error;
const Evaluation = dependency_0.Evaluation;
const Evaluations = dependency_0.Evaluations;
const InputClaimError = dependency_0.InputClaimError;
const InvocationBuffers = dependency_0.InvocationBuffers;
const Lane = dependency_0.Lane;
const Mode = dependency_0.Mode;
const OperationCursors = dependency_0.OperationCursors;
const ProofKind = dependency_0.ProofKind;
const PublicClaimError = dependency_0.PublicClaimError;
const PublicWireTerm = dependency_0.PublicWireTerm;
const QM31 = dependency_0.QM31;
const Reference = dependency_0.Reference;
const checkedAdd = dependency_0.checkedAdd;
const computeUseCountsInto = dependency_0.computeUseCountsInto;
const coordinate = dependency_0.coordinate;
const countGraph = dependency_0.countGraph;
const digest = dependency_0.digest;
const fillLane = dependency_0.fillLane;
const graph_mod = dependency_0.graph_mod;
const inputTermClaim = dependency_0.inputTermClaim;
const inverse = dependency_0.inverse;
const linear = dependency_0.linear;
const maximumNodeCount = dependency_0.maximumNodeCount;
const metaSliceEql = dependency_0.metaSliceEql;
const metadataMatches = dependency_0.metadataMatches;
const multiply = dependency_0.multiply;
const planDigest = dependency_0.planDigest;
const proofMode = dependency_0.proofMode;
const publicSliceEql = dependency_0.publicSliceEql;
const publicTermClaim = dependency_0.publicTermClaim;
const rangeOf = dependency_0.rangeOf;
const relation = dependency_0.relation;
const selectedInverse = dependency_0.selectedInverse;
const selectedLinear = dependency_0.selectedLinear;
const selectedMultiply = dependency_0.selectedMultiply;
const std = dependency_0.std;
const universal = dependency_0.universal;

pub const Plan = struct {
    allocator: std.mem.Allocator,
    multiply_rows: []multiply.PreprocessedRow,
    inverse_rows: []inverse.PreprocessedRow,
    linear_rows: []linear.PreprocessedRow,
    public_terms: []PublicWireTerm,
    mode_counts: [2]Counts,
    reference_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(allocator: std.mem.Allocator, reference: Reference) Error!Plan {
        try reference.validateAuthority();
        const scratch = try allocator.alloc(u32, maximumNodeCount(reference));
        defer allocator.free(scratch);

        var mode_counts = [2]Counts{ .{}, .{} };
        var public_count: usize = 0;
        for (reference.lanes) |lane| {
            const uses = try computeUseCountsInto(lane.graph, scratch);
            const lane_counts = try countGraph(lane.graph, uses);
            const mode_index = @intFromEnum(lane.active_in);
            mode_counts[mode_index] = try mode_counts[mode_index].add(lane_counts);
            public_count = try checkedAdd(public_count, lane_counts.public);
        }

        const multiply_rows = try allocator.alloc(
            multiply.PreprocessedRow,
            @max(mode_counts[0].multiply, mode_counts[1].multiply),
        );
        errdefer allocator.free(multiply_rows);
        const inverse_rows = try allocator.alloc(
            inverse.PreprocessedRow,
            @max(mode_counts[0].inverse, mode_counts[1].inverse),
        );
        errdefer allocator.free(inverse_rows);
        const linear_rows = try allocator.alloc(
            linear.PreprocessedRow,
            @max(mode_counts[0].linear, mode_counts[1].linear),
        );
        errdefer allocator.free(linear_rows);
        const public_terms = try allocator.alloc(PublicWireTerm, public_count);
        errdefer allocator.free(public_terms);
        for (multiply_rows) |*row| row.* = .{};
        for (inverse_rows) |*row| row.* = .{};
        for (linear_rows) |*row| row.* = .{};

        var cursors = [2]OperationCursors{ .{}, .{} };
        var public_cursor: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| {
            const uses = try computeUseCountsInto(lane.graph, scratch);
            try fillLane(
                lane,
                @intCast(lane_index),
                uses,
                multiply_rows,
                inverse_rows,
                linear_rows,
                &cursors[@intFromEnum(lane.active_in)],
                public_terms,
                &public_cursor,
            );
        }
        if (public_cursor != public_terms.len)
            return error.AuthorityMismatch;
        for (cursors, mode_counts) |cursor, mode_count| {
            if (cursor.multiply != mode_count.multiply or
                cursor.inverse != mode_count.inverse or
                cursor.linear != mode_count.linear)
            {
                return error.AuthorityMismatch;
            }
        }

        const authority_digest = planDigest(
            reference.authority_digest,
            multiply_rows,
            inverse_rows,
            linear_rows,
            public_terms,
            mode_counts,
        );
        return .{
            .allocator = allocator,
            .multiply_rows = multiply_rows,
            .inverse_rows = inverse_rows,
            .linear_rows = linear_rows,
            .public_terms = public_terms,
            .mode_counts = mode_counts,
            .reference_digest = reference.authority_digest,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.public_terms);
        self.allocator.free(self.linear_rows);
        self.allocator.free(self.inverse_rows);
        self.allocator.free(self.multiply_rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Plan, reference: Reference) Error!void {
        try reference.validate();
        if (!std.mem.eql(u8, &self.reference_digest, &reference.authority_digest) or
            self.multiply_rows.len != @max(
                self.mode_counts[0].multiply,
                self.mode_counts[1].multiply,
            ) or
            self.inverse_rows.len != @max(
                self.mode_counts[0].inverse,
                self.mode_counts[1].inverse,
            ) or
            self.linear_rows.len != @max(
                self.mode_counts[0].linear,
                self.mode_counts[1].linear,
            ) or
            !std.mem.eql(u8, &self.authority_digest, &planDigest(
                self.reference_digest,
                self.multiply_rows,
                self.inverse_rows,
                self.linear_rows,
                self.public_terms,
                self.mode_counts,
            )))
        {
            return error.AuthorityMismatch;
        }
    }

    pub fn validateAgainstAuthority(
        self: *const Plan,
        allocator: std.mem.Allocator,
        reference: Reference,
    ) Error!void {
        try reference.validateAuthority();
        try self.validateAgainst(reference);
        var expected = try Plan.init(allocator, reference);
        defer expected.deinit();
        if (!std.meta.eql(self.mode_counts, expected.mode_counts) or
            !metaSliceEql(multiply.PreprocessedRow, self.multiply_rows, expected.multiply_rows) or
            !metaSliceEql(inverse.PreprocessedRow, self.inverse_rows, expected.inverse_rows) or
            !metaSliceEql(linear.PreprocessedRow, self.linear_rows, expected.linear_rows) or
            !publicSliceEql(self.public_terms, expected.public_terms) or
            !std.mem.eql(u8, &self.authority_digest, &expected.authority_digest))
        {
            return error.AuthorityMismatch;
        }
    }

    pub fn counts(self: *const Plan, kind: ProofKind) Counts {
        return switch (kind) {
            .segment_leaf => self.mode_counts[@intFromEnum(Mode.segment)],
            .binary_node => self.mode_counts[@intFromEnum(Mode.binary)],
            .empty_leaf => .{},
        };
    }

    pub fn publicBoundaryClaim(
        self: *const Plan,
        kind: ProofKind,
        relations: *const universal.UniversalRelations,
    ) PublicClaimError!QM31 {
        const selected_mode = proofMode(kind) orelse return QM31.zero();
        const challenge = try relations.getExact(.recursion_wire);
        var result = QM31.zero();
        for (self.public_terms) |term| {
            if (term.active_in != selected_mode) continue;
            result = result.add(try publicTermClaim(challenge, term));
        }
        return result;
    }

    /// Recompute the positive `recursion_wire` boundary contributed by every
    /// live graph input in the selected proof mode.
    ///
    /// This is deliberately derived from the authenticated graph, its exact
    /// use multiplicities, and the admitted evaluations.  A caller can compare
    /// it with the independently generated input-component relation claims;
    /// neither side is manufactured by negating the arithmetic providers.
    /// One scratch allocation is reused across all lanes, so the work is
    /// linear in graph nodes and independent of the number of wire uses.
    pub fn inputBoundaryClaim(
        self: *const Plan,
        allocator: std.mem.Allocator,
        reference: Reference,
        evaluations: Evaluations,
        kind: ProofKind,
        relations: *const universal.UniversalRelations,
    ) InputClaimError!QM31 {
        try self.validateAgainst(reference);
        try evaluations.validateAgainst(reference);
        const selected_mode = proofMode(kind) orelse return QM31.zero();
        const challenge = try relations.getExact(.recursion_wire);
        const scratch = try allocator.alloc(u32, maximumNodeCount(reference));
        defer allocator.free(scratch);

        var result = QM31.zero();
        for (reference.lanes, evaluations.lanes) |lane, evaluation| {
            if (lane.active_in != selected_mode) continue;
            const uses = try computeUseCountsInto(lane.graph, scratch);
            for (lane.graph.nodes, evaluation.values, uses, 0..) |
                node,
                value,
                use_count,
                node_id,
            | {
                switch (node.op) {
                    .input => {},
                    else => continue,
                }
                if (use_count == 0) continue;
                result = result.add(try inputTermClaim(
                    challenge,
                    lane.circuit_id,
                    try coordinate(node_id),
                    value,
                    use_count,
                ));
            }
        }
        return result;
    }

    /// Failure-atomic hot materialization. All identities, shapes, aliases and
    /// selected operation coordinates are checked before the first write.
    pub fn materializeInto(
        self: *const Plan,
        reference: Reference,
        evaluations: Evaluations,
        kind: ProofKind,
        buffers: InvocationBuffers,
    ) Error!void {
        try self.validateAgainst(reference);
        try evaluations.validateAgainst(reference);
        const expected = self.counts(kind);
        if (buffers.multiply.len != expected.multiply or
            buffers.inverse.len != expected.inverse or
            buffers.linear.len != expected.linear)
        {
            return error.BufferShapeMismatch;
        }
        try validateBufferAliases(self, reference, evaluations, buffers);
        try validateSelectedOperations(self, reference, kind);

        const selected_mode = proofMode(kind) orelse return;
        var cursors = OperationCursors{};
        for (reference.lanes, evaluations.lanes) |lane, evaluation| {
            if (lane.active_in != selected_mode) continue;
            fillInvocations(
                self,
                lane,
                evaluation,
                &cursors,
                buffers,
            );
        }
        std.debug.assert(cursors.multiply == buffers.multiply.len);
        std.debug.assert(cursors.inverse == buffers.inverse.len);
        std.debug.assert(cursors.linear == buffers.linear.len);
    }
};

pub fn validateSelectedOperations(
    plan: *const Plan,
    reference: Reference,
    kind: ProofKind,
) Error!void {
    const selected_mode = proofMode(kind) orelse return;
    var cursors = OperationCursors{};
    for (reference.lanes) |lane| {
        if (lane.active_in != selected_mode) continue;
        try validateLaneOperations(plan, lane, &cursors);
    }
    const expected = plan.counts(kind);
    if (cursors.multiply != expected.multiply or
        cursors.inverse != expected.inverse or
        cursors.linear != expected.linear)
    {
        return error.AuthorityMismatch;
    }
}

pub fn validateLaneOperations(
    plan: *const Plan,
    lane: Lane,
    cursors: *OperationCursors,
) Error!void {
    for (lane.graph.nodes, 0..) |node, node_id_usize| {
        const node_id = try coordinate(node_id_usize);
        switch (node.op) {
            .input, .constant => {},
            .mul => |operation| {
                if (cursors.multiply >= plan.multiply_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedMultiply(
                    plan.multiply_rows[cursors.multiply],
                    lane.active_in,
                ) orelse return error.InvalidCircuitOperation;
                if (!metadataMatches(
                    actual,
                    lane.circuit_id,
                    node_id,
                    operation.lhs,
                    operation.rhs,
                )) return error.InvalidCircuitOperation;
                cursors.multiply += 1;
            },
            .inverse => |operand| {
                if (cursors.inverse >= plan.inverse_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedInverse(
                    plan.inverse_rows[cursors.inverse],
                    lane.active_in,
                ) orelse return error.InvalidCircuitOperation;
                if (actual.circuit_id.toU32() != lane.circuit_id or
                    actual.node_id.toU32() != node_id or
                    actual.lhs_id.toU32() != operand)
                {
                    return error.InvalidCircuitOperation;
                }
                cursors.inverse += 1;
            },
            .add, .sub => |operation| {
                if (cursors.linear >= plan.linear_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedLinear(
                    plan.linear_rows[cursors.linear],
                    lane.active_in,
                ) orelse return error.InvalidCircuitOperation;
                const expected_kind: linear.Operation = switch (node.op) {
                    .add => .add,
                    .sub => .sub,
                    else => unreachable,
                };
                if (actual.operation != expected_kind or !metadataMatches(
                    actual.circuit,
                    lane.circuit_id,
                    node_id,
                    operation.lhs,
                    operation.rhs,
                )) return error.InvalidCircuitOperation;
                cursors.linear += 1;
            },
            .neg => |operand| {
                if (cursors.linear >= plan.linear_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedLinear(
                    plan.linear_rows[cursors.linear],
                    lane.active_in,
                ) orelse return error.InvalidCircuitOperation;
                if (actual.operation != .neg or
                    actual.circuit.circuit_id.toU32() != lane.circuit_id or
                    actual.circuit.node_id.toU32() != node_id or
                    actual.circuit.lhs_id.toU32() != operand or
                    !actual.circuit.rhs_id.isZero())
                {
                    return error.InvalidCircuitOperation;
                }
                cursors.linear += 1;
            },
        }
    }
}

pub fn fillInvocations(
    plan: *const Plan,
    lane: Lane,
    evaluation: Evaluation,
    cursors: *OperationCursors,
    buffers: InvocationBuffers,
) void {
    for (lane.graph.nodes) |node| switch (node.op) {
        .input, .constant => {},
        .mul => |operation| {
            buffers.multiply[cursors.multiply] = .{
                .a = evaluation.values[operation.lhs],
                .b = evaluation.values[operation.rhs],
                .circuit = selectedMultiply(
                    plan.multiply_rows[cursors.multiply],
                    lane.active_in,
                ).?,
            };
            cursors.multiply += 1;
        },
        .inverse => |operand| {
            buffers.inverse[cursors.inverse] = .{
                .a = evaluation.values[operand],
                .circuit = selectedInverse(
                    plan.inverse_rows[cursors.inverse],
                    lane.active_in,
                ).?,
            };
            cursors.inverse += 1;
        },
        .add, .sub => |operation| {
            const scheduled = selectedLinear(
                plan.linear_rows[cursors.linear],
                lane.active_in,
            ).?;
            buffers.linear[cursors.linear] = .{
                .operation = scheduled.operation,
                .lhs = evaluation.values[operation.lhs],
                .rhs = evaluation.values[operation.rhs],
                .circuit = scheduled.circuit,
            };
            cursors.linear += 1;
        },
        .neg => |operand| {
            const scheduled = selectedLinear(
                plan.linear_rows[cursors.linear],
                lane.active_in,
            ).?;
            buffers.linear[cursors.linear] = .{
                .operation = .neg,
                .lhs = evaluation.values[operand],
                .circuit = scheduled.circuit,
            };
            cursors.linear += 1;
        },
    };
}

pub fn validateBufferAliases(
    plan: *const Plan,
    reference: Reference,
    evaluations: Evaluations,
    buffers: InvocationBuffers,
) Error!void {
    const destinations = [_]?AddressRange{
        try rangeOf(multiply.Invocation, buffers.multiply),
        try rangeOf(inverse.Invocation, buffers.inverse),
        try rangeOf(linear.Invocation, buffers.linear),
    };
    for (destinations, 0..) |maybe_destination, index| {
        const destination = maybe_destination orelse continue;
        for (destinations[0..index]) |maybe_previous| {
            const previous = maybe_previous orelse continue;
            if (destination.overlaps(previous)) return error.AliasedDestination;
        }
        const plan_inputs = [_]?AddressRange{
            try rangeOf(multiply.PreprocessedRow, plan.multiply_rows),
            try rangeOf(inverse.PreprocessedRow, plan.inverse_rows),
            try rangeOf(linear.PreprocessedRow, plan.linear_rows),
            try rangeOf(PublicWireTerm, plan.public_terms),
        };
        for (plan_inputs) |maybe_input| {
            const input = maybe_input orelse continue;
            if (destination.overlaps(input)) return error.AliasedInput;
        }
        for (reference.lanes, evaluations.lanes) |lane, evaluation| {
            const borrowed = [_]?AddressRange{
                try rangeOf(QM31, evaluation.values),
                try rangeOf(graph_mod.Node, lane.graph.nodes),
                try rangeOf(u32, lane.graph.outputs),
            };
            for (borrowed) |maybe_input| {
                const input = maybe_input orelse continue;
                if (destination.overlaps(input)) return error.AliasedInput;
            }
        }
    }
}
