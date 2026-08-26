//! Internal fri verifier lowering authority shard; use fri_verifier_lowering.zig publicly.

const dependency_0 = @import("fri_verifier_lowering_core.zig");

const ActivePublicTerms = dependency_0.ActivePublicTerms;
const AddressRange = dependency_0.AddressRange;
const Counts = dependency_0.Counts;
const Error = dependency_0.Error;
const Evaluations = dependency_0.Evaluations;
const InvocationBuffers = dependency_0.InvocationBuffers;
const Mode = dependency_0.Mode;
const OperationCursors = dependency_0.OperationCursors;
const ProofKind = dependency_0.ProofKind;
const PublicClaimError = dependency_0.PublicClaimError;
const PublicWireTerm = dependency_0.PublicWireTerm;
const QM31 = dependency_0.QM31;
const Reference = dependency_0.Reference;
const checkedAdd = dependency_0.checkedAdd;
const circuit_mod = dependency_0.circuit_mod;
const coordinate = dependency_0.coordinate;
const countLane = dependency_0.countLane;
const digest = dependency_0.digest;
const fillLane = dependency_0.fillLane;
const graph_mod = dependency_0.graph_mod;
const input_witness = dependency_0.input_witness;
const inverse = dependency_0.inverse;
const linear = dependency_0.linear;
const maximumNodeCount = dependency_0.maximumNodeCount;
const metaSliceEql = dependency_0.metaSliceEql;
const metadataMatches = dependency_0.metadataMatches;
const multiply = dependency_0.multiply;
const planDigest = dependency_0.planDigest;
const publicSliceEql = dependency_0.publicSliceEql;
const publicTermClaim = dependency_0.publicTermClaim;
const rangeOf = dependency_0.rangeOf;
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
    lane_counts: [3]Counts,
    public_offsets: [4]usize,
    reference_digest: digest.Digest,
    authority_digest: digest.Digest,

    pub fn init(allocator: std.mem.Allocator, reference: Reference) Error!Plan {
        try reference.validateAuthority();
        const scratch = try allocator.alloc(u32, maximumNodeCount(reference));
        defer allocator.free(scratch);

        var lane_counts: [3]Counts = undefined;
        var public_total: usize = 0;
        for (reference.lanes, 0..) |lane, lane_index| {
            const uses = try circuit_mod.computeUseCountsInto(lane.circuit, scratch);
            lane_counts[lane_index] = try countLane(lane.circuit, uses);
            public_total = try checkedAdd(public_total, lane_counts[lane_index].public);
        }
        const segment = lane_counts[0];
        const binary = try lane_counts[1].add(lane_counts[2]);
        const multiply_rows = try allocator.alloc(
            multiply.PreprocessedRow,
            @max(segment.multiply, binary.multiply),
        );
        errdefer allocator.free(multiply_rows);
        const inverse_rows = try allocator.alloc(
            inverse.PreprocessedRow,
            @max(segment.inverse, binary.inverse),
        );
        errdefer allocator.free(inverse_rows);
        const linear_rows = try allocator.alloc(
            linear.PreprocessedRow,
            @max(segment.linear, binary.linear),
        );
        errdefer allocator.free(linear_rows);
        const public_terms = try allocator.alloc(PublicWireTerm, public_total);
        errdefer allocator.free(public_terms);
        for (multiply_rows) |*row| row.* = .{};
        for (inverse_rows) |*row| row.* = .{};
        for (linear_rows) |*row| row.* = .{};

        var mode_cursors = [2]OperationCursors{ .{}, .{} };
        var public_cursor: usize = 0;
        var public_offsets = [_]usize{0} ** 4;
        for (reference.lanes, 0..) |lane, lane_index| {
            public_offsets[lane_index] = public_cursor;
            const uses = try circuit_mod.computeUseCountsInto(lane.circuit, scratch);
            try fillLane(
                lane,
                @intCast(lane_index),
                if (lane_index == 0) .segment else .binary,
                uses,
                multiply_rows,
                inverse_rows,
                linear_rows,
                &mode_cursors[if (lane_index == 0) 0 else 1],
                public_terms,
                &public_cursor,
            );
        }
        public_offsets[3] = public_cursor;
        if (public_cursor != public_terms.len or
            mode_cursors[0].multiply != segment.multiply or
            mode_cursors[0].inverse != segment.inverse or
            mode_cursors[0].linear != segment.linear or
            mode_cursors[1].multiply != binary.multiply or
            mode_cursors[1].inverse != binary.inverse or
            mode_cursors[1].linear != binary.linear)
        {
            return error.AuthorityMismatch;
        }
        const authority_digest = planDigest(
            reference.authority_digest,
            multiply_rows,
            inverse_rows,
            linear_rows,
            public_terms,
            lane_counts,
            public_offsets,
        );
        return .{
            .allocator = allocator,
            .multiply_rows = multiply_rows,
            .inverse_rows = inverse_rows,
            .linear_rows = linear_rows,
            .public_terms = public_terms,
            .lane_counts = lane_counts,
            .public_offsets = public_offsets,
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
        const segment = self.lane_counts[0];
        const binary = try self.lane_counts[1].add(self.lane_counts[2]);
        if (!std.mem.eql(u8, &self.reference_digest, &reference.authority_digest) or
            self.multiply_rows.len != @max(segment.multiply, binary.multiply) or
            self.inverse_rows.len != @max(segment.inverse, binary.inverse) or
            self.linear_rows.len != @max(segment.linear, binary.linear) or
            self.public_offsets[0] != 0 or
            self.public_offsets[3] != self.public_terms.len or
            self.public_offsets[0] > self.public_offsets[1] or
            self.public_offsets[1] > self.public_offsets[2] or
            self.public_offsets[2] > self.public_offsets[3])
        {
            return error.AuthorityMismatch;
        }
        const actual = planDigest(
            self.reference_digest,
            self.multiply_rows,
            self.inverse_rows,
            self.linear_rows,
            self.public_terms,
            self.lane_counts,
            self.public_offsets,
        );
        if (!std.mem.eql(u8, &actual, &self.authority_digest))
            return error.AuthorityMismatch;
    }

    /// Cold audit that recompiles the complete operation and public-anchor
    /// schedule from verifier-owned circuits. Proof-time callers use the
    /// allocation-free sealed check above.
    pub fn validateAgainstAuthority(
        self: *const Plan,
        allocator: std.mem.Allocator,
        reference: Reference,
    ) Error!void {
        try reference.validateAuthority();
        try self.validateAgainst(reference);
        var expected = try Plan.init(allocator, reference);
        defer expected.deinit();
        if (!std.meta.eql(self.lane_counts, expected.lane_counts) or
            !std.meta.eql(self.public_offsets, expected.public_offsets) or
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
            .segment_leaf => self.lane_counts[0],
            .binary_node => .{
                .multiply = self.lane_counts[1].multiply + self.lane_counts[2].multiply,
                .inverse = self.lane_counts[1].inverse + self.lane_counts[2].inverse,
                .linear = self.lane_counts[1].linear + self.lane_counts[2].linear,
                .public = self.lane_counts[1].public + self.lane_counts[2].public,
            },
            .empty_leaf => .{},
        };
    }

    pub fn publicTerms(self: *const Plan, kind: ProofKind) ActivePublicTerms {
        return switch (kind) {
            .segment_leaf => .{
                .first = self.public_terms[self.public_offsets[0]..self.public_offsets[1]],
                .second = &.{},
            },
            .binary_node => .{
                .first = self.public_terms[self.public_offsets[1]..self.public_offsets[2]],
                .second = self.public_terms[self.public_offsets[2]..self.public_offsets[3]],
            },
            .empty_leaf => .{ .first = &.{}, .second = &.{} },
        };
    }

    /// Evaluates the verifier-owned constant/output boundary of the selected
    /// arithmetic graph under the same universal `wire(6)` challenge used by
    /// rows 29--32. The four committed component claims plus this public claim
    /// must close to zero; no caller may silently discard graph constants or
    /// designated zero outputs.
    pub fn publicBoundaryClaim(
        self: *const Plan,
        kind: ProofKind,
        relations: *const universal.UniversalRelations,
    ) PublicClaimError!QM31 {
        const challenge = try relations.getExact(.recursion_wire);
        const active = self.publicTerms(kind);
        var result = QM31.zero();
        for (active.first) |term|
            result = result.add(try publicTermClaim(challenge, term));
        for (active.second) |term|
            result = result.add(try publicTermClaim(challenge, term));
        return result;
    }

    /// Materializes exact row-30--32 invocations into preallocated buffers.
    /// Every shape, alias, circuit, schedule, and mode check completes before
    /// the first write, preserving failure atomicity.
    pub fn materializeInto(
        self: *const Plan,
        reference: Reference,
        evaluations: Evaluations,
        kind: ProofKind,
        buffers: InvocationBuffers,
    ) Error!void {
        try self.validateAgainst(reference);
        const expected = self.counts(kind);
        if (buffers.multiply.len != expected.multiply or
            buffers.inverse.len != expected.inverse or
            buffers.linear.len != expected.linear)
        {
            return error.BufferShapeMismatch;
        }
        try validateBufferAliases(self, reference, evaluations, buffers);
        try input_witness.validateEvaluationsHot(reference, evaluations, kind);
        try validateSelectedOperations(self, reference, kind);

        var cursors = OperationCursors{};
        switch (kind) {
            .segment_leaf => fillInvocations(
                self,
                reference.lanes[0],
                evaluations.segment,
                .segment,
                &cursors,
                buffers,
            ),
            .binary_node => {
                fillInvocations(
                    self,
                    reference.lanes[1],
                    evaluations.left,
                    .binary,
                    &cursors,
                    buffers,
                );
                fillInvocations(
                    self,
                    reference.lanes[2],
                    evaluations.right,
                    .binary,
                    &cursors,
                    buffers,
                );
            },
            .empty_leaf => {},
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
    var cursors = OperationCursors{};
    switch (kind) {
        .segment_leaf => try validateLaneOperations(
            plan,
            reference.lanes[0],
            .segment,
            &cursors,
        ),
        .binary_node => {
            try validateLaneOperations(plan, reference.lanes[1], .binary, &cursors);
            try validateLaneOperations(plan, reference.lanes[2], .binary, &cursors);
        },
        .empty_leaf => {},
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
    lane: input_witness.Lane,
    mode: Mode,
    cursors: *OperationCursors,
) Error!void {
    for (lane.circuit.nodes, 0..) |node, node_id_usize| {
        const node_id = try coordinate(node_id_usize);
        switch (node.op) {
            .input, .constant => {},
            .mul => |op| {
                if (cursors.multiply >= plan.multiply_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedMultiply(plan.multiply_rows[cursors.multiply], mode) orelse
                    return error.InvalidCircuitOperation;
                if (!metadataMatches(actual, lane.circuit_id, node_id, op.lhs, op.rhs))
                    return error.InvalidCircuitOperation;
                cursors.multiply += 1;
            },
            .inverse => |operand| {
                if (cursors.inverse >= plan.inverse_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedInverse(plan.inverse_rows[cursors.inverse], mode) orelse
                    return error.InvalidCircuitOperation;
                if (actual.circuit_id.toU32() != lane.circuit_id or
                    actual.node_id.toU32() != node_id or
                    actual.lhs_id.toU32() != operand)
                {
                    return error.InvalidCircuitOperation;
                }
                cursors.inverse += 1;
            },
            .add, .sub => |op| {
                if (cursors.linear >= plan.linear_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedLinear(plan.linear_rows[cursors.linear], mode) orelse
                    return error.InvalidCircuitOperation;
                const expected_operation: linear.Operation = switch (node.op) {
                    .add => .add,
                    .sub => .sub,
                    else => unreachable,
                };
                if (actual.operation != expected_operation or
                    !metadataMatches(actual.circuit, lane.circuit_id, node_id, op.lhs, op.rhs))
                {
                    return error.InvalidCircuitOperation;
                }
                cursors.linear += 1;
            },
            .neg => |operand| {
                if (cursors.linear >= plan.linear_rows.len)
                    return error.InvalidCircuitOperation;
                const actual = selectedLinear(plan.linear_rows[cursors.linear], mode) orelse
                    return error.InvalidCircuitOperation;
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
    lane: input_witness.Lane,
    evaluation: *const circuit_mod.Evaluation,
    mode: Mode,
    cursors: *OperationCursors,
    buffers: InvocationBuffers,
) void {
    for (lane.circuit.nodes) |node| switch (node.op) {
        .input, .constant => {},
        .mul => |op| {
            const metadata = selectedMultiply(plan.multiply_rows[cursors.multiply], mode).?;
            buffers.multiply[cursors.multiply] = .{
                .a = evaluation.values[op.lhs],
                .b = evaluation.values[op.rhs],
                .circuit = metadata,
            };
            cursors.multiply += 1;
        },
        .inverse => |operand| {
            const metadata = selectedInverse(plan.inverse_rows[cursors.inverse], mode).?;
            buffers.inverse[cursors.inverse] = .{
                .a = evaluation.values[operand],
                .circuit = metadata,
            };
            cursors.inverse += 1;
        },
        .add, .sub => |op| {
            const scheduled = selectedLinear(plan.linear_rows[cursors.linear], mode).?;
            buffers.linear[cursors.linear] = .{
                .operation = scheduled.operation,
                .lhs = evaluation.values[op.lhs],
                .rhs = evaluation.values[op.rhs],
                .circuit = scheduled.circuit,
            };
            cursors.linear += 1;
        },
        .neg => |operand| {
            const scheduled = selectedLinear(plan.linear_rows[cursors.linear], mode).?;
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
    for (destinations, 0..) |maybe_destination, index| if (maybe_destination) |destination| {
        for (destinations[0..index]) |maybe_previous| if (maybe_previous) |previous| {
            if (destination.overlaps(previous)) return error.AliasedDestination;
        };
        const plan_ranges = [_]?AddressRange{
            try rangeOf(multiply.PreprocessedRow, plan.multiply_rows),
            try rangeOf(inverse.PreprocessedRow, plan.inverse_rows),
            try rangeOf(linear.PreprocessedRow, plan.linear_rows),
            try rangeOf(PublicWireTerm, plan.public_terms),
        };
        for (plan_ranges) |maybe_input| if (maybe_input) |input| {
            if (destination.overlaps(input)) return error.AliasedInput;
        };
        for (reference.lanes, 0..) |lane, lane_index| {
            const evaluation = evaluations.at(lane_index);
            const borrowed = [_]?AddressRange{
                try rangeOf(QM31, evaluation.values),
                try rangeOf(graph_mod.Node, lane.circuit.nodes),
                try rangeOf(u32, lane.circuit.outputs),
                try rangeOf(circuit_mod.InputBinding, lane.circuit.bindings),
            };
            for (borrowed) |maybe_input| if (maybe_input) |input| {
                if (destination.overlaps(input)) return error.AliasedInput;
            };
        }
    };
}
