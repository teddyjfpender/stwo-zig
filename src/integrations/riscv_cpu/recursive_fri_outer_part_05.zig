//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const air = context.d_air;
        const lowering = context.d_lowering;
        const TupleClosureReport = context.d_TupleClosureReport;
        const TupleLedger = context.d_TupleLedger;
        const TupleRole = context.d_TupleRole;
        const InvocationBuffers = context.d_InvocationBuffers;

        pub fn classifySingleArithmeticLaneTupleClosure(
            lane: lowering.Lane,
            evaluation: lowering.Evaluation,
            invocations: lowering.InvocationBuffers,
            use_count_scratch: []u32,
            ledger: *TupleLedger,
            include_boundary_authority: bool,
        ) !air.relation_interaction.TupleClosureReport {
            if (evaluation.values.len != lane.graph.nodes.len or
                !std.mem.eql(
                    u8,
                    &evaluation.circuit_identity,
                    &lane.circuit_identity,
                ))
            {
                return error.AuthorityMismatch;
            }
            const uses = try lowering.computeUseCountsInto(
                lane.graph,
                use_count_scratch,
            );
            var multiply_cursor: usize = 0;
            var inverse_cursor: usize = 0;
            var linear_cursor: usize = 0;

            for (lane.graph.nodes, evaluation.values, uses, 0..) |
                node,
                value,
                use_count,
                node_id,
            | switch (node.op) {
                .input => if (include_boundary_authority)
                    try appendArithmeticWireTuple(
                        ledger,
                        38,
                        0,
                        .emit,
                        use_count,
                        lane.circuit_id,
                        node_id,
                        value,
                    ),
                .constant => |words| {
                    const constant = QM31.fromU32Unchecked(
                        words[0],
                        words[1],
                        words[2],
                        words[3],
                    );
                    if (!value.eql(constant)) return error.AuthorityMismatch;
                    if (include_boundary_authority) try appendArithmeticWireTuple(
                        ledger,
                        38,
                        0,
                        .emit,
                        use_count,
                        lane.circuit_id,
                        node_id,
                        value,
                    );
                },
                .mul => {
                    if (multiply_cursor >= invocations.multiply.len)
                        return error.AuthorityMismatch;
                    const invocation = invocations.multiply[multiply_cursor];
                    multiply_cursor += 1;
                    const metadata = invocation.circuit orelse
                        return error.AuthorityMismatch;
                    try appendArithmeticWireTuple(
                        ledger,
                        30,
                        0,
                        .consume,
                        1,
                        metadata.circuit_id.toU32(),
                        metadata.lhs_id.toU32(),
                        invocation.a,
                    );
                    try appendArithmeticWireTuple(
                        ledger,
                        30,
                        1,
                        .consume,
                        1,
                        metadata.circuit_id.toU32(),
                        metadata.rhs_id.toU32(),
                        invocation.b,
                    );
                    try appendArithmeticWireTuple(
                        ledger,
                        30,
                        2,
                        .emit,
                        metadata.uses.toU32(),
                        metadata.circuit_id.toU32(),
                        metadata.node_id.toU32(),
                        invocation.a.mul(invocation.b),
                    );
                },
                .inverse => {
                    if (inverse_cursor >= invocations.inverse.len)
                        return error.AuthorityMismatch;
                    const invocation = invocations.inverse[inverse_cursor];
                    inverse_cursor += 1;
                    const metadata = invocation.circuit orelse
                        return error.AuthorityMismatch;
                    try appendArithmeticWireTuple(
                        ledger,
                        31,
                        0,
                        .consume,
                        1,
                        metadata.circuit_id.toU32(),
                        metadata.lhs_id.toU32(),
                        invocation.a,
                    );
                    try appendArithmeticWireTuple(
                        ledger,
                        31,
                        1,
                        .emit,
                        metadata.uses.toU32(),
                        metadata.circuit_id.toU32(),
                        metadata.node_id.toU32(),
                        try invocation.a.inv(),
                    );
                },
                .add, .sub, .neg => {
                    if (linear_cursor >= invocations.linear.len)
                        return error.AuthorityMismatch;
                    const invocation = invocations.linear[linear_cursor];
                    linear_cursor += 1;
                    try appendArithmeticWireTuple(
                        ledger,
                        32,
                        0,
                        .consume,
                        1,
                        invocation.circuit.circuit_id.toU32(),
                        invocation.circuit.lhs_id.toU32(),
                        invocation.lhs,
                    );
                    if (invocation.operation != .neg) try appendArithmeticWireTuple(
                        ledger,
                        32,
                        1,
                        .consume,
                        1,
                        invocation.circuit.circuit_id.toU32(),
                        invocation.circuit.rhs_id.toU32(),
                        invocation.rhs,
                    );
                    try appendArithmeticWireTuple(
                        ledger,
                        32,
                        2,
                        .emit,
                        invocation.circuit.uses.toU32(),
                        invocation.circuit.circuit_id.toU32(),
                        invocation.circuit.node_id.toU32(),
                        invocation.operation.apply(invocation.lhs, invocation.rhs),
                    );
                },
            };
            if (include_boundary_authority) {
                for (lane.graph.outputs) |output| try appendArithmeticWireTuple(
                    ledger,
                    38,
                    1,
                    .consume,
                    1,
                    lane.circuit_id,
                    output,
                    evaluation.values[output],
                );
            }
            if (multiply_cursor != invocations.multiply.len or
                inverse_cursor != invocations.inverse.len or
                linear_cursor != invocations.linear.len)
            {
                return error.AuthorityMismatch;
            }
            return ledger.classify();
        }

        pub fn appendArithmeticWireTuple(
            ledger: *TupleLedger,
            component: u8,
            event: u8,
            role: TupleRole,
            multiplicity: u32,
            circuit_id: u32,
            node_id: usize,
            value: QM31,
        ) !void {
            if (multiplicity == 0) return;
            const node_coordinate = std.math.cast(u32, node_id) orelse
                return error.AuthorityMismatch;
            const words = value.toM31Array();
            const tuple = [_]QM31{
                QM31.fromBase(M31.fromCanonical(circuit_id)),
                QM31.fromBase(M31.fromCanonical(node_coordinate)),
                QM31.fromBase(words[0]),
                QM31.fromBase(words[1]),
                QM31.fromBase(words[2]),
                QM31.fromBase(words[3]),
            };
            var signed_weight = QM31.fromBase(M31.fromCanonical(multiplicity));
            if (role != .emit) signed_weight = signed_weight.neg();
            try ledger.append(
                .recursion_wire,
                component,
                event,
                role,
                signed_weight,
                &tuple,
            );
        }
    };
}
