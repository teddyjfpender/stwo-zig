//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const stwo_core = context.d_stwo_core;
        const prover_air_accumulation = context.d_prover_air_accumulation;
        const prover_air = context.d_prover_air;
        const prover_circle = context.d_prover_circle;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const air = context.d_air;
        const manifest_mod = context.d_manifest_mod;
        const manifest_v2 = context.d_manifest_v2;
        const universal = context.d_universal;
        const framework = context.d_framework;
        const Engine = context.d_Engine;
        const Components = context.d_Components;
        const evaluateDiagnosticMasks = context.d_evaluateDiagnosticMasks;

        pub fn printTupleComponentGroups(
            items: []const air.relation_interaction.TupleContribution,
        ) void {
            var cursor: usize = 0;
            while (cursor < items.len) {
                const component = items[cursor].component;
                const event = items[cursor].event;
                var end = cursor + 1;
                while (end < items.len and
                    items[end].component == component and
                    items[end].event == event) : (end += 1)
                {}
                var signed_weight = QM31.zero();
                for (items[cursor..end]) |item|
                    signed_weight = signed_weight.add(item.signed_weight);
                const words = signed_weight.toM31Array();
                const component_name = tupleComponentName(component, event);
                std.debug.print(
                    "    component={d}:{s} event={d} records={d} " ++
                        "weight=[{d},{d},{d},{d}]\n",
                    .{
                        component,
                        component_name,
                        event,
                        end - cursor,
                        words[0].toU32(),
                        words[1].toU32(),
                        words[2].toU32(),
                        words[3].toU32(),
                    },
                );
                cursor = end;
            }
        }

        pub fn tupleComponentName(component: usize, event: usize) []const u8 {
            if (component < air.universal_roster.COMPONENT_COUNT)
                return air.universal_roster.DESCRIPTORS[component].name;
            return switch (event) {
                0 => "public_wire_boundary",
                1 => "public_verifier_input_boundary",
                else => "public_boundary",
            };
        }

        pub fn printClosureValue(
            comptime kind: []const u8,
            index: usize,
            name: []const u8,
            value: QM31,
            logical_rows: usize,
            event_terms: usize,
        ) void {
            const words = value.toM31Array();
            std.debug.print(
                "  OUTER_CLOSURE {s}[{d}] {s}=" ++
                    "[{d},{d},{d},{d}] logical_rows={d} event_terms={d}\n",
                .{
                    kind,
                    index,
                    name,
                    words[0].toU32(),
                    words[1].toU32(),
                    words[2].toU32(),
                    words[3].toU32(),
                    logical_rows,
                    event_terms,
                },
            );
        }

        pub fn printDomainValue(
            comptime kind: []const u8,
            index: usize,
            name: []const u8,
            value: QM31,
        ) void {
            const words = value.toM31Array();
            std.debug.print(
                "  OUTER_CLOSURE {s}[{d}] {s}=[{d},{d},{d},{d}]\n",
                .{
                    kind,
                    index,
                    name,
                    words[0].toU32(),
                    words[1].toU32(),
                    words[2].toU32(),
                    words[3].toU32(),
                },
            );
        }

        /// Slow, opt-in soundness diagnostic for heterogeneous universal assemblies.
        /// It evaluates each component on its cheapest local quotient domain, then
        /// compares that polynomial at the correctly folded shared OODS point with
        /// the component's independent verifier evaluator over the complete trace.
        pub const DIAGNOSTIC_NAMES_WITHOUT_VM = [_][]const u8{
            "vm_air_composition_control",
            "query_bits",
            "query_mapping",
            "merkle_root",
            "trace_merkle",
            "pcs_deep_input",
            "fri_merkle_leaf",
            "fri_merkle_node",
            "fri_merkle_anchor",
            "fri_verifier_control",
            "fri_verifier_input",
            "qm31_mul",
            "qm31_inv",
            "linear_ops",
            "merkle_path",
            "poseidon2",
        };
        pub const DIAGNOSTIC_NAMES_WITH_VM = [_][]const u8{
            "vm_air_composition_input",
            "vm_air_composition_control",
            "query_bits",
            "query_mapping",
            "merkle_root",
            "trace_merkle",
            "pcs_deep_input",
            "fri_merkle_leaf",
            "fri_merkle_node",
            "fri_merkle_anchor",
            "fri_verifier_control",
            "fri_verifier_input",
            "qm31_mul",
            "qm31_inv",
            "linear_ops",
            "merkle_path",
            "poseidon2",
        };
        pub const DIAGNOSTIC_NAMES_SEGMENT_V2_APPEND = [_][]const u8{
            "statement_source_v2",
            "public_logup_source_v2",
            "segment_publication_input_provider_v2",
        };

        pub fn diagnosticComponentName(
            component_count: usize,
            component_index: usize,
        ) ![]const u8 {
            if (component_index >= component_count) return error.InvalidProofShape;
            if (component_count == manifest_v2.COMPONENT_COUNT) {
                if (component_index < air.universal_roster.COMPONENT_COUNT)
                    return air.universal_roster.DESCRIPTORS[component_index].name;
                return DIAGNOSTIC_NAMES_SEGMENT_V2_APPEND[
                    component_index - air.universal_roster.COMPONENT_COUNT
                ];
            }
            return switch (component_count) {
                DIAGNOSTIC_NAMES_WITHOUT_VM.len => DIAGNOSTIC_NAMES_WITHOUT_VM[component_index],
                DIAGNOSTIC_NAMES_WITH_VM.len => DIAGNOSTIC_NAMES_WITH_VM[component_index],
                air.universal_roster.COMPONENT_COUNT => air.universal_roster.DESCRIPTORS[component_index].name,
                else => error.InvalidProofShape,
            };
        }

        /// Constant-time preflight for the slow composition differential. Callers run
        /// this before constructing a proof so a roster-routing regression cannot
        /// waste an end-to-end diagnostic cycle.
        pub fn validateCompositionDiagnosticRoster() !void {
            const checks = [_]struct {
                count: usize,
                index: usize,
                expected: []const u8,
            }{
                .{ .count = 16, .index = 0, .expected = "vm_air_composition_control" },
                .{ .count = 16, .index = 15, .expected = "poseidon2" },
                .{ .count = 17, .index = 0, .expected = "vm_air_composition_input" },
                .{ .count = 17, .index = 16, .expected = "poseidon2" },
                .{ .count = 36, .index = 0, .expected = "control" },
                .{ .count = 36, .index = 35, .expected = "range_check_8_8" },
                .{ .count = 39, .index = 0, .expected = "control" },
                .{ .count = 39, .index = 35, .expected = "range_check_8_8" },
                .{ .count = 39, .index = 36, .expected = "statement_source_v2" },
                .{ .count = 39, .index = 37, .expected = "public_logup_source_v2" },
                .{
                    .count = 39,
                    .index = 38,
                    .expected = "segment_publication_input_provider_v2",
                },
            };
            for (checks) |check| {
                const actual = diagnosticComponentName(check.count, check.index) catch
                    return error.DiagnosticRosterMismatch;
                if (!std.mem.eql(u8, check.expected, actual))
                    return error.DiagnosticRosterMismatch;
            }
            for (air.universal_roster.DESCRIPTORS, 0..) |descriptor, index| {
                if (@intFromEnum(descriptor.component) != index or descriptor.name.len == 0)
                    return error.DiagnosticRosterMismatch;
                const actual = diagnosticComponentName(
                    air.universal_roster.COMPONENT_COUNT,
                    index,
                ) catch return error.DiagnosticRosterMismatch;
                if (!std.mem.eql(u8, descriptor.name, actual))
                    return error.DiagnosticRosterMismatch;
                const segment_v2_actual = diagnosticComponentName(
                    manifest_v2.COMPONENT_COUNT,
                    index,
                ) catch return error.DiagnosticRosterMismatch;
                if (!std.mem.eql(u8, descriptor.name, segment_v2_actual))
                    return error.DiagnosticRosterMismatch;
            }
            for (DIAGNOSTIC_NAMES_SEGMENT_V2_APPEND, 0..) |expected, offset| {
                const actual = diagnosticComponentName(
                    manifest_v2.COMPONENT_COUNT,
                    air.universal_roster.COMPONENT_COUNT + offset,
                ) catch return error.DiagnosticRosterMismatch;
                if (!std.mem.eql(u8, expected, actual))
                    return error.DiagnosticRosterMismatch;
            }
            if (diagnosticComponentName(18, 0)) |_| {
                return error.DiagnosticRosterMismatch;
            } else |err| {
                if (err != error.InvalidProofShape)
                    return error.DiagnosticRosterMismatch;
            }
            if (diagnosticComponentName(36, 36)) |_| {
                return error.DiagnosticRosterMismatch;
            } else |err| {
                if (err != error.InvalidProofShape)
                    return error.DiagnosticRosterMismatch;
            }
            if (diagnosticComponentName(39, 39)) |_| {
                return error.DiagnosticRosterMismatch;
            } else |err| {
                if (err != error.InvalidProofShape)
                    return error.DiagnosticRosterMismatch;
            }
        }

        test "composition diagnostic resolves legacy and universal gate names" {
            try validateCompositionDiagnosticRoster();
            try std.testing.expectEqualStrings(
                "vm_air_composition_control",
                try diagnosticComponentName(16, 0),
            );
            try std.testing.expectEqualStrings(
                "poseidon2",
                try diagnosticComponentName(16, 15),
            );
            try std.testing.expectEqualStrings(
                "vm_air_composition_input",
                try diagnosticComponentName(17, 0),
            );
            try std.testing.expectEqualStrings(
                "poseidon2",
                try diagnosticComponentName(17, 16),
            );
            try std.testing.expectEqualStrings(
                "control",
                try diagnosticComponentName(36, 0),
            );
            try std.testing.expectEqualStrings(
                "range_check_8_8",
                try diagnosticComponentName(36, 35),
            );
            try std.testing.expectEqualStrings(
                "control",
                try diagnosticComponentName(39, 0),
            );
            try std.testing.expectEqualStrings(
                "range_check_8_8",
                try diagnosticComponentName(39, 35),
            );
            try std.testing.expectEqualStrings(
                "statement_source_v2",
                try diagnosticComponentName(39, 36),
            );
            try std.testing.expectEqualStrings(
                "public_logup_source_v2",
                try diagnosticComponentName(39, 37),
            );
            try std.testing.expectEqualStrings(
                "segment_publication_input_provider_v2",
                try diagnosticComponentName(39, 38),
            );
            try std.testing.expectError(
                error.InvalidProofShape,
                diagnosticComponentName(18, 0),
            );
            try std.testing.expectError(
                error.InvalidProofShape,
                diagnosticComponentName(36, 36),
            );
            try std.testing.expectError(
                error.InvalidProofShape,
                diagnosticComponentName(39, 39),
            );
        }

        /// Exact per-component OODS differential shared by recursive outer proof
        /// drivers. Callers must retain committed coefficients and flush every pending
        /// tree before entering; this is an opt-in diagnosis path, never a production
        /// proving cost.
        pub fn diagnoseCompositionComponents(
            allocator: std.mem.Allocator,
            scheme: *const Engine.Scheme,
            prover_components: []const prover_air.ComponentProver,
            verifier_components: []const stwo_core.air.components.Component,
            n_preprocessed_columns: usize,
        ) !void {
            if (prover_components.len != verifier_components.len)
                return error.InvalidProofShape;
            _ = try diagnosticComponentName(prover_components.len, 0);
            const provers = prover_air.ComponentProvers{
                .components = prover_components,
                .n_preprocessed_columns = n_preprocessed_columns,
            };
            const verifiers = stwo_core.air.components.Components{
                .components = verifier_components,
                .n_preprocessed_columns = n_preprocessed_columns,
            };
            const global_composition_log = provers.compositionLogDegreeBound();
            const split = try provers.compositionLogSplit();
            const verifier_composition_log = verifiers.compositionLogDegreeBound();
            const verifier_split = try verifiers.compositionLogSplit();
            if (verifier_composition_log != global_composition_log or
                verifier_split != split)
            {
                return error.DiagnosticCompositionLogMismatch;
            }
            if (global_composition_log <= split)
                return error.DiagnosticComponentLogOutOfRange;
            const max_log_degree_bound = global_composition_log - split;
            var trace = try scheme.trace(allocator);
            defer trace.polys.deinitDeep(allocator);
            if (trace.polys.items.len != manifest_mod.TREE_COUNT)
                return error.DiagnosticTreeCountMismatch;
            const alpha = QM31.fromU32Unchecked(3, 5, 7, 11);
            var diagnostic_channel = Engine.Channel{};
            diagnostic_channel.mixU32s(&.{
                0x5246_4443, // "RFDC"
                global_composition_log,
                max_log_degree_bound,
            });
            const point = stwo_core.circle.randomSecureFieldPoint(&diagnostic_channel);
            var mask_points = try verifiers.maskPoints(
                allocator,
                point,
                max_log_degree_bound,
                false,
            );
            defer mask_points.deinitDeep(allocator);
            try validateCompositionDiagnosticShape(
                &trace,
                &mask_points,
                prover_components,
                verifier_components,
                global_composition_log,
                max_log_degree_bound,
            );
            var mask_values = try evaluateDiagnosticMasks(
                allocator,
                &trace,
                &mask_points,
                max_log_degree_bound,
            );
            defer mask_values.deinitDeep(allocator);

            var all_components_match = true;
            for (prover_components, verifier_components, 0..) |
                prover,
                verifier,
                component_index,
            | {
                const name = try diagnosticComponentName(
                    prover_components.len,
                    component_index,
                );
                const local_log = prover.maxConstraintLogDegreeBound();
                if (local_log > global_composition_log)
                    return error.DiagnosticComponentLogOutOfRange;
                if (verifier.maxConstraintLogDegreeBound() != local_log)
                    return error.DiagnosticComponentLogMismatch;
                var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
                    allocator,
                    alpha,
                    local_log,
                    prover.nConstraints(),
                );
                defer accumulator.deinit();
                try prover.evaluateConstraintQuotientsOnDomain(&trace, &accumulator);
                var evaluation = try accumulator.finalize();
                defer evaluation.deinit(allocator);
                var polynomial = try prover_circle.secure_poly.interpolateFromEvaluation(
                    allocator,
                    prover_circle.CanonicCoset.new(local_log).circleDomain(),
                    &evaluation,
                );
                defer polynomial.deinit(allocator);
                const local_point = point.repeatedDouble(global_composition_log - local_log);
                const domain_value = polynomial.evalAtPoint(local_point);
                var point_accumulator = stwo_core.air.accumulation.PointEvaluationAccumulator.init(
                    alpha,
                );
                try verifier.evaluateConstraintQuotientsAtPoint(
                    point,
                    &mask_values,
                    &point_accumulator,
                    max_log_degree_bound,
                );
                const point_value = point_accumulator.finalize();
                const matches = domain_value.eql(point_value);
                std.debug.print(
                    "  recursion composition differential {s}: local_log={d} global_log={d} {s}\n",
                    .{
                        name,
                        local_log,
                        global_composition_log,
                        if (matches) "ok" else "MISMATCH",
                    },
                );
                if (!matches) isolate_last_constraint: {
                    // Alpha zero makes both accumulator recurrences retain only their
                    // final constraint. This costs one local component evaluation and
                    // identifies the framework LogUp equation without another full
                    // trace construction or proof attempt.
                    const isolated_alpha = QM31.zero();
                    var isolated_accumulator = try prover_air_accumulation
                        .DomainEvaluationAccumulator.init(
                        allocator,
                        isolated_alpha,
                        local_log,
                        prover.nConstraints(),
                    );
                    defer isolated_accumulator.deinit();
                    try prover.evaluateConstraintQuotientsOnDomain(
                        &trace,
                        &isolated_accumulator,
                    );
                    var isolated_evaluation = try isolated_accumulator.finalize();
                    defer isolated_evaluation.deinit(allocator);
                    var isolated_polynomial = try prover_circle.secure_poly
                        .interpolateFromEvaluation(
                        allocator,
                        prover_circle.CanonicCoset.new(local_log).circleDomain(),
                        &isolated_evaluation,
                    );
                    defer isolated_polynomial.deinit(allocator);
                    const isolated_domain_value = isolated_polynomial.evalAtPoint(
                        local_point,
                    );
                    var isolated_point_accumulator = stwo_core.air.accumulation
                        .PointEvaluationAccumulator.init(isolated_alpha);
                    try verifier.evaluateConstraintQuotientsAtPoint(
                        point,
                        &mask_values,
                        &isolated_point_accumulator,
                        max_log_degree_bound,
                    );
                    const isolated_matches = isolated_domain_value.eql(
                        isolated_point_accumulator.finalize(),
                    );
                    std.debug.print(
                        "    final constraint[{d}] {s}\n",
                        .{
                            prover.nConstraints() - 1,
                            if (isolated_matches) "ok" else "MISMATCH",
                        },
                    );
                    break :isolate_last_constraint;
                }
                all_components_match = all_components_match and matches;
            }
            if (!all_components_match) return error.ConstraintsNotSatisfied;
        }

        /// Verifies every assumption made by the opt-in per-component differential
        /// before it allocates or evaluates a single quotient column. This is kept
        /// separate from `evaluateDiagnosticMasks` so shape failures are atomic and
        /// reported before partial diagnostic output can be mistaken for coverage.
        pub fn validateCompositionDiagnosticShape(
            trace: *const prover_air.Trace,
            points: *const stwo_core.air.components.MaskPoints,
            prover_components: []const prover_air.ComponentProver,
            verifier_components: []const stwo_core.air.components.Component,
            global_composition_log: u32,
            lifting_log_size: u32,
        ) !void {
            if (trace.polys.items.len != manifest_mod.TREE_COUNT or
                points.items.len != manifest_mod.TREE_COUNT)
            {
                return error.DiagnosticTreeCountMismatch;
            }
            if (prover_components.len != verifier_components.len or
                prover_components.len == 0)
            {
                return error.InvalidProofShape;
            }
            for (trace.polys.items, points.items) |polys, point_columns| {
                if (polys.len != point_columns.len)
                    return error.DiagnosticColumnCountMismatch;
                for (polys) |poly| {
                    const coefficients = poly.coefficients orelse
                        return error.DiagnosticCoefficientsUnavailable;
                    if (coefficients.logSize() > lifting_log_size)
                        return error.DiagnosticColumnLogOutOfRange;
                }
            }
            for (prover_components, verifier_components) |prover, verifier| {
                const local_log = prover.maxConstraintLogDegreeBound();
                if (local_log > global_composition_log)
                    return error.DiagnosticComponentLogOutOfRange;
                if (verifier.maxConstraintLogDegreeBound() != local_log)
                    return error.DiagnosticComponentLogMismatch;
            }
        }
    };
}
