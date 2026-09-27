//! Graph recording for the VM AIR composition authority.

const std = @import("std");
const stwo_core = @import("stwo_core");
const circle = stwo_core.circle;
const QM31 = stwo_core.fields.qm31.QM31;
const qm31 = stwo_core.fields.qm31;
const canonic = stwo_core.poly.circle.canonic;
const verifier_types = stwo_core.verifier_types;
const logup = @import("../air/logup.zig");
const clock_component = @import("../air/clock_update_component.zig");
const clock_interaction = @import("../air/clock_update_interaction.zig");
const component_order = @import("../air/component_order.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const merkle_node = @import("../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const table_interaction = @import("../air/lookups/tables/interaction.zig");
const table_schema = @import("../air/lookups/tables/schema.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const statement_mod = @import("../air/statement.zig");
const trace_mod = @import("../runner/trace.zig");
const graph_mod = @import("air/composition_circuit.zig");
const vm_leaf_context = @import("vm_leaf_context.zig");
const transcript_claims = @import("../air/transcript/claims.zig");

pub fn Build(comptime Context: type) type {
    const Error = Context.ErrorSet;
    const Builder = Context.Builder;
    const Scalar = Context.Scalar;
    const GraphRelations = Context.GraphRelations;
    const SampleLayout = Context.SampleLayout;
    const Circuit = Context.CircuitType;
    const validateSampleGeometry = Context.validateSampleGeometry;
    const transcriptComponentForInfra = Context.transcriptComponentForInfra;
    const circuitDigest = Context.circuitDigest;
    const CIRCUIT_ID = Context.CIRCUIT_ID;

    return struct {
        pub fn build(
            allocator: std.mem.Allocator,
            context: *const vm_leaf_context.Context,
            capture: anytype,
        ) Error!Circuit {
            try context.validate();
            try validateSampleGeometry(context, capture);
            const sample_count = std.math.cast(u32, capture.sampled_values.len) orelse
                return error.CircuitTooLarge;
            const input_profile = graph_mod.InputProfile{
                .sampled_value_count = sample_count,
                .claimed_sum_count = context.profile.claimed_sum_count,
                .relation_challenge_count = context.profile.relation_challenge_count,
                .transcript_claimed_sum_count = transcript_claims.COMPONENT_COUNT,
            };
            const input_count = try graph_mod.vmInputCount(input_profile);

            var builder = Builder.init(allocator);
            defer builder.deinit();
            try builder.reserve(input_count, context.profile.air_instruction_count);
            Context.installBuilder(&builder);
            defer Context.uninstallBuilder();

            const selector = try builder.input(.segment_selector);
            const sampled = try allocator.alloc(Scalar, capture.sampled_values.len);
            defer allocator.free(sampled);
            for (sampled, 0..) |*value, item| {
                value.* = try secureInput(&builder, .sampled_value, @intCast(item));
            }
            const claims = try allocator.alloc(Scalar, context.detailed_claims.len);
            defer allocator.free(claims);
            for (claims, 0..) |*value, item| {
                value.* = try secureInput(&builder, .claimed_sum, @intCast(item));
            }
            var canonical_claims: [transcript_claims.COMPONENT_COUNT]Scalar = undefined;
            for (&canonical_claims, 0..) |*value, item| {
                value.* = try secureInput(
                    &builder,
                    .transcript_claimed_sum,
                    @intCast(item),
                );
            }
            var challenge_pairs: [12][2]Scalar = undefined;
            for (&challenge_pairs, 0..) |*pair, challenge| {
                pair[0] = try challengeInput(&builder, @intCast(challenge), 0);
                pair[1] = try challengeInput(&builder, @intCast(challenge), 4);
            }
            const composition_randomness = try scalarInput(&builder, .composition_randomness);
            const oods_seed = try scalarInput(&builder, .oods_point);
            try builder.check();

            // Bind the transcript's fixed 28 aggregate claims to the exact detailed
            // sequence used below by the native AIR composition replay. This closes
            // the otherwise independent row-5 and row-18 authorities in the same
            // authenticated arithmetic graph.
            var aggregate_claims = [_]Scalar{Scalar.zero()} **
                transcript_claims.COMPONENT_COUNT;
            var aggregate_cursor: usize = 0;
            for (context.component_descs) |descriptor| {
                const component = component_order.transcriptComponentForOpcodeFamily(
                    descriptor.family,
                );
                for (0..opcode_entries.batchCount(descriptor.family)) |_| {
                    if (aggregate_cursor >= claims.len)
                        return error.InvalidComponentOrder;
                    aggregate_claims[@intFromEnum(component)] =
                        aggregate_claims[@intFromEnum(component)]
                            .add(claims[aggregate_cursor]);
                    aggregate_cursor += 1;
                }
            }
            for (context.infra_descs) |descriptor| {
                const component = transcriptComponentForInfra(descriptor.kind);
                for (0..statement_mod.nClaimedSumsForInfra(descriptor.kind)) |_| {
                    if (aggregate_cursor >= claims.len)
                        return error.InvalidComponentOrder;
                    aggregate_claims[@intFromEnum(component)] =
                        aggregate_claims[@intFromEnum(component)]
                            .add(claims[aggregate_cursor]);
                    aggregate_cursor += 1;
                }
            }
            if (aggregate_cursor != claims.len) return error.InvalidComponentOrder;
            for (canonical_claims, aggregate_claims) |canonical, aggregate| {
                try builder.constrainZero(selector.mul(canonical.sub(aggregate)));
            }
            try builder.check();

            const relations = GraphRelations.init(challenge_pairs);
            var sample_layout = try SampleLayout.init(
                allocator,
                capture.sampled_points,
                sampled,
            );
            defer sample_layout.deinit();
            const point = pointFromSeed(oods_seed);
            var denominators: [31]?Scalar = .{null} ** 31;
            var accumulation = Scalar.zero();
            var instruction_count: usize = 0;
            var claim_cursor: usize = 0;
            var main_offset: usize = 0;
            var interaction_offset: usize = 0;

            const Semantic = semantic_eval.Eval(Scalar);
            const OpcodeEntries = opcode_entries.Entries(Scalar);
            for (context.component_descs, 0..) |descriptor, shard_index| {
                const semantic_main_count = semantic_eval.mainColumnCount(descriptor.family);
                var semantic_main: [trace_mod.MAX_FAMILY_COLUMNS]Scalar = undefined;
                for (semantic_main[0..semantic_main_count], 0..) |*value, column| {
                    value.* = try sample_layout.at(1, main_offset + column, 0);
                }
                const is_active = try sample_layout.at(0, 2 * shard_index + 1, 0);
                const direct = try Semantic.evaluate(
                    descriptor.family,
                    semantic_main[0..semantic_main_count],
                    is_active,
                );
                const denominator = quotientDenominator(
                    descriptor.log_size,
                    context.profile.max_log_degree_bound,
                    point,
                    &denominators,
                );
                for (direct.values[0..direct.len]) |constraint| {
                    accumulate(&accumulation, composition_randomness, constraint, denominator);
                    instruction_count += 1;
                }

                const n_main = trace_mod.nColumnsForFamily(descriptor.family);
                var lookup_main: [trace_mod.MAX_FAMILY_COLUMNS]Scalar = undefined;
                for (lookup_main[0..n_main], 0..) |*value, column| {
                    value.* = try sample_layout.at(1, main_offset + column, 0);
                }
                const entries = OpcodeEntries.fromMain(
                    descriptor.family,
                    lookup_main[0..n_main],
                ) catch return error.InvalidMainTraceShape;
                const batches = opcode_entries.batchCount(descriptor.family);
                if (entries.batchCount() != batches) return error.InvalidInteractionShape;
                const is_first = try sample_layout.at(0, 2 * shard_index, 0);
                for (0..batches) |batch| {
                    const current = try sampledSecure(&sample_layout, interaction_offset + 4 * batch, 0);
                    const previous = try sampledSecure(&sample_layout, interaction_offset + 4 * batch, 1);
                    const pair = try entries.pairWith(batch, &relations);
                    const constraint = logup.pairConstraintGeneric(
                        Scalar,
                        current,
                        previous,
                        is_first,
                        claims[claim_cursor],
                        pair,
                    );
                    claim_cursor += 1;
                    accumulate(&accumulation, composition_randomness, constraint, denominator);
                    instruction_count += 1;
                }
                main_offset += descriptor.n_columns;
                interaction_offset += opcode_interaction.nColumns(descriptor.family);
                try builder.check();
            }

            var preprocessed_offset: usize = 2 * context.component_descs.len;
            for (context.infra_descs) |descriptor| {
                const denominator_log = if (statement_mod.tableKind(descriptor.kind)) |kind|
                    table_schema.logSize(kind)
                else
                    descriptor.log_size;
                const denominator = quotientDenominator(
                    denominator_log,
                    context.profile.max_log_degree_bound,
                    point,
                    &denominators,
                );
                const is_first = try sample_layout.at(0, preprocessed_offset, 0);
                switch (descriptor.kind) {
                    .program => {
                        const main = try sampledMain(
                            program_commitment.N_MAIN_COLUMNS,
                            &sample_layout,
                            main_offset,
                        );
                        const current = try sampledInteraction(
                            program_interaction.N_SUMS,
                            &sample_layout,
                            interaction_offset,
                            0,
                        );
                        const previous = try sampledInteraction(
                            program_interaction.N_SUMS,
                            &sample_layout,
                            interaction_offset,
                            1,
                        );
                        const active = try sample_layout.at(0, preprocessed_offset + 1, 0);
                        const component_claims = claims[claim_cursor..][0..program_interaction.N_SUMS].*;
                        claim_cursor += program_interaction.N_SUMS;
                        const constraints = program_interaction.evaluateGeneric(
                            Scalar,
                            main,
                            active,
                            is_first,
                            current,
                            previous,
                            component_claims,
                            &relations,
                        );
                        appendConstraints(
                            &accumulation,
                            composition_randomness,
                            denominator,
                            &constraints,
                            &instruction_count,
                        );
                    },
                    .memory => {
                        const main = try sampledMain(8, &sample_layout, main_offset);
                        const current = try sampledInteraction(
                            memory_interaction.N_SUMS,
                            &sample_layout,
                            interaction_offset,
                            0,
                        );
                        const previous = try sampledInteraction(
                            memory_interaction.N_SUMS,
                            &sample_layout,
                            interaction_offset,
                            1,
                        );
                        const active = try sample_layout.at(0, preprocessed_offset + 1, 0);
                        const component_claims = claims[claim_cursor..][0..memory_interaction.N_SUMS].*;
                        claim_cursor += memory_interaction.N_SUMS;
                        const constraints = memory_interaction.evaluateGeneric(
                            Scalar,
                            main,
                            active,
                            is_first,
                            current,
                            previous,
                            component_claims,
                            &relations,
                        );
                        appendConstraints(&accumulation, composition_randomness, denominator, &constraints, &instruction_count);
                    },
                    .clock_update => {
                        const main = try sampledMain(clock_interaction.N_MAIN_COLUMNS, &sample_layout, main_offset);
                        const current = try sampledInteraction(clock_interaction.N_SUMS, &sample_layout, interaction_offset, 0);
                        const previous = try sampledInteraction(clock_interaction.N_SUMS, &sample_layout, interaction_offset, 1);
                        const active = try sample_layout.at(0, preprocessed_offset + 1, 0);
                        const component_claims = claims[claim_cursor..][0..clock_interaction.N_SUMS].*;
                        claim_cursor += clock_interaction.N_SUMS;
                        const constraints = try clock_component.evaluateGeneric(
                            Scalar,
                            &main,
                            current,
                            previous,
                            is_first,
                            active,
                            component_claims,
                            &relations,
                        );
                        appendConstraints(&accumulation, composition_randomness, denominator, &constraints, &instruction_count);
                    },
                    .merkle => {
                        const main = try sampledMain(merkle_node.N_MAIN_COLUMNS, &sample_layout, main_offset);
                        const current = try sampledInteraction(merkle_node.N_SUMS, &sample_layout, interaction_offset, 0);
                        const previous = try sampledInteraction(merkle_node.N_SUMS, &sample_layout, interaction_offset, 1);
                        const active = try sample_layout.at(0, preprocessed_offset + 1, 0);
                        const component_claims = claims[claim_cursor..][0..merkle_node.N_SUMS].*;
                        claim_cursor += merkle_node.N_SUMS;
                        const constraints = merkle_node.evaluateGeneric(
                            Scalar,
                            main,
                            active,
                            is_first,
                            current,
                            previous,
                            component_claims,
                            &relations,
                        );
                        appendConstraints(&accumulation, composition_randomness, denominator, &constraints, &instruction_count);
                    },
                    .poseidon2 => {
                        const main = try sampledMain(poseidon2_air.N_MAIN_COLUMNS, &sample_layout, main_offset);
                        const current = try sampledInteraction(poseidon2_air.N_SUMS, &sample_layout, interaction_offset, 0);
                        const previous = try sampledInteraction(poseidon2_air.N_SUMS, &sample_layout, interaction_offset, 1);
                        const active = try sample_layout.at(0, preprocessed_offset + 1, 0);
                        const component_claims = claims[claim_cursor..][0..poseidon2_air.N_SUMS].*;
                        claim_cursor += poseidon2_air.N_SUMS;
                        const air_constraints = poseidon2_air.evaluateGeneric(Scalar, main);
                        appendConstraints(&accumulation, composition_randomness, denominator, &air_constraints, &instruction_count);
                        const shell = [_]Scalar{
                            main[0].sub(active),
                            main[poseidon2_air.WIDE_COLUMN],
                            main[poseidon2_air.IO_COLUMN],
                        };
                        appendConstraints(&accumulation, composition_randomness, denominator, &shell, &instruction_count);
                        const interaction_constraints = poseidon2_air.interactionConstraintsGeneric(
                            Scalar,
                            main,
                            is_first,
                            current,
                            previous,
                            component_claims,
                            &relations,
                        );
                        appendConstraints(&accumulation, composition_randomness, denominator, &interaction_constraints, &instruction_count);
                    },
                    .bitwise,
                    .range_check_20,
                    .range_check_8_11,
                    .range_check_8_8_4,
                    .range_check_8_8,
                    .range_check_m31,
                    => {
                        const kind = statement_mod.tableKind(descriptor.kind) orelse unreachable;
                        var tuple: [table_schema.MAX_ARITY]Scalar = undefined;
                        for (tuple[0..table_schema.arity(kind)], 0..) |*value, index| {
                            value.* = try sample_layout.at(0, preprocessed_offset + 1 + index, 0);
                        }
                        const signed_multiplicity = try sample_layout.at(1, main_offset, 0);
                        const current = try sampledSecure(&sample_layout, interaction_offset, 0);
                        const previous = try sampledSecure(&sample_layout, interaction_offset, 1);
                        const constraint = try table_interaction.evaluateGeneric(
                            Scalar,
                            kind,
                            tuple[0..table_schema.arity(kind)],
                            signed_multiplicity,
                            current,
                            previous,
                            is_first,
                            claims[claim_cursor],
                            &relations,
                        );
                        claim_cursor += 1;
                        accumulate(&accumulation, composition_randomness, constraint, denominator);
                        instruction_count += 1;
                    },
                }
                preprocessed_offset += statement_mod.nPreprocessedColumnsForInfra(descriptor.kind);
                main_offset += descriptor.n_columns;
                interaction_offset += statement_mod.nInteractionColsForInfra(descriptor.kind);
                try builder.check();
            }

            if (instruction_count != context.profile.air_instruction_count or
                claim_cursor != claims.len or
                preprocessed_offset != capture.sampled_points[0].len or
                main_offset != capture.sampled_points[1].len or
                interaction_offset != capture.sampled_points[2].len)
            {
                return error.InvalidComponentOrder;
            }
            const composition = try reconstructComposition(
                &sample_layout,
                point,
                context.profile.composition_log_degree_bound,
                context.profile.composition_log_split,
            );
            try builder.constrainZero(selector.mul(composition.sub(accumulation)));
            try builder.check();

            const nodes = try builder.nodes.toOwnedSlice(allocator);
            errdefer allocator.free(nodes);
            const outputs = try builder.outputs.toOwnedSlice(allocator);
            errdefer allocator.free(outputs);
            const bindings = try builder.bindings.toOwnedSlice(allocator);
            errdefer allocator.free(bindings);
            const graph_digest = graph_mod.computeGraphDigest(nodes, outputs);
            const graph = graph_mod.CircuitGraph{
                .nodes = nodes,
                .outputs = outputs,
                .identity_digest = graph_digest,
            };
            const lane = graph_mod.VmLane{
                .circuit_id = CIRCUIT_ID,
                .graph = graph,
                .profile = input_profile,
                .bindings = bindings,
            };
            const reference_digest = graph_mod.computeReferenceDigest(lane, &.{}, &.{});
            const reference = try graph_mod.Reference.authenticate(
                lane,
                &.{},
                &.{},
                reference_digest,
            );
            var compiled = try graph_mod.compile(allocator, &reference);
            defer compiled.deinit();
            const schedule_digest = compiled.authority_digest;
            var result = Circuit{
                .allocator = allocator,
                .nodes = nodes,
                .outputs = outputs,
                .bindings = bindings,
                .input_profile = input_profile,
                .air_profile_digest = context.profile.manifest_digest,
                .graph_digest = graph_digest,
                .reference_digest = reference_digest,
                .schedule_digest = schedule_digest,
                .identity_digest = circuitDigest(
                    context.profile.manifest_digest,
                    graph_digest,
                    reference_digest,
                    schedule_digest,
                    input_profile,
                    bindings,
                ),
            };
            try result.validate();
            return result;
        }

        fn secureInput(
            builder: *Builder,
            comptime tag: enum { sampled_value, claimed_sum, transcript_claimed_sum },
            item_index: u32,
        ) Error!Scalar {
            var words: [4]Scalar = undefined;
            for (&words, 0..) |*word, word_index| {
                const coordinate = graph_mod.SecureCoordinate{
                    .item_index = item_index,
                    .word_index = @intCast(word_index),
                };
                word.* = try builder.input(@unionInit(graph_mod.VmSource, @tagName(tag), coordinate));
            }
            return secureFromWords(words);
        }

        fn challengeInput(builder: *Builder, challenge: u32, word_offset: u32) Error!Scalar {
            var words: [4]Scalar = undefined;
            for (&words, 0..) |*word, index| {
                word.* = try builder.input(.{ .relation_challenge = .{
                    .challenge = challenge,
                    .word_index = word_offset + @as(u32, @intCast(index)),
                } });
            }
            return secureFromWords(words);
        }

        fn scalarInput(builder: *Builder, comptime tag: enum { composition_randomness, oods_point }) Error!Scalar {
            var words: [4]Scalar = undefined;
            for (&words, 0..) |*word, index| {
                word.* = try builder.input(@unionInit(
                    graph_mod.VmSource,
                    @tagName(tag),
                    @as(u32, @intCast(index)),
                ));
            }
            return secureFromWords(words);
        }

        fn secureFromWords(words: [4]Scalar) Scalar {
            return words[0]
                .add(words[1].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 1, 0, 0))))
                .add(words[2].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 0, 1, 0))))
                .add(words[3].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 0, 0, 1))));
        }

        fn sampledSecure(layout: *const SampleLayout, column: usize, sample: usize) Error!Scalar {
            var coordinates: [4]Scalar = undefined;
            for (&coordinates, 0..) |*value, index| {
                value.* = try layout.at(2, column + index, sample);
            }
            return fromPartialEvals(coordinates);
        }

        fn sampledMain(
            comptime n: usize,
            layout: *const SampleLayout,
            offset: usize,
        ) Error![n]Scalar {
            var result: [n]Scalar = undefined;
            for (&result, 0..) |*value, column| value.* = try layout.at(1, offset + column, 0);
            return result;
        }

        fn sampledInteraction(
            comptime n: usize,
            layout: *const SampleLayout,
            offset: usize,
            sample: usize,
        ) Error![n]Scalar {
            var result: [n]Scalar = undefined;
            for (&result, 0..) |*value, index| {
                value.* = try sampledSecure(layout, offset + 4 * index, sample);
            }
            return result;
        }

        fn fromPartialEvals(values: [4]Scalar) Scalar {
            return values[0]
                .add(values[1].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 1, 0, 0))))
                .add(values[2].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 0, 1, 0))))
                .add(values[3].mul(Scalar.fromSecure(QM31.fromU32Unchecked(0, 0, 0, 1))));
        }

        fn pointFromSeed(seed: Scalar) circle.CirclePoint(Scalar) {
            const square = seed.square();
            const inverse = square.add(Scalar.one()).inverse();
            return .{
                .x = Scalar.one().sub(square).mul(inverse),
                .y = seed.add(seed).mul(inverse),
            };
        }

        fn quotientDenominator(
            log_size: u32,
            max_log_degree_bound: u32,
            point: circle.CirclePoint(Scalar),
            cache: *[31]?Scalar,
        ) Scalar {
            std.debug.assert(log_size < cache.len and max_log_degree_bound >= log_size);
            if (cache[log_size]) |cached| return cached;
            const coset = canonic.CanonicCoset.new(log_size).coset();
            const folded = point.repeatedDouble(max_log_degree_bound - log_size);
            const shifted = folded
                .sub(.{ .x = Scalar.fromBase(coset.initial.x), .y = Scalar.fromBase(coset.initial.y) })
                .add(.{ .x = Scalar.fromBase(coset.half_step.x), .y = Scalar.fromBase(coset.half_step.y) });
            var x = shifted.x;
            var round: u32 = 1;
            while (round < coset.log_size) : (round += 1) {
                x = circle.CirclePoint(Scalar).doubleX(x);
            }
            const inverse = x.inverse();
            cache[log_size] = inverse;
            return inverse;
        }

        fn accumulate(acc: *Scalar, random: Scalar, constraint: Scalar, denominator: Scalar) void {
            acc.* = acc.mul(random).add(constraint.mul(denominator));
        }

        fn appendConstraints(
            acc: *Scalar,
            random: Scalar,
            denominator: Scalar,
            constraints: []const Scalar,
            count: *usize,
        ) void {
            for (constraints) |constraint| {
                accumulate(acc, random, constraint, denominator);
                count.* += 1;
            }
        }

        fn reconstructComposition(
            layout: *const SampleLayout,
            point: circle.CirclePoint(Scalar),
            composition_log_size: u32,
            split_depth: u32,
        ) Error!Scalar {
            const chunk_count = verifier_types.compositionChunkCount(split_depth) orelse
                return error.InvalidSampleGeometry;
            const expected_columns = verifier_types.compositionColumnCount(
                split_depth,
                qm31.SECURE_EXTENSION_DEGREE,
            ) orelse return error.InvalidSampleGeometry;
            if (layout.offsets[3].len != expected_columns + 1 or
                composition_log_size <= split_depth)
            {
                return error.InvalidSampleGeometry;
            }
            var chunks: [@as(usize, 1) << verifier_types.MAX_COMPOSITION_LOG_SPLIT]Scalar = undefined;
            for (chunks[0..chunk_count], 0..) |*chunk, chunk_index| {
                var coordinates: [4]Scalar = undefined;
                for (&coordinates, 0..) |*coordinate, coordinate_index| {
                    coordinate.* = try layout.at(
                        3,
                        chunk_index * 4 + coordinate_index,
                        0,
                    );
                }
                chunk.* = fromPartialEvals(coordinates);
            }
            var active = chunk_count;
            var parent_log = composition_log_size - split_depth + 1;
            while (active > 1) {
                const factor = point.repeatedDouble(parent_log - 2).x;
                var output: usize = 0;
                var input: usize = 0;
                while (input < active) : (input += 2) {
                    chunks[output] = chunks[input].add(factor.mul(chunks[input + 1]));
                    output += 1;
                }
                active /= 2;
                parent_log += 1;
            }
            return chunks[0];
        }
    };
}
