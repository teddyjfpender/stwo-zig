//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const m31 = context.d_m31;
        const transcript_air = context.d_transcript_air;
        const transcript_component = context.d_transcript_component;
        const transcript_control = context.d_transcript_control;
        const transcript_binding = context.d_transcript_binding;
        const transcript_state = context.d_transcript_state;
        const transcript_word = context.d_transcript_word;
        const transcript_payload = context.d_transcript_payload;
        const pow_check_air = context.d_pow_check_air;
        const verifier_randomness = context.d_verifier_randomness;
        const framework_interaction = context.d_framework_interaction;
        const universal_binding = context.d_universal_binding;
        const universal_manifest = context.d_universal_manifest;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const control_air = context.d_control_air;
        const transcript_binding_air = context.d_transcript_binding_air;
        const transcript_state_air = context.d_transcript_state_air;
        const transcript_word_air = context.d_transcript_word_air;
        const pow_frame_air = context.d_pow_frame_air;
        const verifier_randomness_air = context.d_verifier_randomness_air;
        const statement_input_air = context.d_statement_input_air;
        const statement_input_witness = context.d_statement_input_witness;
        const statement_semantics_air = context.d_statement_semantics_air;
        const statement_semantics_witness = context.d_statement_semantics_witness;
        const vm_claim_input_air = context.d_vm_claim_input_air;
        const vm_claim_hash_air = context.d_vm_claim_hash_air;
        const vm_io_hash_air = context.d_vm_io_hash_air;
        const vm_claim_semantics_air = context.d_vm_claim_semantics_air;
        const vm_public_logup_air = context.d_vm_public_logup_air;
        const vm_public_logup_control_air = context.d_vm_public_logup_control_air;
        const TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT = context.d_TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT;
        const TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND = context.d_TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND;
        const PREFIX_TREE_COUNT = context.d_PREFIX_TREE_COUNT;
        const PREFIX_TREE0_INDEX = context.d_PREFIX_TREE0_INDEX;
        const PREFIX_TREE1_INDEX = context.d_PREFIX_TREE1_INDEX;
        const PREFIX_TREE2_INDEX = context.d_PREFIX_TREE2_INDEX;
        const TemporalTranscriptPayloadRowV2 = context.d_TemporalTranscriptPayloadRowV2;
        const TemporalPowCheckRowV2 = context.d_TemporalPowCheckRowV2;
        const TemporalPowFrameRowV2 = context.d_TemporalPowFrameRowV2;
        const TranscriptPayloadRelation = context.d_TranscriptPayloadRelation;
        const PowCheckRelation = context.d_PowCheckRelation;
        const PowFrameRelation = context.d_PowFrameRelation;
        const InteractionFramework = context.d_InteractionFramework;
        const TemporalPrefixCommitmentLayoutV3 = context.d_TemporalPrefixCommitmentLayoutV3;
        const Error = context.d_Error;
        const TemporalPrefixLogicalBuffersV3 = context.d_TemporalPrefixLogicalBuffersV3;
        const TemporalPrefixTreeSourcesV3 = context.d_TemporalPrefixTreeSourcesV3;
        const TemporalPrefixTreeWriterV3 = context.d_TemporalPrefixTreeWriterV3;
        const ByteRange = context.d_ByteRange;
        const byteRange = context.d_byteRange;

        pub fn validatePrefixBufferGeometry(
            buffers: *const TemporalPrefixLogicalBuffersV3,
            sources: TemporalPrefixTreeSourcesV3,
        ) Error!void {
            const counts = sources.custody.transcript_manifest.logical_rows;
            if (buffers.control_typed.len != @as(usize, @intCast(counts[0])) or
                buffers.control.len != @as(usize, @intCast(counts[0])) or
                buffers.transcript_air.len != @as(usize, @intCast(counts[1])) or
                buffers.binding_typed.len != @as(usize, @intCast(counts[2])) or
                buffers.transcript_binding.len != @as(usize, @intCast(counts[2])) or
                buffers.state_typed.len != @as(usize, @intCast(counts[3])) or
                buffers.transcript_state.len != @as(usize, @intCast(counts[3])) or
                buffers.word_typed.len != @as(usize, @intCast(counts[4])) or
                buffers.transcript_word.len != @as(usize, @intCast(counts[4])) or
                buffers.payload_typed.len != @as(usize, @intCast(counts[5])) or
                buffers.transcript_payload.len != @as(usize, @intCast(counts[5])) or
                buffers.pow_check_typed.len != @as(usize, @intCast(counts[6])) or
                buffers.pow_check.len != @as(usize, @intCast(counts[6])) or
                buffers.pow_frame_typed.len != @as(usize, @intCast(counts[7])) or
                buffers.pow_frame.len != @as(usize, @intCast(counts[7])) or
                buffers.packed_typed.len != @as(usize, @intCast(counts[8])) or
                buffers.packed_relation_challenge.len !=
                    @as(usize, @intCast(counts[8])) or
                buffers.randomness_typed.len != @as(usize, @intCast(counts[9])) or
                buffers.verifier_randomness.len != @as(usize, @intCast(counts[9])) or
                buffers.statement_input.len !=
                    sources.statement_authority.statement_input_preprocessing.rows.len or
                buffers.statement_semantics.len !=
                    sources.statement_authority.statement_semantics_preprocessing.rows.len or
                buffers.statement_semantics.len != sources.statement.statement_values.len)
            {
                return error.InvalidPrefixTreeWriter;
            }
        }

        pub fn fillPrefixLogicalRows(
            writer: *TemporalPrefixTreeWriterV3,
            sources: TemporalPrefixTreeSourcesV3,
        ) Error!void {
            const buffers = &writer.buffers;
            for (buffers.control, buffers.control_typed) |*target, row|
                target.* = transcript_control.logicalRow(row, .binary_node);
            for (buffers.transcript_air, sources.transcript.rows) |*target, row|
                target.* = try transcript_air.logicalRow(row);
            for (
                buffers.transcript_binding,
                buffers.binding_typed,
            ) |*target, row| target.* = transcript_binding.logicalInputs(
                row.main,
                row.preprocessing,
                .binary_node,
            );
            for (
                buffers.transcript_state,
                buffers.state_typed,
            ) |*target, row| target.* = transcript_state.logicalInputs(
                row.main,
                row.preprocessing,
                .binary_node,
            );
            for (buffers.transcript_word, buffers.word_typed) |*target, row|
                target.* = try transcript_word.logicalRow(
                    row.preprocessing,
                    row.value,
                    .binary_node,
                );
            for (buffers.transcript_payload, buffers.payload_typed) |*target, row|
                target.* = try temporalPayloadLogicalRow(row);
            for (buffers.pow_check, buffers.pow_check_typed) |*target, row|
                target.* = try temporalPowCheckLogicalRow(row);
            for (buffers.pow_frame, buffers.pow_frame_typed) |*target, row|
                target.* = try temporalPowFrameLogicalRow(row);
            for (
                buffers.packed_relation_challenge,
                buffers.packed_typed,
            ) |*target, row| target.* = packed_relation_challenge_v2.logicalInputs(
                row.main,
                row.preprocessing,
                .binary_node,
            );
            for (
                buffers.verifier_randomness,
                buffers.randomness_typed,
            ) |*target, row| target.* = verifier_randomness.logicalInputs(
                row.main,
                row.preprocessing,
                .binary_node,
            );

            const statement_witness = statement_input_witness.StatementWitness{
                .binary_node = .{
                    .left = &sources.statement.left_words,
                    .right = &sources.statement.right_words,
                    .parent = &sources.statement.parent_words,
                },
            };
            for (
                buffers.statement_input,
                sources.statement_authority.statement_input_preprocessing.rows,
            ) |*target, row| target.* = try statement_input_witness.logicalRow(
                row,
                statement_witness,
            );
            for (
                buffers.statement_semantics,
                sources.statement_authority.statement_semantics_preprocessing.rows,
                sources.statement.statement_values,
            ) |*target, row, value| target.* =
                try statement_semantics_witness.logicalRow(
                    row,
                    value,
                    .binary_node,
                );
        }

        pub fn temporalPayloadLogicalRow(
            row: TemporalTranscriptPayloadRowV2,
        ) Error!TranscriptPayloadRelation.Row {
            const source_kind = @intFromEnum(row.source_kind);
            inline for (.{
                row.verifier_id,
                row.instruction_index,
                row.tag,
                row.args[0],
                row.args[1],
                row.args[2],
                row.args[3],
                row.payload_index,
                source_kind,
                row.item_index,
                row.limb_index,
                row.constant_mask,
                row.input_use_count,
                row.source_hash_id,
                row.source_word_index,
            }) |value| if (value >= m31.Modulus)
                return error.InvalidTemporalPayloadAuthority;
            if (source_kind == 0 or source_kind > TEMPORAL_PAYLOAD_SOURCE_KIND_COUNT or
                row.constant_mask > 1 or
                (source_kind == TEMPORAL_PAYLOAD_PUBLIC_GEOMETRY_KIND and
                    (row.constant_mask != 1 or row.input_use_count != 0)))
            {
                return error.InvalidTemporalPayloadAuthority;
            }
            const selectors = transcript_control.ProofKind.binary_node.selectors();
            return .{
                M31.one(),
                row.value,
                M31.one(),
                M31.zero(),
                M31.one(),
                M31.fromCanonical(row.verifier_id),
                M31.fromCanonical(row.instruction_index),
                M31.fromCanonical(row.tag),
                M31.fromCanonical(row.args[0]),
                M31.fromCanonical(row.args[1]),
                M31.fromCanonical(row.args[2]),
                M31.fromCanonical(row.args[3]),
                M31.fromCanonical(row.payload_index),
                M31.fromCanonical(source_kind),
                M31.fromCanonical(row.item_index),
                M31.fromCanonical(row.limb_index),
                M31.fromCanonical(row.constant_mask),
                M31.fromCanonical(row.input_use_count),
                if (row.constant_mask == 1) row.value else M31.zero(),
                selectors[0],
                selectors[1],
            };
        }

        pub fn temporalPowCheckLogicalRow(
            row: TemporalPowCheckRowV2,
        ) Error!PowCheckRelation.Row {
            inline for (.{
                row.enabler,
                row.verifier_id,
                @intFromEnum(row.pow_kind),
                row.call_id,
                row.bits,
            }) |value| if (value >= m31.Modulus)
                return error.InvalidTranscriptRecorder;
            if (row.enabler != 1 or row.bits > 31)
                return error.InvalidTranscriptRecorder;
            var result: PowCheckRelation.Row = undefined;
            result[0] = M31.one();
            result[1] = M31.fromCanonical(row.verifier_id);
            result[2] = M31.fromCanonical(@intFromEnum(row.pow_kind));
            result[3] = M31.fromCanonical(row.call_id);
            result[4] = M31.fromCanonical(row.bits);
            result[5] = row.word;
            for (row.word_bits, 0..) |value, index|
                result[6 + index] = M31.fromCanonical(value);
            for (row.active_bits, 0..) |value, index|
                result[6 + row.word_bits.len + index] = M31.fromCanonical(value);
            return result;
        }

        pub fn temporalPowFrameLogicalRow(
            row: TemporalPowFrameRowV2,
        ) Error!PowFrameRelation.Row {
            inline for (.{
                row.enabler,
                row.verifier_id,
                row.sequence,
                @intFromEnum(row.pow_kind),
                row.hash_id,
                row.call_id,
                row.bits,
            }) |value| if (value >= m31.Modulus)
                return error.InvalidTranscriptRecorder;
            if (row.enabler != 1 or row.bits > 31)
                return error.InvalidTranscriptRecorder;
            return .{
                M31.one(),
                M31.fromCanonical(row.verifier_id),
                M31.fromCanonical(row.sequence),
                M31.fromCanonical(@intFromEnum(row.pow_kind)),
                M31.fromCanonical(row.hash_id),
                M31.fromCanonical(row.call_id),
                M31.fromCanonical(row.bits),
            } ++ row.words;
        }

        pub fn scatterPrefixTree(
            writer: *const TemporalPrefixTreeWriterV3,
            sources: TemporalPrefixTreeSourcesV3,
            layout: *const TemporalPrefixCommitmentLayoutV3,
            tree: usize,
            destination: []const []M31,
        ) void {
            scatterPrefixRow(control_air, writer.buffers.control, layout.placements[0], tree, destination);
            scatterPrefixRow(transcript_component, writer.buffers.transcript_air, layout.placements[1], tree, destination);
            scatterPrefixRow(transcript_binding_air, writer.buffers.transcript_binding, layout.placements[2], tree, destination);
            scatterPrefixRow(transcript_state_air, writer.buffers.transcript_state, layout.placements[3], tree, destination);
            scatterPrefixRow(transcript_word_air, writer.buffers.transcript_word, layout.placements[4], tree, destination);
            scatterPrefixRow(transcript_payload, writer.buffers.transcript_payload, layout.placements[5], tree, destination);
            scatterPrefixRow(pow_check_air, writer.buffers.pow_check, layout.placements[6], tree, destination);
            scatterPrefixRow(pow_frame_air, writer.buffers.pow_frame, layout.placements[7], tree, destination);
            scatterPrefixRow(packed_relation_challenge_v2, writer.buffers.packed_relation_challenge, layout.placements[8], tree, destination);
            scatterPrefixRow(verifier_randomness_air, writer.buffers.verifier_randomness, layout.placements[9], tree, destination);
            scatterPrefixRow(statement_input_air, writer.buffers.statement_input, layout.placements[10], tree, destination);
            scatterPrefixRow(statement_semantics_air, writer.buffers.statement_semantics, layout.placements[11], tree, destination);
            scatterPrefixRow(vm_claim_input_air, sources.inactive_prepared.claim_input_rows, layout.placements[12], tree, destination);
            scatterPrefixRow(vm_claim_hash_air, sources.inactive_prepared.claim_hash_rows, layout.placements[13], tree, destination);
            scatterPrefixRow(vm_io_hash_air, sources.inactive_prepared.io_hash_rows, layout.placements[14], tree, destination);
            scatterPrefixRow(vm_claim_semantics_air, sources.inactive_prepared.claim_semantics_rows, layout.placements[15], tree, destination);
            scatterPrefixRow(vm_public_logup_air, sources.inactive_prepared.public_logup_rows, layout.placements[16], tree, destination);
            scatterPrefixRow(vm_public_logup_control_air, sources.inactive_source.public_logup_control_rows, layout.placements[17], tree, destination);
        }

        pub fn scatterPrefixRow(
            comptime Air: type,
            rows: []const universal_binding.Binding(Air).Row,
            placement: universal_manifest.Placement,
            tree: usize,
            destination: []const []M31,
        ) void {
            const source_offset: usize = switch (tree) {
                PREFIX_TREE0_INDEX => Air.PHYSICAL_MAIN_COLUMN_COUNT,
                PREFIX_TREE1_INDEX => 0,
                else => unreachable,
            };
            const column_count: usize = switch (tree) {
                PREFIX_TREE0_INDEX => Air.PREPROCESSED_COLUMN_COUNT,
                PREFIX_TREE1_INDEX => Air.PHYSICAL_MAIN_COLUMN_COUNT,
                else => unreachable,
            };
            const destination_offset: usize = switch (tree) {
                PREFIX_TREE0_INDEX => placement.preprocessed_offset,
                PREFIX_TREE1_INDEX => placement.main_offset,
                else => unreachable,
            };
            for (0..column_count) |column| {
                const output = destination[destination_offset + column];
                for (rows, 0..) |row, logical_row| {
                    output[
                        framework_interaction.committedRow(
                            logical_row,
                            placement.geometry.log_size,
                        )
                    ] = row[source_offset + column];
                }
            }
        }

        pub fn preflightPrefixTree(
            writer: *const TemporalPrefixTreeWriterV3,
            sources: TemporalPrefixTreeSourcesV3,
            layout: *const TemporalPrefixCommitmentLayoutV3,
            tree: usize,
            destination: []const []M31,
        ) Error!void {
            // Every caller first executes `prepareLogicalRows`, which authenticates
            // the writer and sources. Keeping that single admission outside this
            // per-destination check avoids a duplicate full source-seal walk.
            try layout.validate();
            if (tree >= PREFIX_TREE_COUNT or
                destination.len != @as(
                    usize,
                    @intCast(prefixTreeColumnCount(layout, tree)),
                ))
            {
                return error.InvalidTraceShape;
            }
            for (layout.placements) |placement| {
                const offset: usize = @intCast(prefixTreeOffset(placement, tree));
                const count: usize = @intCast(prefixTreeColumns(placement, tree));
                const trace_size = @as(usize, 1) <<
                    @intCast(placement.geometry.log_size);
                if (offset + count > destination.len)
                    return error.InvalidTraceShape;
                for (destination[offset .. offset + count]) |column| {
                    if (column.len != trace_size) return error.InvalidTraceShape;
                    for (column) |value| if (!value.isZero())
                        return error.DestinationNotZero;
                }
            }
            for (destination, 0..) |column, index| {
                const range = try byteRange(column);
                for (destination[0..index]) |prior|
                    if (range.overlaps(try byteRange(prior)))
                        return error.DestinationAlias;
                try rejectPrefixDestinationSourceAlias(range, writer, sources);
            }
        }

        pub fn rejectPrefixDestinationSourceAlias(
            destination: ByteRange,
            writer: *const TemporalPrefixTreeWriterV3,
            sources: TemporalPrefixTreeSourcesV3,
        ) Error!void {
            inline for (.{
                std.mem.asBytes(writer),
                std.mem.asBytes(sources.custody),
                std.mem.asBytes(sources.transcript),
                std.mem.asBytes(sources.statement),
                std.mem.asBytes(sources.statement_authority),
                std.mem.asBytes(sources.statement_workspace),
                std.mem.asBytes(sources.inactive_source),
                std.mem.asBytes(sources.inactive_prepared),
                std.mem.asBytes(sources.typed_public),
                std.mem.asBytes(sources.vm_plan),
                std.mem.asBytes(sources.recursion_plan),
                std.mem.asBytes(sources.preprocessing),
            }) |source| if (destination.overlaps(try byteRange(source)))
                return error.DestinationAlias;
            inline for (.{
                std.mem.sliceAsBytes(writer.interaction_scratch),
                std.mem.sliceAsBytes(sources.transcript.rows),
                std.mem.sliceAsBytes(sources.transcript.operations),
                std.mem.sliceAsBytes(sources.transcript.frames),
                std.mem.sliceAsBytes(sources.statement.statement_values),
                std.mem.sliceAsBytes(sources.inactive_prepared.claim_input_rows),
                std.mem.sliceAsBytes(sources.inactive_prepared.claim_hash_rows),
                std.mem.sliceAsBytes(sources.inactive_prepared.io_hash_rows),
                std.mem.sliceAsBytes(sources.inactive_prepared.claim_semantics_rows),
                std.mem.sliceAsBytes(sources.inactive_prepared.public_logup_rows),
                std.mem.sliceAsBytes(
                    sources.inactive_source.public_logup_control_rows,
                ),
                std.mem.sliceAsBytes(writer.buffers.control),
                std.mem.sliceAsBytes(writer.buffers.transcript_air),
                std.mem.sliceAsBytes(writer.buffers.transcript_binding),
                std.mem.sliceAsBytes(writer.buffers.transcript_state),
                std.mem.sliceAsBytes(writer.buffers.transcript_word),
                std.mem.sliceAsBytes(writer.buffers.transcript_payload),
                std.mem.sliceAsBytes(writer.buffers.pow_check),
                std.mem.sliceAsBytes(writer.buffers.pow_frame),
                std.mem.sliceAsBytes(writer.buffers.packed_relation_challenge),
                std.mem.sliceAsBytes(writer.buffers.verifier_randomness),
                std.mem.sliceAsBytes(writer.buffers.statement_input),
                std.mem.sliceAsBytes(writer.buffers.statement_semantics),
            }) |source| if (destination.overlaps(try byteRange(source)))
                return error.DestinationAlias;
        }

        pub fn rejectPrefixTreeCrossAlias(
            left: []const []M31,
            right: []const []M31,
        ) Error!void {
            for (left) |left_column| {
                const left_range = try byteRange(left_column);
                for (right) |right_column|
                    if (left_range.overlaps(try byteRange(right_column)))
                        return error.DestinationAlias;
            }
        }

        pub fn clearPrefixTree(destination: []const []M31) void {
            for (destination) |column| @memset(column, M31.zero());
        }

        pub fn prefixTreeColumnCount(
            layout: *const TemporalPrefixCommitmentLayoutV3,
            tree: usize,
        ) u32 {
            return switch (tree) {
                PREFIX_TREE0_INDEX => layout.total_preprocessed_columns,
                PREFIX_TREE1_INDEX => layout.total_main_columns,
                PREFIX_TREE2_INDEX => layout.total_interaction_columns,
                else => 0,
            };
        }

        pub fn prefixTreeOffset(
            placement: universal_manifest.Placement,
            tree: usize,
        ) u32 {
            return switch (tree) {
                PREFIX_TREE0_INDEX => placement.preprocessed_offset,
                PREFIX_TREE1_INDEX => placement.main_offset,
                PREFIX_TREE2_INDEX => placement.interaction_offset,
                else => unreachable,
            };
        }

        pub fn prefixTreeColumns(
            placement: universal_manifest.Placement,
            tree: usize,
        ) u16 {
            return switch (tree) {
                PREFIX_TREE0_INDEX => placement.geometry.preprocessed_columns,
                PREFIX_TREE1_INDEX => placement.geometry.main_columns,
                PREFIX_TREE2_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
        }

        pub fn prefixTreeCellCount(
            layout: *const TemporalPrefixCommitmentLayoutV3,
            tree: usize,
        ) Error!u64 {
            if (tree >= PREFIX_TREE_COUNT) return error.InvalidTraceShape;
            var result: u64 = 0;
            for (layout.placements) |placement| {
                const cells = std.math.mul(
                    u64,
                    @as(u64, prefixTreeColumns(placement, tree)),
                    @as(u64, 1) << @intCast(placement.geometry.log_size),
                ) catch return error.ArithmeticOverflow;
                result = std.math.add(u64, result, cells) catch
                    return error.ArithmeticOverflow;
            }
            return result;
        }

        pub fn componentScratchCount(
            comptime Air: type,
            layout: *const TemporalPrefixCommitmentLayoutV3,
            row: usize,
        ) Error!usize {
            return InteractionFramework(Air).requiredScratchElementCount(
                layout.placements[row].geometry.log_size,
            );
        }

        pub fn prefixInteractionScratchCount(
            layout: *const TemporalPrefixCommitmentLayoutV3,
        ) Error!usize {
            try layout.validate();
            var result: usize = 0;
            result = @max(result, try componentScratchCount(control_air, layout, 0));
            result = @max(result, try componentScratchCount(transcript_component, layout, 1));
            result = @max(result, try componentScratchCount(transcript_binding_air, layout, 2));
            result = @max(result, try componentScratchCount(transcript_state_air, layout, 3));
            result = @max(result, try componentScratchCount(transcript_word_air, layout, 4));
            result = @max(result, try componentScratchCount(transcript_payload, layout, 5));
            result = @max(result, try componentScratchCount(pow_check_air, layout, 6));
            result = @max(result, try componentScratchCount(pow_frame_air, layout, 7));
            result = @max(result, try componentScratchCount(packed_relation_challenge_v2, layout, 8));
            result = @max(result, try componentScratchCount(verifier_randomness_air, layout, 9));
            result = @max(result, try componentScratchCount(statement_input_air, layout, 10));
            result = @max(result, try componentScratchCount(statement_semantics_air, layout, 11));
            result = @max(result, try componentScratchCount(vm_claim_input_air, layout, 12));
            result = @max(result, try componentScratchCount(vm_claim_hash_air, layout, 13));
            result = @max(result, try componentScratchCount(vm_io_hash_air, layout, 14));
            result = @max(result, try componentScratchCount(vm_claim_semantics_air, layout, 15));
            result = @max(result, try componentScratchCount(vm_public_logup_air, layout, 16));
            result = @max(result, try componentScratchCount(vm_public_logup_control_air, layout, 17));
            return result;
        }
    };
}
