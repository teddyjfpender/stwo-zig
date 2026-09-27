//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const recursion = context.d_recursion;
        const air = context.d_air;
        const merkle_root_witness = context.d_merkle_root_witness;
        const trace_merkle_witness = context.d_trace_merkle_witness;
        const schedule = context.d_schedule;
        const lowering = context.d_lowering;
        const multiply_witness = context.d_multiply_witness;
        const inverse_witness = context.d_inverse_witness;
        const linear_witness = context.d_linear_witness;
        const merkle_path_witness = context.d_merkle_path_witness;
        const manifest_mod = context.d_manifest_mod;
        const universal_manifest = context.d_universal_manifest;
        const shared_provider = context.d_shared_provider;
        const range_bridge = context.d_range_bridge;
        const SegmentTranscriptSource = context.d_SegmentTranscriptSource;
        const SegmentLeafOuterBundle = context.d_SegmentLeafOuterBundle;
        const LogIndex = context.d_LogIndex;
        const InputAdapter = context.d_InputAdapter;
        const VmInputAdapter = context.d_VmInputAdapter;
        const CompositionControlAdapter = context.d_CompositionControlAdapter;
        const QueryBitsAdapter = context.d_QueryBitsAdapter;
        const QueryMappingAdapter = context.d_QueryMappingAdapter;
        const MerkleRootAdapter = context.d_MerkleRootAdapter;
        const TraceMerkleAdapter = context.d_TraceMerkleAdapter;
        const PcsAdapter = context.d_PcsAdapter;
        const FriLeafAdapter = context.d_FriLeafAdapter;
        const FriNodeAdapter = context.d_FriNodeAdapter;
        const FriAnchorAdapter = context.d_FriAnchorAdapter;
        const ControlAdapter = context.d_ControlAdapter;
        const MultiplyAdapter = context.d_MultiplyAdapter;
        const InverseAdapter = context.d_InverseAdapter;
        const LinearAdapter = context.d_LinearAdapter;
        const MerklePathAdapter = context.d_MerklePathAdapter;
        const INACTIVE_LOG_SIZE = context.d_INACTIVE_LOG_SIZE;
        const SegmentTranscriptInputs = context.d_SegmentTranscriptInputs;
        const VmAirAuthority = context.d_VmAirAuthority;
        const Authority = context.d_Authority;
        const tracePathRowCount = context.d_tracePathRowCount;
        const mapTreeQueryPosition = context.d_mapTreeQueryPosition;

        pub fn buildAuthorityManifest(
            full_roster: bool,
            vm_air: ?VmAirAuthority,
            log_sizes: [LogIndex.count]u32,
            admitted_segment_leaf_bundle: ?SegmentLeafOuterBundle,
        ) !manifest_mod.Manifest {
            return if (full_roster) blk: {
                var universal_logs = [_]u32{INACTIVE_LOG_SIZE} **
                    air.universal_roster.COMPONENT_COUNT;
                universal_logs[@intFromEnum(air.universal_roster.Component.vm_air_composition_input)] =
                    log_sizes[LogIndex.vm_input];
                universal_logs[@intFromEnum(air.universal_roster.Component.vm_air_composition_control)] =
                    log_sizes[LogIndex.composition_control];
                universal_logs[@intFromEnum(air.universal_roster.Component.query_bits)] =
                    log_sizes[LogIndex.query_bits];
                universal_logs[@intFromEnum(air.universal_roster.Component.query_mapping)] =
                    log_sizes[LogIndex.query_mapping];
                universal_logs[@intFromEnum(air.universal_roster.Component.merkle_root)] =
                    log_sizes[LogIndex.merkle_root];
                universal_logs[@intFromEnum(air.universal_roster.Component.trace_merkle)] =
                    log_sizes[LogIndex.trace_merkle];
                universal_logs[@intFromEnum(air.universal_roster.Component.pcs_deep_input)] =
                    log_sizes[LogIndex.pcs_deep];
                universal_logs[@intFromEnum(air.universal_roster.Component.fri_merkle_leaf)] =
                    log_sizes[LogIndex.fri_leaf];
                universal_logs[@intFromEnum(air.universal_roster.Component.fri_merkle_node)] =
                    log_sizes[LogIndex.fri_node];
                universal_logs[@intFromEnum(air.universal_roster.Component.fri_merkle_anchor)] =
                    log_sizes[LogIndex.fri_anchor];
                universal_logs[@intFromEnum(air.universal_roster.Component.fri_verifier_control)] =
                    log_sizes[LogIndex.fri_control];
                universal_logs[@intFromEnum(air.universal_roster.Component.fri_verifier_input)] =
                    log_sizes[LogIndex.fri_input];
                universal_logs[@intFromEnum(air.universal_roster.Component.qm31_mul)] =
                    log_sizes[LogIndex.multiply];
                universal_logs[@intFromEnum(air.universal_roster.Component.qm31_inv)] =
                    log_sizes[LogIndex.inverse];
                universal_logs[@intFromEnum(air.universal_roster.Component.linear_ops)] =
                    log_sizes[LogIndex.linear];
                universal_logs[@intFromEnum(air.universal_roster.Component.merkle_path)] =
                    log_sizes[LogIndex.merkle_path];
                universal_logs[@intFromEnum(air.universal_roster.Component.poseidon2)] =
                    log_sizes[LogIndex.poseidon2];
                universal_logs[@intFromEnum(air.universal_roster.Component.range_check_8_8)] =
                    range_bridge.LOG_SIZE;
                const bundle = admitted_segment_leaf_bundle.?;
                bundle.installLogSizes(&universal_logs);
                break :blk try universal_manifest.build(universal_logs);
            } else blk: {
                var builder = manifest_mod.Builder{};
                if (vm_air != null) _ = try builder.append(
                    VmInputAdapter.manifestGeometry(
                        .vm_air_composition_input,
                        log_sizes[LogIndex.vm_input],
                    ),
                );
                _ = try builder.append(CompositionControlAdapter.manifestGeometry(
                    .vm_air_composition_control,
                    log_sizes[LogIndex.composition_control],
                ));
                _ = try builder.append(QueryBitsAdapter.manifestGeometry(
                    .query_bits,
                    log_sizes[LogIndex.query_bits],
                ));
                _ = try builder.append(QueryMappingAdapter.manifestGeometry(
                    .query_mapping,
                    log_sizes[LogIndex.query_mapping],
                ));
                _ = try builder.append(MerkleRootAdapter.manifestGeometry(
                    .merkle_root,
                    log_sizes[LogIndex.merkle_root],
                ));
                _ = try builder.append(TraceMerkleAdapter.manifestGeometry(
                    .trace_merkle,
                    log_sizes[LogIndex.trace_merkle],
                ));
                _ = try builder.append(PcsAdapter.manifestGeometry(
                    .pcs_deep_input,
                    log_sizes[LogIndex.pcs_deep],
                ));
                _ = try builder.append(FriLeafAdapter.manifestGeometry(
                    .fri_merkle_leaf,
                    log_sizes[LogIndex.fri_leaf],
                ));
                _ = try builder.append(FriNodeAdapter.manifestGeometry(
                    .fri_merkle_node,
                    log_sizes[LogIndex.fri_node],
                ));
                _ = try builder.append(FriAnchorAdapter.manifestGeometry(
                    .fri_merkle_anchor,
                    log_sizes[LogIndex.fri_anchor],
                ));
                _ = try builder.append(ControlAdapter.manifestGeometry(
                    .fri_verifier_control,
                    log_sizes[LogIndex.fri_control],
                ));
                _ = try builder.append(InputAdapter.manifestGeometry(
                    .fri_verifier_input,
                    log_sizes[LogIndex.fri_input],
                ));
                _ = try builder.append(MultiplyAdapter.manifestGeometry(
                    .qm31_mul,
                    log_sizes[LogIndex.multiply],
                ));
                _ = try builder.append(InverseAdapter.manifestGeometry(
                    .qm31_inv,
                    log_sizes[LogIndex.inverse],
                ));
                _ = try builder.append(LinearAdapter.manifestGeometry(
                    .linear_ops,
                    log_sizes[LogIndex.linear],
                ));
                _ = try builder.append(MerklePathAdapter.manifestGeometry(
                    .merkle_path,
                    log_sizes[LogIndex.merkle_path],
                ));
                _ = try builder.append(shared_provider.Poseidon2Adapter.manifestGeometry(
                    log_sizes[LogIndex.poseidon2],
                ));
                break :blk try builder.seal();
            };
        }

        pub fn initSegmentLeafBundle(
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            inputs: SegmentTranscriptInputs,
            transcript_source: *const SegmentTranscriptSource,
        ) !SegmentLeafOuterBundle {
            return SegmentLeafOuterBundle.init(segmentLeafBundleInputs(
                vm_plan,
                recursion_plan,
                inputs,
                transcript_source,
            ));
        }

        pub fn segmentLeafBundleInputs(
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            inputs: SegmentTranscriptInputs,
            transcript_source: *const SegmentTranscriptSource,
        ) SegmentLeafOuterBundle.Inputs {
            return .{
                .vm_plan = vm_plan,
                .recursion_plan = recursion_plan,
                .transcript_preprocessing = inputs.preprocessing,
                .transcript_prepared = inputs.prepared,
                .transcript_source = transcript_source,
                .leaf_preprocessing = inputs.public.leaf_preprocessing,
                .leaf = inputs.public.leaf,
                .public_data = inputs.public.data,
                .statement_authority = inputs.statement.authority,
                .statement_workspace = inputs.statement.workspace,
                .statement_prepared = inputs.statement.prepared,
                .public_source = inputs.public.source,
                .public_prepared = inputs.public.prepared,
            };
        }

        /// Reconstructs the admitted bundle after the owning `Authority` has reached
        /// its stable address.  The transcript source is Authority-owned by value, so
        /// caching the original bundle itself would retain a pointer into the moved
        /// pre-return local.  This reconstruction is allocation-free and the token
        /// binds every externally borrowed address plus the schedule/manifest seals.
        pub fn admittedSegmentLeafBundle(
            authority: *const Authority,
        ) !SegmentLeafOuterBundle {
            const inputs = authority.segment_transcript_inputs orelse
                return error.AuthorityMismatch;
            const transcript_source = if (authority.segment_transcript) |*source|
                source
            else
                return error.AuthorityMismatch;
            const admission = authority.segment_leaf_admission orelse
                return error.AuthorityMismatch;
            try admission.validateFor(
                authority.vm_schedule,
                authority.recursion_schedule,
                inputs,
                &authority.manifest,
            );
            return .{ .inputs = segmentLeafBundleInputs(
                authority.vm_schedule,
                authority.recursion_schedule,
                inputs,
                transcript_source,
            ) };
        }

        /// Full hostile-boundary reconstruction retained at component publication.
        /// This is intentionally independent of the cheap fill capability so an
        /// in-place mutation after the final writer cannot enter the proof gate.
        pub fn checkedSegmentLeafBundle(
            authority: *const Authority,
        ) !SegmentLeafOuterBundle {
            const inputs = authority.segment_transcript_inputs orelse
                return error.AuthorityMismatch;
            const transcript_source = if (authority.segment_transcript) |*source|
                source
            else
                return error.AuthorityMismatch;
            return initSegmentLeafBundle(
                authority.vm_schedule,
                authority.recursion_schedule,
                inputs,
                transcript_source,
            );
        }

        pub const InvocationBuffers = struct {
            allocator: std.mem.Allocator,
            multiply: []multiply_witness.Invocation,
            inverse: []inverse_witness.Invocation,
            linear: []linear_witness.Invocation,

            pub fn init(
                allocator: std.mem.Allocator,
                counts: lowering.Counts,
            ) !InvocationBuffers {
                const multiply = try allocator.alloc(multiply_witness.Invocation, counts.multiply);
                errdefer allocator.free(multiply);
                const inverse = try allocator.alloc(inverse_witness.Invocation, counts.inverse);
                errdefer allocator.free(inverse);
                const linear = try allocator.alloc(linear_witness.Invocation, counts.linear);
                errdefer allocator.free(linear);
                return .{
                    .allocator = allocator,
                    .multiply = multiply,
                    .inverse = inverse,
                    .linear = linear,
                };
            }

            pub fn deinit(self: *InvocationBuffers) void {
                self.allocator.free(self.linear);
                self.allocator.free(self.inverse);
                self.allocator.free(self.multiply);
                self.* = undefined;
            }

            pub fn view(self: *InvocationBuffers) lowering.InvocationBuffers {
                return .{
                    .multiply = self.multiply,
                    .inverse = self.inverse,
                    .linear = self.linear,
                };
            }
        };

        pub const MerklePathBuffers = struct {
            allocator: std.mem.Allocator,
            leaf_digests: [][merkle_path_witness.DIGEST_WORD_COUNT]u32,
            trace_leaf_count: usize,
            fri_leaf_count: usize,
            invocations: []merkle_path_witness.Invocation,
            ready: bool,

            pub fn init(
                allocator: std.mem.Allocator,
                captured: *const recursion.captured_fri.Owned,
            ) !MerklePathBuffers {
                const query_count = captured.raw_queries.len;
                const trace_leaf_count = std.math.mul(
                    usize,
                    captured.trace_tree_heights.len,
                    query_count,
                ) catch return error.ArithmeticOverflow;
                const fri_leaf_count = std.math.mul(
                    usize,
                    captured.fri_siblings.len,
                    query_count,
                ) catch return error.ArithmeticOverflow;
                const leaf_count = std.math.add(
                    usize,
                    trace_leaf_count,
                    fri_leaf_count,
                ) catch return error.ArithmeticOverflow;
                const leaf_digests = try allocator.alloc(
                    [merkle_path_witness.DIGEST_WORD_COUNT]u32,
                    leaf_count,
                );
                errdefer allocator.free(leaf_digests);
                var invocation_count = try tracePathRowCount(
                    captured.trace_tree_heights,
                    captured.circuit.query_count,
                );
                for (captured.fri_siblings) |siblings| {
                    if (query_count == 0 or siblings.len % query_count != 0)
                        return error.AuthorityMismatch;
                    invocation_count = std.math.add(
                        usize,
                        invocation_count,
                        siblings.len,
                    ) catch return error.ArithmeticOverflow;
                }
                const invocations = try allocator.alloc(
                    merkle_path_witness.Invocation,
                    invocation_count,
                );
                return .{
                    .allocator = allocator,
                    .leaf_digests = leaf_digests,
                    .trace_leaf_count = trace_leaf_count,
                    .fri_leaf_count = fri_leaf_count,
                    .invocations = invocations,
                    .ready = false,
                };
            }

            pub fn deinit(self: *MerklePathBuffers) void {
                self.allocator.free(self.invocations);
                self.allocator.free(self.leaf_digests);
                self.* = undefined;
            }

            pub fn materialize(
                self: *MerklePathBuffers,
                captured: *const recursion.captured_fri.Owned,
            ) !void {
                if (self.ready or captured.trace_siblings.len != captured.trace_roots.len or
                    captured.trace_tree_heights.len != captured.trace_roots.len or
                    captured.fri_siblings.len != captured.fri_roots.len or
                    captured.fri_siblings.len != captured.fold_widths.len)
                {
                    return error.AuthorityMismatch;
                }
                const query_count = captured.raw_queries.len;
                const expected_trace_leaf_count = std.math.mul(
                    usize,
                    captured.trace_tree_heights.len,
                    query_count,
                ) catch return error.ArithmeticOverflow;
                const expected_fri_leaf_count = std.math.mul(
                    usize,
                    captured.fri_siblings.len,
                    query_count,
                ) catch return error.ArithmeticOverflow;
                if (self.trace_leaf_count != expected_trace_leaf_count or
                    self.fri_leaf_count != expected_fri_leaf_count or
                    self.leaf_digests.len != self.trace_leaf_count + self.fri_leaf_count)
                {
                    return error.AuthorityMismatch;
                }
                var cursor: usize = 0;
                for (captured.trace_tree_heights, 0..) |height_u32, tree| {
                    const height: usize = @intCast(height_u32);
                    const siblings = captured.trace_siblings[tree];
                    if (siblings.len != try std.math.mul(usize, query_count, height))
                        return error.AuthorityMismatch;
                    const tree_id = try merkle_root_witness.traceTreeId(
                        merkle_root_witness.SEGMENT_VERIFIER_ID,
                        tree,
                    );
                    for (captured.raw_queries, 0..) |raw_query, query| {
                        const position = mapTreeQueryPosition(
                            raw_query.toU32(),
                            captured.circuit.lifting_log_size,
                            height_u32,
                        );
                        const start = cursor;
                        for (0..height) |depth| {
                            const leaf_layer = height - depth - 1;
                            const direction: u32 = @intCast(
                                (position >> @intCast(leaf_layer)) & 1,
                            );
                            self.invocations[cursor] = .{
                                .tree_id = tree_id,
                                .depth = @intCast(depth),
                                .index = @intCast(position >> @intCast(height - depth)),
                                .child = [_]u32{0} ** merkle_path_witness.DIGEST_WORD_COUNT,
                                .step = .{
                                    .direction = direction,
                                    .sibling = siblings[query * height + leaf_layer],
                                },
                                .is_leaf = depth + 1 == height,
                            };
                            cursor += 1;
                        }
                        var current = self.leaf_digests[tree * query_count + query];
                        var reverse = cursor;
                        while (reverse > start) {
                            reverse -= 1;
                            self.invocations[reverse].child = current;
                            current = try merkle_path_witness.parentDigest(
                                self.invocations[reverse],
                            );
                        }
                        if (!std.mem.eql(u32, &current, &captured.trace_roots[tree]))
                            return error.AuthorityMismatch;
                    }
                }

                var folded_bits: u32 = 0;
                for (
                    captured.fri_siblings,
                    captured.fri_roots,
                    captured.fold_widths,
                    0..,
                ) |siblings, root, fold_width, layer| {
                    if (!std.math.isPowerOfTwo(fold_width) or query_count == 0 or
                        siblings.len % query_count != 0)
                    {
                        return error.AuthorityMismatch;
                    }
                    folded_bits = std.math.add(
                        u32,
                        folded_bits,
                        std.math.log2_int(u32, fold_width),
                    ) catch return error.ArithmeticOverflow;
                    const path_depth = siblings.len / query_count;
                    if (folded_bits >= captured.circuit.lifting_log_size or
                        path_depth == 0 or
                        path_depth >= @bitSizeOf(u32) or
                        path_depth != captured.circuit.lifting_log_size - folded_bits)
                    {
                        return error.AuthorityMismatch;
                    }
                    const tree_id = try merkle_root_witness.friTreeId(
                        merkle_root_witness.SEGMENT_VERIFIER_ID,
                        layer,
                    );
                    for (captured.raw_queries, 0..) |raw_query, query| {
                        const position = raw_query.toU32() >> @intCast(folded_bits);
                        if (position >= @as(u32, 1) << @intCast(path_depth))
                            return error.AuthorityMismatch;
                        const start = cursor;
                        for (0..path_depth) |depth| {
                            const leaf_layer = path_depth - depth - 1;
                            const direction: u32 = @intCast(
                                (position >> @intCast(leaf_layer)) & 1,
                            );
                            self.invocations[cursor] = .{
                                .tree_id = tree_id,
                                .depth = @intCast(depth),
                                .index = @intCast(
                                    position >> @intCast(path_depth - depth),
                                ),
                                .child = [_]u32{0} **
                                    merkle_path_witness.DIGEST_WORD_COUNT,
                                .step = .{
                                    .direction = direction,
                                    .sibling = siblings[
                                        query * path_depth + leaf_layer
                                    ],
                                },
                                .is_leaf = depth + 1 == path_depth,
                            };
                            cursor += 1;
                        }
                        const leaf_index = self.trace_leaf_count +
                            layer * query_count + query;
                        var current = self.leaf_digests[leaf_index];
                        var reverse = cursor;
                        while (reverse > start) {
                            reverse -= 1;
                            self.invocations[reverse].child = current;
                            current = try merkle_path_witness.parentDigest(
                                self.invocations[reverse],
                            );
                        }
                        if (!std.mem.eql(u32, &current, &root))
                            return error.AuthorityMismatch;
                    }
                }
                if (cursor != self.invocations.len) return error.AuthorityMismatch;
                self.ready = true;
            }
        };

        pub fn captureTracePathLeaves(
            paths: *MerklePathBuffers,
            captured: *const recursion.captured_fri.Owned,
            rows: []const trace_merkle_witness.Row,
            columns: *const [trace_merkle_witness.MAIN_COLUMN_COUNT][]M31,
        ) !void {
            var captured_count: usize = 0;
            const output_start: usize = @intFromEnum(
                trace_merkle_witness.MainSource.output_0,
            );
            for (rows, 0..) |row, row_index| {
                if (row.verifier_id != trace_merkle_witness.SEGMENT_VERIFIER_ID or
                    row.last != 1)
                {
                    continue;
                }
                const leaf_index = @as(usize, row.tree) * captured.raw_queries.len +
                    @as(usize, row.query);
                if (leaf_index >= paths.trace_leaf_count)
                    return error.AuthorityMismatch;
                for (&paths.leaf_digests[leaf_index], 0..) |*word, index|
                    word.* = columns.*[output_start + index][row_index].toU32();
                captured_count += 1;
            }
            if (captured_count != paths.trace_leaf_count)
                return error.AuthorityMismatch;
        }
    };
}
