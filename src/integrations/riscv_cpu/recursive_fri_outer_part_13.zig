//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const circuit_mod = context.d_circuit_mod;
        const trace_merkle_air = context.d_trace_merkle_air;
        const trace_merkle_witness = context.d_trace_merkle_witness;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const fri_node_witness = context.d_fri_node_witness;
        const fri_anchor_witness = context.d_fri_anchor_witness;
        const schedule = context.d_schedule;
        const lowering = context.d_lowering;
        const merkle_path_witness = context.d_merkle_path_witness;
        const merkle_path_poseidon = context.d_merkle_path_poseidon;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const framework = context.d_framework;
        const poseidon2_air = context.d_poseidon2_air;
        const MAX_ARITHMETIC_EVALUATION_LANES = context.d_MAX_ARITHMETIC_EVALUATION_LANES;
        const Authority = context.d_Authority;
        const MerklePathBuffers = context.d_MerklePathBuffers;

        pub fn captureFriPathLeaves(
            paths: *MerklePathBuffers,
            captured: *const recursion.captured_fri.Owned,
            rows: []const fri_anchor_witness.Row,
            columns: *const [fri_anchor_witness.MAIN_COLUMN_COUNT][]M31,
        ) !void {
            var captured_count: usize = 0;
            const digest_start: usize = @intFromEnum(
                fri_anchor_witness.MainSource.digest_0,
            );
            for (rows, 0..) |row, row_index| {
                if (row.verifier_id != fri_anchor_witness.SEGMENT_VERIFIER_ID)
                    continue;
                const leaf_index = paths.trace_leaf_count +
                    @as(usize, row.layer) * captured.raw_queries.len +
                    @as(usize, row.query);
                if (leaf_index >= paths.leaf_digests.len)
                    return error.AuthorityMismatch;
                for (&paths.leaf_digests[leaf_index], 0..) |*word, index|
                    word.* = columns.*[digest_start + index][row_index].toU32();
                captured_count += 1;
            }
            if (captured_count != paths.fri_leaf_count)
                return error.AuthorityMismatch;
        }

        /// Exact-capacity provider schedule for every active Poseidon2-I/O
        /// requester in this outer proof. Calls are derived from already-materialized
        /// consumer columns; outputs are retained only as compact endpoints so Tree 2
        /// never repeats the permutation performed for the provider main trace.
        pub const PoseidonCallBuffers = struct {
            allocator: std.mem.Allocator,
            calls: []poseidon2_air.Call,
            outputs: [][poseidon2_air.WIDTH]u32,
            cursor: usize,
            outputs_ready: bool,

            pub fn init(allocator: std.mem.Allocator, count: usize) !PoseidonCallBuffers {
                const calls = try allocator.alloc(poseidon2_air.Call, count);
                errdefer allocator.free(calls);
                const outputs = try allocator.alloc([poseidon2_air.WIDTH]u32, count);
                return .{
                    .allocator = allocator,
                    .calls = calls,
                    .outputs = outputs,
                    .cursor = 0,
                    .outputs_ready = false,
                };
            }

            pub fn deinit(self: *PoseidonCallBuffers) void {
                self.allocator.free(self.outputs);
                self.allocator.free(self.calls);
                self.* = undefined;
            }

            pub fn appendAuthenticatedPrefix(
                self: *PoseidonCallBuffers,
                calls: []const poseidon2_air.Call,
            ) !void {
                if (self.cursor != 0 or calls.len == 0 or calls.len > self.calls.len)
                    return error.AuthorityMismatch;
                @memcpy(self.calls[0..calls.len], calls);
                self.cursor = calls.len;
            }

            pub fn preparedSuffix(
                self: *const PoseidonCallBuffers,
                start: usize,
            ) ![]const poseidon2_air.Call {
                if (start > self.cursor or self.outputs_ready)
                    return error.AuthorityMismatch;
                return self.calls[start..self.cursor];
            }

            pub fn appendTraceMerkle(
                self: *PoseidonCallBuffers,
                rows: []const trace_merkle_witness.Row,
                columns: *const [trace_merkle_witness.MAIN_COLUMN_COUNT][]M31,
            ) !void {
                return self.appendSponge(
                    rows,
                    columns,
                    @intFromEnum(trace_merkle_witness.MainSource.previous_0),
                    @intFromEnum(trace_merkle_witness.MainSource.chunk_0),
                );
            }

            pub fn appendFriLeaf(
                self: *PoseidonCallBuffers,
                rows: []const fri_leaf_witness.Row,
                columns: *const [fri_leaf_witness.MAIN_COLUMN_COUNT][]M31,
            ) !void {
                return self.appendSponge(
                    rows,
                    columns,
                    @intFromEnum(fri_leaf_witness.MainSource.previous_0),
                    @intFromEnum(fri_leaf_witness.MainSource.chunk_0),
                );
            }

            fn appendSponge(
                self: *PoseidonCallBuffers,
                rows: anytype,
                columns: anytype,
                previous_start: usize,
                chunk_start: usize,
            ) !void {
                for (rows, 0..) |row, row_index| {
                    if (row.segment_mask != 1) continue;
                    if (!columns.*[0][row_index].eql(M31.one()) or
                        self.cursor >= self.calls.len)
                    {
                        return error.AuthorityMismatch;
                    }
                    var input: [poseidon2_air.WIDTH]u32 = undefined;
                    for (&input, 0..) |*word, lane| {
                        var value = columns.*[previous_start + lane][row_index];
                        if (lane < trace_merkle_air.RATE) value = value.add(
                            columns.*[chunk_start + lane][row_index],
                        );
                        word.* = value.toU32();
                    }
                    self.calls[self.cursor] = .{
                        .input = input,
                        .wide = false,
                        .io = true,
                        .narrow_output = null,
                    };
                    self.cursor += 1;
                }
            }

            pub fn appendFriNodes(
                self: *PoseidonCallBuffers,
                rows: []const fri_node_witness.Row,
                columns: *const [fri_node_witness.MAIN_COLUMN_COUNT][]M31,
            ) !void {
                const left_start: usize = @intFromEnum(fri_node_witness.MainSource.left_0);
                const right_start: usize = @intFromEnum(fri_node_witness.MainSource.right_0);
                for (rows, 0..) |row, row_index| {
                    if (row.segment_mask != 1) continue;
                    if (!columns.*[0][row_index].eql(M31.one()) or
                        self.cursor >= self.calls.len)
                    {
                        return error.AuthorityMismatch;
                    }
                    var input: [poseidon2_air.WIDTH]u32 = undefined;
                    for (input[0..8], 0..) |*word, lane|
                        word.* = columns.*[left_start + lane][row_index].toU32();
                    for (input[8..16], 0..) |*word, lane|
                        word.* = columns.*[right_start + lane][row_index].toU32();
                    self.calls[self.cursor] = .{
                        .input = input,
                        .wide = false,
                        .io = true,
                        .narrow_output = null,
                    };
                    self.cursor += 1;
                }
            }

            pub fn appendPublic(
                self: *PoseidonCallBuffers,
                prepared: *const recursion.segment_public_outer_source.Prepared,
                leaf: *const recursion.segment_leaf_authority.Prepared,
            ) !void {
                const count = prepared.poseidonCallCount(leaf);
                if (count > self.calls.len - self.cursor)
                    return error.AuthorityMismatch;
                try prepared.appendPoseidonCallsInto(
                    leaf,
                    self.calls[self.cursor .. self.cursor + count],
                );
                self.cursor += count;
            }

            pub fn appendTranscript(
                self: *PoseidonCallBuffers,
                execution: *const recursion.transcript_program.Execution,
            ) !void {
                if (execution.poseidon_calls.len > self.calls.len - self.cursor)
                    return error.AuthorityMismatch;
                for (execution.poseidon_calls) |source| {
                    var input: [poseidon2_air.WIDTH]u32 = undefined;
                    for (&input, source.input) |*destination, word|
                        destination.* = word.toU32();
                    self.calls[self.cursor] = .{
                        .input = input,
                        .wide = false,
                        .io = true,
                        .narrow_output = null,
                    };
                    self.cursor += 1;
                }
            }

            pub fn appendMerklePaths(
                self: *PoseidonCallBuffers,
                invocations: []const merkle_path_witness.Invocation,
            ) !void {
                if (invocations.len > self.calls.len - self.cursor)
                    return error.AuthorityMismatch;
                try merkle_path_poseidon.fillCallsInto(
                    self.calls[self.cursor .. self.cursor + invocations.len],
                    invocations,
                );
                self.cursor += invocations.len;
            }

            pub fn callsView(self: *const PoseidonCallBuffers) ![]const poseidon2_air.Call {
                if (self.cursor != self.calls.len) return error.AuthorityMismatch;
                return self.calls;
            }

            pub fn captureOutputs(
                self: *PoseidonCallBuffers,
                columns: *const [poseidon2_air.N_MAIN_COLUMNS][]M31,
                log_size: u32,
            ) !void {
                if (self.outputs_ready or self.cursor != self.calls.len)
                    return error.AuthorityMismatch;
                const output_start = shared_provider.POSEIDON_OUTPUT_COLUMN_START;
                for (self.outputs, 0..) |*output, logical_row| {
                    const committed_row = framework.committedRow(logical_row, log_size);
                    if (!columns.*[0][committed_row].eql(M31.one()))
                        return error.AuthorityMismatch;
                    for (output, 0..) |*word, lane|
                        word.* = columns.*[output_start + lane][committed_row].toU32();
                }
                self.outputs_ready = true;
            }

            pub fn outputsView(
                self: *const PoseidonCallBuffers,
            ) ![]const [poseidon2_air.WIDTH]u32 {
                if (!self.outputs_ready or self.cursor != self.calls.len)
                    return error.AuthorityMismatch;
                return self.outputs;
            }

            /// Prover-side assembly audit. The final recursive verifier will enforce
            /// this through whole-manifest global cancellation once every open domain
            /// has its provider; until then this catches call extraction drift without
            /// pretending an isolated public request claim is protocol authority.
            pub fn auditWitnessClaimClosure(
                self: *const PoseidonCallBuffers,
                provider_claims: [poseidon2_air.N_SUMS]QM31,
                relations: *const universal.UniversalRelations,
            ) !void {
                const outputs = try self.outputsView();
                const challenge = try relations.getExact(.poseidon2_io);
                var request_claim = QM31.zero();
                for (self.calls, outputs) |call, output| {
                    var tuple: [2 * poseidon2_air.WIDTH]M31 = undefined;
                    for (tuple[0..poseidon2_air.WIDTH], call.input) |*word, value|
                        word.* = M31.fromCanonical(value);
                    for (tuple[poseidon2_air.WIDTH..], output) |*word, value|
                        word.* = M31.fromCanonical(value);
                    const denominator = try challenge.combineBase(&tuple);
                    const inverse = denominator.inv() catch
                        return error.PoseidonClosureMismatch;
                    request_claim = request_claim.sub(inverse);
                }
                if (!request_claim
                    .add(provider_claims[0])
                    .add(provider_claims[1])
                    .isZero())
                {
                    return error.PoseidonClosureMismatch;
                }
            }
        };

        pub fn tracePathRowCount(heights: []const u32, query_count: u32) !usize {
            var depth_sum: usize = 0;
            for (heights) |height| depth_sum = std.math.add(
                usize,
                depth_sum,
                @as(usize, height),
            ) catch return error.ArithmeticOverflow;
            return std.math.mul(usize, depth_sum, @as(usize, query_count)) catch
                return error.ArithmeticOverflow;
        }

        pub fn merklePathRowCount(
            trace_heights: []const u32,
            query_count: u32,
            fri_anchor_rows: []const fri_anchor_witness.Row,
        ) !usize {
            var result = try tracePathRowCount(trace_heights, query_count);
            for (fri_anchor_rows) |row| {
                if (row.segment_mask != 1) continue;
                result = std.math.add(
                    usize,
                    result,
                    @as(usize, row.path_depth),
                ) catch return error.ArithmeticOverflow;
            }
            return result;
        }

        pub fn poseidonCallCount(
            trace_rows: []const trace_merkle_witness.Row,
            fri_leaf_rows: []const fri_leaf_witness.Row,
            fri_node_rows: []const fri_node_witness.Row,
            path_rows: usize,
        ) !usize {
            var result = path_rows;
            for (trace_rows) |row| {
                if (row.segment_mask == 1)
                    result = try std.math.add(usize, result, 1);
            }
            for (fri_leaf_rows) |row| {
                if (row.segment_mask == 1)
                    result = try std.math.add(usize, result, 1);
            }
            for (fri_node_rows) |row| {
                if (row.segment_mask == 1)
                    result = try std.math.add(usize, result, 1);
            }
            return result;
        }

        pub fn mapTreeQueryPosition(position: u32, max_log_size: u32, tree_log_size: u32) u32 {
            if (tree_log_size == 0) return 0;
            if (max_log_size < tree_log_size) {
                return (position >> 1 << @intCast(tree_log_size - max_log_size + 1)) +
                    (position & 1);
            }
            return (position >> @intCast(max_log_size - tree_log_size + 1) << 1) +
                (position & 1);
        }

        pub fn buildArithmeticEvaluations(
            authority: *const Authority,
            captured: *const recursion.captured_fri.Owned,
            inactive: *const circuit_mod.Evaluation,
            public_native_sum_evaluation: ?lowering.Evaluation,
            storage: *[MAX_ARITHMETIC_EVALUATION_LANES]lowering.Evaluation,
        ) !lowering.Evaluations {
            var cursor: usize = 0;
            if (authority.vm_air) |prepared| {
                storage[cursor] = .{
                    .circuit_identity = prepared.prepared.evaluation.circuit_identity,
                    .values = prepared.prepared.evaluation.values,
                };
                cursor += 1;
            }
            if (authority.public_native_sum_lane) |lane| {
                const evaluation = public_native_sum_evaluation orelse
                    return error.AuthorityMismatch;
                if (!std.mem.eql(
                    u8,
                    &evaluation.circuit_identity,
                    &lane.circuit_identity,
                ) or evaluation.values.len != lane.graph.nodes.len)
                    return error.AuthorityMismatch;
                storage[cursor] = evaluation;
                cursor += 1;
            } else if (public_native_sum_evaluation != null) {
                return error.AuthorityMismatch;
            }
            if (authority.segment_transcript_inputs) |inputs| {
                storage[cursor] = inputs.statement.prepared.loweringEvaluation();
                cursor += 1;
                const public_evaluations = inputs.public.prepared.loweringEvaluations(
                    inputs.public.source,
                );
                @memcpy(
                    storage[cursor..][0..public_evaluations.len],
                    &public_evaluations,
                );
                cursor += public_evaluations.len;
            }
            const base = [2]lowering.Evaluation{
                .{
                    .circuit_identity = captured.pcs_evaluation.circuit_identity,
                    .values = captured.pcs_evaluation.values,
                },
                .{
                    .circuit_identity = captured.evaluation.circuit_identity,
                    .values = captured.evaluation.values,
                },
            };
            @memcpy(storage[cursor..][0..base.len], &base);
            cursor += base.len;
            if (authority.vm_air) |prepared| {
                storage[cursor] = .{
                    .circuit_identity = prepared.prepared.evaluation.circuit_identity,
                    .values = prepared.prepared.evaluation.values,
                };
            } else {
                storage[cursor] = .{
                    .circuit_identity = inactive.circuit_identity,
                    .values = inactive.values,
                };
            }
            cursor += 1;
            if (cursor != authority.arithmetic_lanes.len or cursor > storage.len)
                return error.AuthorityMismatch;
            const result = lowering.Evaluations{ .lanes = storage[0..cursor] };
            try result.validateAgainst(authority.arithmetic_reference);
            return result;
        }
    };
}
