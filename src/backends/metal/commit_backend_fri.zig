//! Metal FRI fold-and-commit operations.

const std = @import("std");
const work_profile = @import("stwo_prover_api").work_profile;
const commit_policy = @import("commit_policy.zig");
const fold_inverses = @import("runtime/fold_inverses.zig");
const fold_parity = @import("fri_fold_parity.zig");
const hash_domain = @import("hash_domain.zig");
const shared_runtime = @import("shared_runtime.zig");
const telemetry = @import("telemetry.zig");

pub fn Ops(comptime Backend: type) type {
    return struct {
        const MerkleTree = Backend.MerkleTree;
        const FriLineCascadeResult = Backend.FriLineCascadeResult;
        const allocateLineEvaluation = Backend.allocateLineEvaluation;
        const allocateSecureColumn = Backend.allocateSecureColumn;
        const secureColumnForMerkle = Backend.secureColumnForMerkle;
        const commitMerkle = Backend.commitMerkle;

        pub fn foldCircleIntoLine(
            allocator: std.mem.Allocator,
            dst: []@import("stwo_core").fields.qm31.QM31,
            src_columns: [4][]const @import("stwo_core").fields.m31.M31,
            src_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldCircleWorkspace,
        ) !void {
            return foldCircleIntoLineInternal(
                allocator,
                dst,
                src_columns,
                src_domain,
                alpha,
                workspace,
                null,
            );
        }

        pub fn foldCircleIntoLineWithReceipt(
            allocator: std.mem.Allocator,
            dst: []@import("stwo_core").fields.qm31.QM31,
            src_columns: [4][]const @import("stwo_core").fields.m31.M31,
            src_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldCircleWorkspace,
            ledger: *work_profile.FriFoldExecutionLedger,
        ) !void {
            return foldCircleIntoLineInternal(
                allocator,
                dst,
                src_columns,
                src_domain,
                alpha,
                workspace,
                ledger,
            );
        }

        fn foldCircleIntoLineInternal(
            allocator: std.mem.Allocator,
            dst: []@import("stwo_core").fields.qm31.QM31,
            src_columns: [4][]const @import("stwo_core").fields.m31.M31,
            src_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldCircleWorkspace,
            ledger: ?*work_profile.FriFoldExecutionLedger,
        ) !void {
            const M31 = @import("stwo_core").fields.m31.M31;
            const use_resident_inverse = dst.len >= 1 << 13;
            const check_parity = fold_parity.enabled();
            var inverse_words: ?[]const u32 = null;
            var parity_inverses: ?[]const M31 = null;
            if (!use_resident_inverse or check_parity) {
                try workspace.ensureCapacity(allocator, dst.len);
                const py = workspace.py_values[0..dst.len];
                const inverse_y = workspace.inv_py_values[0..dst.len];
                try fold_inverses.prepare(py, inverse_y, src_domain.half_coset, .y);
                if (!use_resident_inverse) {
                    inverse_words = std.mem.bytesAsSlice(
                        u32,
                        std.mem.sliceAsBytes(inverse_y),
                    );
                }
                if (check_parity) parity_inverses = inverse_y;
            }
            const alpha_coords = alpha.toM31Array();
            const alpha_words = [4]u32{ alpha_coords[0].v, alpha_coords[1].v, alpha_coords[2].v, alpha_coords[3].v };
            const source_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(src_columns[0].ptr[0 .. src_columns[0].len * 4]));
            const destination_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(dst));
            const fold_coset = src_domain.half_coset;
            var lease = try shared_runtime.acquire();
            defer lease.deinit();
            var inverse_generated = false;
            const gpu_ms = if (ledger != null) blk: {
                const result = try lease.runtime.foldFriCircleWithReceipt(
                    source_words.ptr,
                    @intCast(src_columns[0].len),
                    inverse_words,
                    @intCast(fold_coset.initial_index.v),
                    @intCast(fold_coset.step_size.v),
                    alpha_words,
                    destination_words.ptr,
                );
                inverse_generated = result.inverse_generated;
                break :blk result.gpu_ms;
            } else try lease.runtime.foldFriCircle(
                source_words.ptr,
                @intCast(src_columns[0].len),
                inverse_words,
                @intCast(fold_coset.initial_index.v),
                @intCast(fold_coset.step_size.v),
                alpha_words,
                destination_words.ptr,
            );
            telemetry.record(.metal_fri_circle_fold_dispatch);
            std.log.debug("Metal FRI circle fold: {d:.3}ms", .{gpu_ms});
            if (check_parity) {
                const receipt = try fold_parity.validateCircle(
                    src_columns,
                    src_domain,
                    parity_inverses.?,
                    alpha,
                    dst,
                );
                receipt.print();
            }
            if (ledger) |active| active.observe(.{
                .kind = .circle_to_line,
                .initial_count = src_columns[0].len,
                .fold_count = 1,
                .domain_log_size = fold_coset.logSize(),
                .domain_initial_index = @intCast(fold_coset.initial_index.v),
                .domain_step_size = @intCast(fold_coset.step_size.v),
                .inverse_path = if (inverse_words != null)
                    .host_batch
                else if (inverse_generated)
                    .metal_direct
                else
                    .retained,
                .alpha_squares = 0,
                .domain_doubles = 0,
                .optimized_zero_accumulator = true,
            });
        }

        pub fn foldLineEvaluationN(
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            n_folds: u32,
        ) !@import("stwo_prover_engine").line.LineEvaluation {
            return foldLineEvaluationNInternal(
                allocator,
                evaluation,
                alpha,
                workspace,
                n_folds,
                null,
            );
        }

        pub fn foldLineEvaluationNWithReceipt(
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            n_folds: u32,
            ledger: *work_profile.FriFoldExecutionLedger,
        ) !@import("stwo_prover_engine").line.LineEvaluation {
            return foldLineEvaluationNInternal(
                allocator,
                evaluation,
                alpha,
                workspace,
                n_folds,
                ledger,
            );
        }

        fn foldLineEvaluationNInternal(
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            n_folds: u32,
            ledger: ?*work_profile.FriFoldExecutionLedger,
        ) !@import("stwo_prover_engine").line.LineEvaluation {
            const initial_count = evaluation.len();
            const initial_domain = evaluation.domain();
            var current = evaluation;
            var owns_current = false;
            var current_alpha = alpha;
            errdefer if (owns_current) current.deinit(allocator);
            var step: u32 = 0;
            while (step < n_folds) : (step += 1) {
                const destination_domain = current.domain().double();
                var next = try allocateLineEvaluation(destination_domain);
                errdefer next.deinit(allocator);
                const destination_len = next.len();
                try workspace.ensureCapacity(allocator, destination_len);
                const x = workspace.x_values[0..destination_len];
                const inverse_x = workspace.inv_x_values[0..destination_len];
                try fold_inverses.prepare(x, inverse_x, current.domain().coset(), .x);
                const source_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(current.values));
                const destination_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(@constCast(next.values)));
                const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_x));
                const alpha_coords = current_alpha.toM31Array();
                const alpha_words = [4]u32{ alpha_coords[0].v, alpha_coords[1].v, alpha_coords[2].v, alpha_coords[3].v };
                var lease = try shared_runtime.acquire();
                defer lease.deinit();
                const gpu_ms = try lease.runtime.foldFriLine(
                    source_words.ptr,
                    @intCast(current.len()),
                    inverse_words,
                    alpha_words,
                    destination_words.ptr,
                );
                telemetry.record(.metal_fri_line_fold_dispatch);
                std.log.debug("Metal FRI line fold: {d:.3}ms", .{gpu_ms});
                if (fold_parity.enabled()) {
                    const receipt = try fold_parity.validateLine(
                        current.values,
                        current.domain(),
                        inverse_x,
                        current_alpha,
                        next.values,
                    );
                    receipt.print();
                }
                if (owns_current) current.deinit(allocator);
                current = next;
                owns_current = true;
                current_alpha = current_alpha.square();
            }
            if (ledger) |active| {
                const coset = initial_domain.coset();
                active.observe(.{
                    .kind = .line,
                    .initial_count = initial_count,
                    .fold_count = n_folds,
                    .domain_log_size = initial_domain.logSize(),
                    .domain_initial_index = @intCast(coset.initial_index.v),
                    .domain_step_size = @intCast(coset.step_size.v),
                    .inverse_path = .host_batch,
                    .alpha_squares = n_folds,
                    .domain_doubles = n_folds,
                });
            }
            return current;
        }

        pub fn foldLineAndCommitNext(
            comptime H: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            n_folds: u32,
        ) !@import("stwo_backend_contracts").fri_ops.FoldLineAndCommitResult(MerkleTree(H)) {
            return foldLineAndCommitNextInternal(
                H,
                allocator,
                evaluation,
                alpha,
                workspace,
                n_folds,
                null,
            );
        }

        pub fn foldLineAndCommitNextWithReceipt(
            comptime H: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            n_folds: u32,
            ledger: *work_profile.FriFoldExecutionLedger,
        ) !@import("stwo_backend_contracts").fri_ops.FoldLineAndCommitResult(MerkleTree(H)) {
            return foldLineAndCommitNextInternal(
                H,
                allocator,
                evaluation,
                alpha,
                workspace,
                n_folds,
                ledger,
            );
        }

        fn foldLineAndCommitNextInternal(
            comptime H: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            alpha: @import("stwo_core").fields.qm31.QM31,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            n_folds: u32,
            ledger: ?*work_profile.FriFoldExecutionLedger,
        ) !@import("stwo_backend_contracts").fri_ops.FoldLineAndCommitResult(MerkleTree(H)) {
            const M31 = @import("stwo_core").fields.m31.M31;
            const secure_column = @import("stwo_prover_engine").secure_column;
            const domain = comptime hash_domain.parameters(H);
            if (n_folds == 0 or n_folds >= @bitSizeOf(usize) or
                evaluation.len() >> @intCast(n_folds) == 0)
            {
                return error.InvalidColumns;
            }

            const final_count = evaluation.len() >> @intCast(n_folds);
            const source_storage = evaluation.resident_storage;
            if (source_storage == null or domain == null or
                !commit_policy.friFoldCommitUsesResidentMerkle(final_count, n_folds))
            {
                const folded = try foldLineEvaluationNInternal(
                    allocator,
                    evaluation,
                    alpha,
                    workspace,
                    n_folds,
                    ledger,
                );
                errdefer {
                    var owned = folded;
                    owned.deinit(allocator);
                }
                var coordinates = if (comptime @hasDecl(@This(), "secureColumnForMerkle"))
                    try secureColumnForMerkle(allocator, folded)
                else
                    try secure_column.SecureColumnByCoords.fromSecureSlice(allocator, folded.values);
                errdefer coordinates.deinit(allocator);
                const columns = [_][]const M31{
                    coordinates.columns[0],
                    coordinates.columns[1],
                    coordinates.columns[2],
                    coordinates.columns[3],
                };
                const tree = try commitMerkle(H, allocator, columns[0..]);
                return .{ .evaluation = folded, .column = coordinates, .tree = tree };
            }

            var final_domain = evaluation.domain();
            var inverse_count: usize = 0;
            var stage_count = evaluation.len();
            for (0..n_folds) |_| {
                stage_count >>= 1;
                inverse_count = try std.math.add(usize, inverse_count, stage_count);
                final_domain = final_domain.double();
            }
            const inverse_values = try allocator.alloc(M31, inverse_count);
            defer allocator.free(inverse_values);
            const alphas = try allocator.alloc([4]u32, n_folds);
            defer allocator.free(alphas);

            var inverse_cursor: usize = 0;
            var current_count = evaluation.len();
            var current_domain = evaluation.domain();
            var current_alpha = alpha;
            for (0..n_folds) |step| {
                const destination_count = current_count >> 1;
                try workspace.ensureCapacity(allocator, destination_count);
                const x = workspace.x_values[0..destination_count];
                const inverse_x = workspace.inv_x_values[0..destination_count];
                try fold_inverses.prepare(x, inverse_x, current_domain.coset(), .x);
                @memcpy(inverse_values[inverse_cursor .. inverse_cursor + destination_count], inverse_x);
                inverse_cursor += destination_count;
                const alpha_coordinates = current_alpha.toM31Array();
                alphas[step] = .{
                    alpha_coordinates[0].v,
                    alpha_coordinates[1].v,
                    alpha_coordinates[2].v,
                    alpha_coordinates[3].v,
                };
                current_count = destination_count;
                current_domain = current_domain.double();
                current_alpha = current_alpha.square();
            }

            var folded = try allocateLineEvaluation(final_domain);
            errdefer folded.deinit(allocator);
            var coordinates = try allocateSecureColumn(final_count);
            errdefer coordinates.deinit(allocator);
            const destination_storage = folded.resident_storage orelse return error.InvalidColumns;
            const coordinate_storage = coordinates.resident_storage orelse return error.InvalidColumns;
            const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_values));
            var lease = try shared_runtime.acquire();
            defer lease.deinit();
            const result = try lease.runtime.foldFriLineAndCommitForHash(
                source_storage.?.handle,
                @intCast(evaluation.len()),
                inverse_words,
                alphas,
                destination_storage.handle,
                coordinate_storage.handle,
                domain.?.leaf_seed,
                domain.?.node_seed,
                domain.?.domain_prefix_bytes,
                @intFromEnum(domain.?.family),
            );
            const tree = try MerkleTree(H).fromSharedRuntime(result.tree);
            telemetry.record(.metal_fri_fold_commit_epoch);
            telemetry.record(.resident_merkle_commit);
            std.log.debug(
                "Metal FRI fold + Merkle epoch: {d:.3}ms, {} dispatches, {} command buffer, {} wait",
                .{
                    result.stats.gpu_milliseconds,
                    result.stats.dispatches,
                    result.stats.command_buffers,
                    result.stats.wait_count,
                },
            );
            if (ledger) |active| {
                const initial_domain = evaluation.domain();
                const coset = initial_domain.coset();
                active.observe(.{
                    .kind = .line,
                    .initial_count = evaluation.len(),
                    .fold_count = n_folds,
                    .domain_log_size = initial_domain.logSize(),
                    .domain_initial_index = @intCast(coset.initial_index.v),
                    .domain_step_size = @intCast(coset.step_size.v),
                    .inverse_path = .host_batch,
                    .alpha_squares = n_folds,
                    .domain_doubles = 2 * n_folds,
                });
            }
            return .{ .evaluation = folded, .column = coordinates, .tree = tree };
        }

        pub fn commitFriLineCascade(
            comptime H: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            channel: anytype,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            last_layer_size: usize,
            fold_step: u32,
            circle_source: ?*anyopaque,
            circle_alpha: ?[4]u32,
        ) !?FriLineCascadeResult(H) {
            return commitFriLineCascadeInternal(
                H,
                allocator,
                evaluation,
                channel,
                workspace,
                last_layer_size,
                fold_step,
                circle_source,
                circle_alpha,
                null,
            );
        }

        pub fn commitFriLineCascadeWithReceipt(
            comptime H: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            channel: anytype,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            last_layer_size: usize,
            fold_step: u32,
            circle_source: ?*anyopaque,
            circle_alpha: ?[4]u32,
            ledger: *work_profile.FriFoldExecutionLedger,
        ) !?FriLineCascadeResult(H) {
            return commitFriLineCascadeInternal(
                H,
                allocator,
                evaluation,
                channel,
                workspace,
                last_layer_size,
                fold_step,
                circle_source,
                circle_alpha,
                ledger,
            );
        }

        fn commitFriLineCascadeInternal(
            comptime H: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            channel: anytype,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            last_layer_size: usize,
            fold_step: u32,
            circle_source: ?*anyopaque,
            circle_alpha: ?[4]u32,
            ledger: ?*work_profile.FriFoldExecutionLedger,
        ) !?FriLineCascadeResult(H) {
            const channel_blake2s = @import("stwo_core").channel.blake2s;
            const M31 = @import("stwo_core").fields.m31.M31;
            const maybe_domain = comptime hash_domain.blake2sParameters(H);
            if (comptime maybe_domain == null) return null;
            const domain = maybe_domain.?;
            if (comptime @TypeOf(channel.*) != channel_blake2s.Blake2sChannel) return null;
            if (fold_step != 1 or last_layer_size == 0 or
                evaluation.len() <= last_layer_size or evaluation.resident_storage == null or
                !std.math.isPowerOfTwo(evaluation.len()) or !std.math.isPowerOfTwo(last_layer_size) or
                evaluation.len() % last_layer_size != 0)
            {
                return null;
            }
            const layer_count: usize = std.math.log2_int(usize, evaluation.len() / last_layer_size);
            if (layer_count == 0 or layer_count >= 31) return null;
            const inverse_count = evaluation.len() - last_layer_size;
            const use_resident_inverse = evaluation.len() >= 1 << 13;
            var inverse_values: ?[]M31 = null;
            if (!use_resident_inverse) inverse_values = try allocator.alloc(M31, inverse_count);
            defer if (inverse_values) |values| allocator.free(values);
            var current_domain = evaluation.domain();
            var current_count = evaluation.len();
            var inverse_cursor: usize = 0;
            for (0..layer_count) |_| {
                const destination_count = current_count >> 1;
                if (inverse_values) |values| {
                    try workspace.ensureCapacity(allocator, destination_count);
                    const x = workspace.x_values[0..destination_count];
                    const inverse_x = workspace.inv_x_values[0..destination_count];
                    try fold_inverses.prepare(x, inverse_x, current_domain.coset(), .x);
                    @memcpy(values[inverse_cursor .. inverse_cursor + destination_count], inverse_x);
                }
                inverse_cursor += destination_count;
                current_count = destination_count;
                current_domain = current_domain.double();
            }

            const SecureColumn = @import("stwo_prover_engine").secure_column.SecureColumnByCoords;
            const columns = try allocator.alloc(SecureColumn, layer_count);
            var initialized_columns: usize = 0;
            errdefer {
                for (columns[0..initialized_columns]) |*column| column.deinit(allocator);
                allocator.free(columns);
            }
            const coordinate_handles = try allocator.alloc(*anyopaque, layer_count);
            defer allocator.free(coordinate_handles);
            current_count = evaluation.len();
            for (columns, coordinate_handles) |*column, *handle| {
                column.* = try allocateSecureColumn(current_count);
                initialized_columns += 1;
                handle.* = column.resident_storage.?.handle;
                current_count >>= 1;
            }

            var terminal = try allocateLineEvaluation(current_domain);
            errdefer terminal.deinit(allocator);
            const terminal_storage = terminal.resident_storage orelse return error.InvalidColumns;
            const source_storage = evaluation.resident_storage.?;

            var channel_state = [_]u32{0} ** 10;
            for (0..8) |word| {
                channel_state[word] = std.mem.readInt(
                    u32,
                    channel.digest[word * 4 ..][0..4],
                    .little,
                );
            }
            channel_state[8] = channel.n_draws;
            const inverse_words: ?[]const u32 = if (inverse_values) |values|
                std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(values))
            else
                null;
            const initial_coset = evaluation.domain().coset();

            var lease = try shared_runtime.acquire();
            defer lease.deinit();
            var runtime_result = if (ledger != null)
                try lease.runtime.foldFriCircleLineCascadeWithReceipt(
                    allocator,
                    source_storage.handle,
                    @intCast(evaluation.len()),
                    circle_source,
                    circle_alpha,
                    inverse_words,
                    @intCast(initial_coset.initial_index.v),
                    @intCast(initial_coset.step_size.v),
                    coordinate_handles,
                    terminal_storage.handle,
                    domain.leaf_seed,
                    domain.node_seed,
                    domain.domain_prefix_bytes,
                    &channel_state,
                )
            else
                try lease.runtime.foldFriCircleLineCascade(
                    allocator,
                    source_storage.handle,
                    @intCast(evaluation.len()),
                    circle_source,
                    circle_alpha,
                    inverse_words,
                    @intCast(initial_coset.initial_index.v),
                    @intCast(initial_coset.step_size.v),
                    coordinate_handles,
                    terminal_storage.handle,
                    domain.leaf_seed,
                    domain.node_seed,
                    domain.domain_prefix_bytes,
                    &channel_state,
                );
            defer allocator.free(runtime_result.trees);

            var consumed_runtime_trees: usize = 0;
            errdefer {
                for (runtime_result.trees[consumed_runtime_trees..]) |*tree| tree.deinit();
            }
            const trees = try allocator.alloc(MerkleTree(H), layer_count);
            var initialized_trees: usize = 0;
            errdefer {
                for (trees[0..initialized_trees]) |*tree| tree.deinit(allocator);
                allocator.free(trees);
            }
            for (runtime_result.trees, trees) |runtime_tree, *tree| {
                consumed_runtime_trees += 1;
                tree.* = try MerkleTree(H).fromSharedRuntime(runtime_tree);
                initialized_trees += 1;
            }

            for (0..8) |word| {
                std.mem.writeInt(u32, channel.digest[word * 4 ..][0..4], channel_state[word], .little);
            }
            channel.n_draws = channel_state[8];
            telemetry.record(.metal_fri_fold_commit_epoch);
            for (0..layer_count) |_| telemetry.record(.resident_merkle_commit);
            std.log.debug(
                "Metal FRI line cascade: {d:.3}ms, {} layers, {} dispatches, {} command buffer, {} wait",
                .{
                    runtime_result.stats.gpu_milliseconds,
                    layer_count,
                    runtime_result.stats.dispatches,
                    runtime_result.stats.command_buffers,
                    runtime_result.stats.wait_count,
                },
            );
            if (ledger) |active| {
                const receipt_domain = evaluation.domain();
                const receipt_coset = receipt_domain.coset();
                if (circle_source != null) active.observe(.{
                    .kind = .circle_to_line,
                    .initial_count = 2 * evaluation.len(),
                    .fold_count = 1,
                    .domain_log_size = receipt_domain.logSize(),
                    .domain_initial_index = @intCast(receipt_coset.initial_index.v),
                    .domain_step_size = @intCast(receipt_coset.step_size.v),
                    .inverse_path = if (runtime_result.inverse_generation_mask & 1 != 0)
                        .metal_direct
                    else
                        .retained,
                    .alpha_squares = 0,
                    .domain_doubles = 0,
                    .optimized_zero_accumulator = true,
                });
                active.observe(.{
                    .kind = .line,
                    .initial_count = evaluation.len(),
                    .fold_count = @intCast(layer_count),
                    .domain_log_size = receipt_domain.logSize(),
                    .domain_initial_index = @intCast(receipt_coset.initial_index.v),
                    .domain_step_size = @intCast(receipt_coset.step_size.v),
                    .inverse_path = if (inverse_words != null)
                        .host_batch
                    else if (runtime_result.inverse_generation_mask & 2 != 0)
                        .metal_direct
                    else
                        .retained,
                    .alpha_squares = 0,
                    // One pass prepares/caches domains; the owner performs a
                    // second pass while materializing typed layer domains.
                    .domain_doubles = @intCast(2 * layer_count),
                });
            }
            return .{
                .columns = columns,
                .trees = trees,
                .last_layer_evaluation = terminal,
            };
        }

        pub fn commitFriLayers(
            comptime H: type,
            comptime InnerLayerProver: type,
            comptime InnerCommitResult: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            channel: anytype,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            config: @import("stwo_core").fri.FriConfig,
        ) !?InnerCommitResult {
            return commitFriLayersInternal(
                H,
                InnerLayerProver,
                InnerCommitResult,
                allocator,
                evaluation,
                channel,
                workspace,
                config,
                null,
            );
        }

        pub fn commitFriLayersWithReceipt(
            comptime H: type,
            comptime InnerLayerProver: type,
            comptime InnerCommitResult: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            channel: anytype,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            config: @import("stwo_core").fri.FriConfig,
            ledger: *work_profile.FriFoldExecutionLedger,
        ) !?InnerCommitResult {
            return commitFriLayersInternal(
                H,
                InnerLayerProver,
                InnerCommitResult,
                allocator,
                evaluation,
                channel,
                workspace,
                config,
                ledger,
            );
        }

        fn commitFriLayersInternal(
            comptime H: type,
            comptime InnerLayerProver: type,
            comptime InnerCommitResult: type,
            allocator: std.mem.Allocator,
            evaluation: @import("stwo_prover_engine").line.LineEvaluation,
            channel: anytype,
            workspace: *@import("stwo_core").fri.FoldLineWorkspace,
            config: @import("stwo_core").fri.FriConfig,
            ledger: ?*work_profile.FriFoldExecutionLedger,
        ) !?InnerCommitResult {
            var cascade = (if (ledger) |active|
                try commitFriLineCascadeWithReceipt(
                    H,
                    allocator,
                    evaluation,
                    channel,
                    workspace,
                    config.lastLayerDomainSize(),
                    config.fold_step,
                    null,
                    null,
                    active,
                )
            else
                try commitFriLineCascade(
                    H,
                    allocator,
                    evaluation,
                    channel,
                    workspace,
                    config.lastLayerDomainSize(),
                    config.fold_step,
                    null,
                    null,
                )) orelse return null;
            std.debug.assert(cascade.columns.len == cascade.trees.len);
            const ready_layers = allocator.alloc(InnerLayerProver, cascade.columns.len) catch |err| {
                cascade.deinit(allocator);
                return err;
            };
            var layer_domain = evaluation.domain();
            for (ready_layers, cascade.columns, cascade.trees) |*layer, column, tree| {
                layer.* = .{
                    .domain = layer_domain,
                    .column = column,
                    .merkle_tree = tree,
                    .fold_step = 1,
                };
                layer_domain = layer_domain.double();
            }
            const terminal_evaluation = cascade.last_layer_evaluation;
            allocator.free(cascade.columns);
            allocator.free(cascade.trees);
            var consumed_evaluation = evaluation;
            consumed_evaluation.deinit(allocator);
            return .{
                .inner_layers = ready_layers,
                .last_layer_evaluation = terminal_evaluation,
            };
        }
    };
}
