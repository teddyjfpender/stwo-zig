const std = @import("std");
const commit_policy = @import("../commit_policy.zig");
const shared_runtime = @import("../shared_runtime.zig");
const telemetry = @import("../telemetry.zig");

const fri_inverse_cache_min_values: usize = 1 << 13;

pub fn Ops(comptime B: type) type {
    return struct {
        pub fn commitLazyFriTransaction(
            comptime H: type,
            comptime FirstLayerProver: type,
            comptime InnerLayerProver: type,
            comptime InnerCommitResult: type,
            comptime LazyFriCommitResult: type,
            allocator: std.mem.Allocator,
            channel: anytype,
            config: @import("stwo_core").fri.FriConfig,
            circle_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
            provider: anytype,
        ) !?LazyFriCommitResult {
            const channel_blake2s = @import("stwo_core").channel.blake2s;
            const line = @import("stwo_core").poly.line;
            const circle = @import("stwo_core").circle;
            if (comptime @TypeOf(channel.*) != channel_blake2s.Blake2sChannel) return null;
            if (config.fold_step != 1 or
                provider.domain_size != circle_domain.size() or
                !commit_policy.quotientUsesResidentMerkle(provider.lifting_log_size) or
                circle_domain.logSize() == 0)
            {
                return null;
            }
            const line_domain = try line.LineDomain.init(
                circle.Coset.halfOdds(circle_domain.logSize() - 1),
            );
            const last_layer_size = config.lastLayerDomainSize();
            if (line_domain.size() < fri_inverse_cache_min_values or
                line_domain.size() <= last_layer_size or
                !std.math.isPowerOfTwo(line_domain.size()) or
                !std.math.isPowerOfTwo(last_layer_size) or
                line_domain.size() % last_layer_size != 0)
            {
                return null;
            }
            const layer_count = std.math.log2_int(
                usize,
                line_domain.size() / last_layer_size,
            );
            if (layer_count == 0 or layer_count >= 31) return null;

            var first_column = try B.allocateSecureColumn(provider.domain_size);
            errdefer first_column.deinit(allocator);
            var line_evaluation = try B.allocateLineEvaluation(line_domain);
            defer line_evaluation.deinit(allocator);

            const SecureColumn = @import("stwo_prover_engine").secure_column.SecureColumnByCoords;
            const columns = try allocator.alloc(SecureColumn, layer_count);
            defer allocator.free(columns);
            var initialized_columns: usize = 0;
            var moved_columns: usize = 0;
            errdefer {
                for (columns[moved_columns..initialized_columns]) |*column| {
                    column.deinit(allocator);
                }
            }
            const coordinate_handles = try allocator.alloc(*anyopaque, layer_count);
            defer allocator.free(coordinate_handles);
            var current_count = line_domain.size();
            for (columns, coordinate_handles) |*column, *handle| {
                column.* = try B.allocateSecureColumn(current_count);
                initialized_columns += 1;
                handle.* = column.resident_storage.?.handle;
                current_count >>= 1;
            }

            var terminal_domain = line_domain;
            for (0..layer_count) |_| terminal_domain = terminal_domain.double();
            var terminal = try B.allocateLineEvaluation(terminal_domain);
            errdefer terminal.deinit(allocator);

            var channel_state = [_]u32{0} ** 10;
            for (0..8) |word| {
                channel_state[word] = std.mem.readInt(
                    u32,
                    channel.digest[word * 4 ..][0..4],
                    .little,
                );
            }
            channel_state[8] = channel.n_draws;

            _ = first_column.resident_storage orelse return error.InvalidColumns;
            const line_storage = line_evaluation.resident_storage orelse return error.InvalidColumns;
            const terminal_storage = terminal.resident_storage orelse return error.InvalidColumns;
            const initial_coset = line_domain.coset();
            var lease = try shared_runtime.acquire();
            defer lease.deinit();
            var runtime_result = try lease.runtime.computeQuotientsAndCommitFri(
                allocator,
                provider,
                &first_column,
                line_storage.handle,
                coordinate_handles,
                terminal_storage.handle,
                @intCast(initial_coset.initial_index.v),
                @intCast(initial_coset.step_size.v),
                &channel_state,
                H.leafSeed(),
                H.nodeSeed(),
                H.domainPrefixBytes(),
            );
            defer allocator.free(runtime_result.fri.trees);

            var initial_runtime_tree = runtime_result.tree;
            var initial_tree_consumed = false;
            errdefer if (!initial_tree_consumed) initial_runtime_tree.deinit();
            var first_tree = try B.MerkleTree(H).fromSharedRuntime(initial_runtime_tree);
            initial_tree_consumed = true;
            errdefer first_tree.deinit(allocator);

            var consumed_runtime_trees: usize = 0;
            errdefer {
                for (runtime_result.fri.trees[consumed_runtime_trees..]) |*tree| tree.deinit();
            }
            const ready_layers = try allocator.alloc(InnerLayerProver, layer_count);
            var initialized_layers: usize = 0;
            errdefer {
                for (ready_layers[0..initialized_layers]) |*layer| {
                    layer.column.deinit(allocator);
                    layer.merkle_tree.deinit(allocator);
                }
                allocator.free(ready_layers);
            }
            var layer_domain = line_domain;
            for (ready_layers, runtime_result.fri.trees, columns) |*layer, runtime_tree, column| {
                const tree = try B.MerkleTree(H).fromSharedRuntime(runtime_tree);
                consumed_runtime_trees += 1;
                layer.* = .{
                    .domain = layer_domain,
                    .column = column,
                    .merkle_tree = tree,
                    .fold_step = 1,
                };
                initialized_layers += 1;
                moved_columns += 1;
                layer_domain = layer_domain.double();
            }

            for (0..8) |word| {
                std.mem.writeInt(
                    u32,
                    channel.digest[word * 4 ..][0..4],
                    channel_state[word],
                    .little,
                );
            }
            channel.n_draws = channel_state[8];
            telemetry.record(.metal_quotient_dispatch);
            telemetry.record(.metal_fri_circle_fold_dispatch);
            telemetry.record(.metal_fri_fold_commit_epoch);
            telemetry.record(.resident_merkle_commit);
            for (0..layer_count) |_| telemetry.record(.resident_merkle_commit);
            std.log.debug(
                "Metal quotient + complete FRI transaction: quotient={d:.3}ms fri={d:.3}ms, {} FRI layers, 2 command buffers, 1 wait",
                .{
                    runtime_result.gpu_ms,
                    runtime_result.fri.stats.gpu_milliseconds,
                    layer_count,
                },
            );

            return .{
                .first_layer = FirstLayerProver{
                    .domain = circle_domain,
                    .column = first_column,
                    .merkle_tree = first_tree,
                },
                .inner_commit = InnerCommitResult{
                    .inner_layers = ready_layers,
                    .last_layer_evaluation = terminal,
                },
            };
        }

        pub fn commitFriCircleLayers(
            comptime H: type,
            comptime InnerLayerProver: type,
            comptime InnerCommitResult: type,
            allocator: std.mem.Allocator,
            circle_column: @import("stwo_prover_engine").secure_column.SecureColumnByCoords,
            circle_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
            line_domain: @import("stwo_core").poly.line.LineDomain,
            channel: anytype,
            config: @import("stwo_core").fri.FriConfig,
        ) !?InnerCommitResult {
            const channel_blake2s = @import("stwo_core").channel.blake2s;
            if (comptime @TypeOf(channel.*) != channel_blake2s.Blake2sChannel) return null;
            if (config.fold_step != 1 or
                circle_column.resident_storage == null or
                circle_column.len() != circle_domain.size() or
                circle_column.len() != line_domain.size() * 2 or
                line_domain.size() < fri_inverse_cache_min_values or
                line_domain.size() <= config.lastLayerDomainSize())
            {
                return null;
            }

            var evaluation = try B.allocateLineEvaluation(line_domain);
            defer evaluation.deinit(allocator);
            var workspace = try @import("stwo_core").fri.FoldLineWorkspace.init(allocator, 0);
            defer workspace.deinit(allocator);

            const folding_alpha = channel.drawSecureFelt();
            const alpha_coordinates = folding_alpha.toM31Array();
            const alpha_words = [4]u32{
                alpha_coordinates[0].v,
                alpha_coordinates[1].v,
                alpha_coordinates[2].v,
                alpha_coordinates[3].v,
            };
            var cascade = (try B.commitFriLineCascade(
                H,
                allocator,
                evaluation,
                channel,
                &workspace,
                config.lastLayerDomainSize(),
                config.fold_step,
                circle_column.resident_storage.?.handle,
                alpha_words,
            )) orelse return error.InvalidColumns;
            telemetry.record(.metal_fri_circle_fold_dispatch);

            std.debug.assert(cascade.columns.len == cascade.trees.len);
            const ready_layers = allocator.alloc(InnerLayerProver, cascade.columns.len) catch |err| {
                cascade.deinit(allocator);
                return err;
            };
            var layer_domain = line_domain;
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
            return .{
                .inner_layers = ready_layers,
                .last_layer_evaluation = terminal_evaluation,
            };
        }
    };
}
