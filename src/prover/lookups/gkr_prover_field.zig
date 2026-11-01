const std = @import("std");
const fraction = @import("stwo_core").fraction;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const gkr_circuit_module = @import("gkr_circuit.zig");
const gkr_verifier_module = @import("gkr_verifier.zig");
const mle_mod = @import("mle.zig");
const sumcheck_module = @import("sumcheck.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

/// One algorithm authority for the selected secure extension; Q entrypoints below remain compatible.
pub fn ForField(comptime Secure: type) type {
    return struct {
        const sumcheck_field = sumcheck_module.ForField(Secure);
        const gkr_circuit_field = gkr_circuit_module.ForField(Secure);
        const gkr_verifier_field = gkr_verifier_module.ForField(Secure);
        const MleBase = mle_mod.MleFor(Secure, M31);
        const MleSecure = mle_mod.MleFor(Secure, Secure);
        pub const GkrProverError = gkr_circuit_module.GkrProverError;
        pub const EqEvals = gkr_circuit_field.EqEvals;
        pub const Layer = gkr_circuit_field.Layer;
        pub const GkrMultivariatePolyOracle = gkr_circuit_field.GkrMultivariatePolyOracle;
        pub const correctSumAsPolyInFirstVariable = gkr_circuit_field.correctSumAsPolyInFirstVariable;

        pub const ProveBatchResult = struct {
            proof: gkr_verifier_field.GkrBatchProof,
            artifact: gkr_verifier_field.GkrArtifact,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                self.proof.deinit(allocator);
                self.artifact.deinit(allocator);
                self.* = undefined;
            }
        };

        /// Batch-proves lookup circuits with GKR.
        pub fn proveBatch(
            allocator: std.mem.Allocator,
            channel: anytype,
            input_layer_by_instance: []const Layer,
        ) (std.mem.Allocator.Error || GkrProverError)!ProveBatchResult {
            if (input_layer_by_instance.len == 0) return GkrProverError.EmptyBatch;

            const n_instances = input_layer_by_instance.len;

            const n_layers_by_instance = try allocator.alloc(usize, n_instances);
            defer allocator.free(n_layers_by_instance);

            var n_layers: usize = 0;
            for (input_layer_by_instance, 0..) |layer, i| {
                n_layers_by_instance[i] = layer.nVariables();
                n_layers = @max(n_layers, n_layers_by_instance[i]);
            }

            const layers_by_instance = try allocator.alloc([]Layer, n_instances);
            var layers_initialized: usize = 0;
            defer {
                var i: usize = 0;
                while (i < layers_initialized) : (i += 1) {
                    for (layers_by_instance[i]) |*layer| layer.deinit(allocator);
                    allocator.free(layers_by_instance[i]);
                }
                allocator.free(layers_by_instance);
            }

            for (input_layer_by_instance, 0..) |input_layer, i| {
                layers_by_instance[i] = try gkr_circuit_field.buildLayers(allocator, input_layer);
                layers_initialized += 1;
            }

            const next_layer_idx = try allocator.alloc(usize, n_instances);
            defer allocator.free(next_layer_idx);
            for (layers_by_instance, 0..) |layers, i| next_layer_idx[i] = layers.len;

            var output_claims_by_instance = try allocator.alloc(?[]Secure, n_instances);
            defer {
                for (output_claims_by_instance) |maybe_claims| {
                    if (maybe_claims) |claims| allocator.free(claims);
                }
                allocator.free(output_claims_by_instance);
            }
            @memset(output_claims_by_instance, null);

            var claims_to_verify_by_instance = try allocator.alloc(?[]Secure, n_instances);
            defer {
                for (claims_to_verify_by_instance) |maybe_claims| {
                    if (maybe_claims) |claims| allocator.free(claims);
                }
                allocator.free(claims_to_verify_by_instance);
            }
            @memset(claims_to_verify_by_instance, null);

            const mask_builders = try allocator.alloc(std.ArrayList(gkr_verifier_field.GkrMask), n_instances);
            defer {
                for (mask_builders) |*builder| {
                    for (builder.items) |*mask| mask.deinit(allocator);
                    builder.deinit(allocator);
                }
                allocator.free(mask_builders);
            }
            for (mask_builders) |*builder| builder.* = .empty;

            var sumcheck_proofs = std.ArrayList(sumcheck_field.SumcheckProof).empty;
            defer {
                for (sumcheck_proofs.items) |*proof| proof.deinit(allocator);
                sumcheck_proofs.deinit(allocator);
            }

            var ood_point = try allocator.alloc(Secure, 0);
            defer allocator.free(ood_point);

            var layer_idx: usize = 0;
            while (layer_idx < n_layers) : (layer_idx += 1) {
                const n_remaining_layers = n_layers - layer_idx;

                var instance: usize = 0;
                while (instance < n_instances) : (instance += 1) {
                    if (n_layers_by_instance[instance] == n_remaining_layers) {
                        const output_layer = try popNextLayer(
                            layers_by_instance[instance],
                            &next_layer_idx[instance],
                        );
                        const output_values = try output_layer.outputLayerValues(allocator);
                        errdefer allocator.free(output_values);
                        try replaceOwnedSlice(
                            allocator,
                            &claims_to_verify_by_instance[instance],
                            try allocator.dupe(Secure, output_values),
                        );
                        try replaceOwnedSlice(
                            allocator,
                            &output_claims_by_instance[instance],
                            output_values,
                        );
                    }
                }

                for (claims_to_verify_by_instance) |maybe_claims| {
                    if (maybe_claims) |claims| channel.mixFelts(claims);
                }

                var eq_evals = try EqEvals.generate(allocator, ood_point);
                defer eq_evals.deinit(allocator);

                const sumcheck_alpha = channel.drawSecureFelt();
                const instance_lambda = channel.drawSecureFelt();

                var sumcheck_oracles = std.ArrayList(GkrMultivariatePolyOracle).empty;
                defer {
                    for (sumcheck_oracles.items) |*oracle| oracle.deinit(allocator);
                    sumcheck_oracles.deinit(allocator);
                }

                var sumcheck_claims = std.ArrayList(Secure).empty;
                defer sumcheck_claims.deinit(allocator);

                var sumcheck_instances = std.ArrayList(usize).empty;
                defer sumcheck_instances.deinit(allocator);

                instance = 0;
                while (instance < n_instances) : (instance += 1) {
                    if (claims_to_verify_by_instance[instance]) |claims| {
                        const layer = try popNextLayer(
                            layers_by_instance[instance],
                            &next_layer_idx[instance],
                        );
                        var oracle = try layer.intoMultivariatePoly(allocator, instance_lambda, &eq_evals);
                        sumcheck_oracles.append(allocator, oracle) catch |err| {
                            oracle.deinit(allocator);
                            return err;
                        };
                        try sumcheck_claims.append(
                            allocator,
                            utils.hornerEval(Secure, claims, instance_lambda),
                        );
                        try sumcheck_instances.append(allocator, instance);
                    }
                }

                var sumcheck_result = sumcheck_field.proveBatch(
                    GkrMultivariatePolyOracle,
                    allocator,
                    sumcheck_claims.items,
                    sumcheck_oracles.items,
                    sumcheck_alpha,
                    channel,
                ) catch |err| switch (err) {
                    std.mem.Allocator.Error.OutOfMemory => return error.OutOfMemory,
                    else => return GkrProverError.InvalidSumcheck,
                };

                defer sumcheck_result.deinit(allocator);
                try sumcheck_proofs.append(allocator, sumcheck_result.proof);
                sumcheck_result.proof.round_polys = &.{};

                const masks = try allocator.alloc(gkr_verifier_field.GkrMask, sumcheck_result.constant_polys.len);
                var masks_initialized: usize = 0;
                var masks_transferred: usize = 0;
                defer {
                    for (masks[masks_transferred..masks_initialized]) |*mask| mask.deinit(allocator);
                    allocator.free(masks);
                }

                for (sumcheck_result.constant_polys, 0..) |oracle, i| {
                    masks[i] = try oracle.tryIntoMask(allocator);
                    masks_initialized += 1;
                }

                for (masks, sumcheck_instances.items) |mask, instance_idx| {
                    const flattened = try flattenMaskColumns(allocator, &mask);
                    defer allocator.free(flattened);
                    channel.mixFelts(flattened);
                    try mask_builders[instance_idx].append(allocator, mask);
                    masks_transferred += 1;
                }

                const challenge = channel.drawSecureFelt();

                const next_ood = try allocator.alloc(Secure, sumcheck_result.assignment.len + 1);
                @memcpy(next_ood[0..sumcheck_result.assignment.len], sumcheck_result.assignment);
                next_ood[sumcheck_result.assignment.len] = challenge;
                allocator.free(ood_point);

                ood_point = next_ood;

                for (masks, sumcheck_instances.items) |mask, instance_idx| {
                    const reduced = try mask.reduceAtPoint(allocator, challenge);
                    try replaceOwnedSlice(
                        allocator,
                        &claims_to_verify_by_instance[instance_idx],
                        reduced,
                    );
                }
            }

            const proof_sumcheck = try sumcheck_proofs.toOwnedSlice(allocator);
            errdefer {
                for (proof_sumcheck) |*v| v.deinit(allocator);
                allocator.free(proof_sumcheck);
            }

            const proof_layer_masks = try allocator.alloc([]gkr_verifier_field.GkrMask, n_instances);
            var transferred_masks: usize = 0;
            errdefer {
                for (proof_layer_masks[0..transferred_masks]) |row| {
                    for (row) |*v| v.deinit(allocator);
                    allocator.free(row);
                }
                allocator.free(proof_layer_masks);
            }
            for (mask_builders, 0..) |*builder, i| {
                proof_layer_masks[i] = try builder.toOwnedSlice(allocator);
                transferred_masks += 1;
            }

            const proof_output_claims = try allocator.alloc([]Secure, n_instances);
            var proof_output_claims_count: usize = 0;
            errdefer {
                for (proof_output_claims[0..proof_output_claims_count]) |v| allocator.free(v);
                allocator.free(proof_output_claims);
            }
            for (output_claims_by_instance, 0..) |*maybe_claims, i| {
                proof_output_claims[i] = maybe_claims.* orelse return GkrProverError.InvalidLayerStructure;
                proof_output_claims_count += 1;
                maybe_claims.* = null;
            }

            const artifact_claims = try allocator.alloc([]Secure, n_instances);
            var artifact_claims_count: usize = 0;
            errdefer {
                for (artifact_claims[0..artifact_claims_count]) |v| allocator.free(v);
                allocator.free(artifact_claims);
            }
            for (claims_to_verify_by_instance, 0..) |*maybe_claims, i| {
                artifact_claims[i] = maybe_claims.* orelse return GkrProverError.InvalidLayerStructure;
                artifact_claims_count += 1;
                maybe_claims.* = null;
            }

            const artifact_n_vars = try allocator.dupe(usize, n_layers_by_instance);

            const proof = gkr_verifier_field.GkrBatchProof{
                .sumcheck_proofs = proof_sumcheck,
                .layer_masks_by_instance = proof_layer_masks,
                .output_claims_by_instance = proof_output_claims,
            };

            const artifact = gkr_verifier_field.GkrArtifact{
                .ood_point = ood_point,
                .claims_to_verify_by_instance = artifact_claims,
                .n_variables_by_instance = artifact_n_vars,
            };

            ood_point = &[_]Secure{};
            return .{ .proof = proof, .artifact = artifact };
        }

        fn popNextLayer(layers: []const Layer, next_idx: *usize) GkrProverError!Layer {
            if (next_idx.* == 0) return GkrProverError.InvalidLayerStructure;
            next_idx.* -= 1;
            return layers[next_idx.*];
        }

        fn replaceOwnedSlice(
            allocator: std.mem.Allocator,
            slot: *?[]Secure,
            next: []Secure,
        ) !void {
            if (slot.*) |old| allocator.free(old);
            slot.* = next;
        }

        fn flattenMaskColumns(allocator: std.mem.Allocator, mask: *const gkr_verifier_field.GkrMask) ![]Secure {
            const out = try allocator.alloc(Secure, mask.columnsSlice().len * 2);
            for (mask.columnsSlice(), 0..) |column, i| {
                out[2 * i] = column[0];
                out[2 * i + 1] = column[1];
            }
            return out;
        }
    };
}
