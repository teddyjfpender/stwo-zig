//! Fixed field9 child shape derived only from an independently admitted key.
//! Multiproof compression and duplicate queries never select circuit geometry.
//! Shape validation does not verify a proof or admit an enclosing fold circuit.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("ethereum_wrapper_root_verifier_v1.zig");
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const layout_mod = recursion.recursion_air_composition_circuit_v3.capture_layout_v3;
const fixed = recursion.fixed_profile;
const wire = recursion.fixed_wire;
const Digest = recursion.poseidon2_channel.Digest;
pub const VERSION: u16 = 1;
pub const FOLD_ADMISSION_AVAILABLE = false;

pub const Ordinary = Types(manifest_mod);
pub const Initial38 = Types(recursion.air.ethereum_initial_input_manifest_v1);
pub const OwnedV1 = Ordinary.OwnedV1;
pub const dimensionsForManifest = Ordinary.dimensionsForManifest;

pub fn Types(comptime ManifestMod: type) type {
    const Verifier = verifier.Types(ManifestMod);
    return struct {
        const Selected = @This();
        pub const OwnedV1 = opaque {
            const Storage = struct {
                allocator: std.mem.Allocator,
                manifest: ManifestMod.Manifest,
                key_id: Digest,
                geometry: layout_mod.EthereumWrapperGeometryV1,
                shape: fixed.ProofShapeV1,
                dimensions: wire.Dimensions,
            };

            pub fn create(allocator: std.mem.Allocator, key: *const Verifier.KeyV1) !*Selected.OwnedV1 {
                try key.validate();
                const pcs = try key.session_fields.protocol.pcsConfig();
                // ProofShapeV1 is explicitly the fixed recursion protocol. A different
                // protocol needs its own admitted shape; it cannot borrow these counts.
                if (!std.meta.eql(pcs, recursion.protocol.PCS_CONFIG)) return error.InvalidEthereumChildShapeProtocol;
                const derived = try derive(&key.manifest);
                const geometry = derived.geometry;
                const fri = derived.fri;
                const dimensions = derived.dimensions;
                const columns = derived.columns;
                const shape = fixed.ProofShapeV1{
                    .air_program_id = key.session_fields.air_program_id,
                    .preprocessing_id = key.preprocessed_root,
                    .table_layout_id = recursion.poseidon2_channel.hashBytes(&key.manifest.seal, 0x4543_5331), // ECS1
                    .table_count = columns,
                    .claimed_sum_count = key.manifest.roster_count,
                    .sampled_value_count = geometry.sampled_value_count,
                    .preprocessed_column_count = geometry.tree_column_counts[0],
                    .tree_column_counts = geometry.tree_column_counts,
                    .tree_heights = geometry.tree_heights,
                    .column_log_degree = geometry.composition_chunk_log_degree,
                    .proof_wire_bytes = try wire.serializedByteCountRuntime(dimensions),
                    .fri = fri,
                };
                try shape.validate();
                try wire.validateDimensionsAgainstShape(dimensions, shape);
                const value = try allocator.create(Storage);
                value.* = .{ .allocator = allocator, .manifest = key.manifest, .key_id = key.session_fields.verification_key_id, .geometry = geometry, .shape = shape, .dimensions = dimensions };
                return @ptrCast(value);
            }

            fn storage(self: *const Selected.OwnedV1) *const Storage {
                return @ptrCast(@alignCast(self));
            }
            pub fn deinit(self: *Selected.OwnedV1) void {
                const value: *Storage = @ptrCast(@alignCast(self));
                value.allocator.destroy(value);
            }
            pub fn proofShape(self: *const Selected.OwnedV1) *const fixed.ProofShapeV1 {
                return &self.storage().shape;
            }
            pub fn wireDimensions(self: *const Selected.OwnedV1) wire.Dimensions {
                return self.storage().dimensions;
            }
            pub fn fixedGeometry(self: *const Selected.OwnedV1) layout_mod.EthereumWrapperGeometryV1 {
                return self.storage().geometry;
            }
            pub fn validateAgainstKey(self: *const Selected.OwnedV1, key: *const Verifier.KeyV1) !void {
                try key.validate();
                if (!std.meta.eql(self.storage().key_id, key.session_fields.verification_key_id)) return error.EthereumChildShapeKeyMismatch;
            }

            /// Checks expanded slot geometry only. Opening values, query positions,
            /// hashes and Fiat-Shamir relations still require child verification/AIR.
            pub fn validateCaptureShape(self: *const Selected.OwnedV1, allocator: std.mem.Allocator, capture: *const Verifier.ProofCapture) !void {
                const value = self.storage();
                const d = value.dimensions;
                if (capture.commitments.len != d.commitment_count or
                    !std.meta.eql(capture.commitments[0], value.shape.preprocessing_id) or
                    capture.queries.raw.len != d.query_count or capture.deep_answers.len != d.query_count or
                    capture.sampled_values.len != d.sampled_value_count or capture.queried_values.len != d.queried_value_count or
                    capture.trace_paths.len != d.commitment_count or capture.fri.layers.len != d.fri_layer_count or
                    capture.last_layer_coefficients.len != d.last_layer_coefficient_count)
                    return error.EthereumChildCaptureShapeMismatch;
                // Reuses exact per-column logs and sample counts, including all sixteen
                // q2 composition columns. Neither compressed lengths nor queried data
                // can alter this admission.
                var layout = if (ManifestMod == recursion.air.ethereum_initial_input_manifest_v1) try layout_mod.CaptureLayoutV3.initEthereumInitialWrapperV1(allocator, &value.manifest, capture) else try layout_mod.CaptureLayoutV3.initEthereumWrapperV1(allocator, &value.manifest, capture);
                defer layout.deinit();
                if (!std.meta.eql(layout.tree_column_counts, value.geometry.tree_column_counts) or
                    layout.sampled_value_count != value.geometry.sampled_value_count or
                    layout.composition_log_size != value.geometry.composition_log_size or
                    layout.fri_log_blowup != recursion.protocol.FRI_LOG_BLOWUP_FACTOR)
                    return error.EthereumChildCaptureShapeMismatch;
                for (capture.trace_paths, value.shape.tree_heights) |path, height| {
                    if (path.path_depth != height or path.positions.len != d.query_count or
                        path.siblings.len != try std.math.mul(usize, d.query_count, height)) return error.EthereumChildCaptureShapeMismatch;
                }
                for (capture.fri.layers, value.shape.fri.active()) |layer, round| {
                    if (layer.fold_step != round.fold_step or layer.fold_width != round.fold_width or
                        layer.path_depth != round.authentication_path_depth or layer.query_count != d.query_count or
                        layer.positions.len != d.query_count or layer.values.len != try std.math.mul(usize, d.query_count, round.fold_width) or
                        layer.siblings.len != try std.math.mul(usize, d.query_count, round.authentication_path_depth)) return error.EthereumChildCaptureShapeMismatch;
                }
            }
        };

        /// Allocation-free selector derivation; it carries no key-admission authority.
        /// The opaque key owner uses this same calculation and checks selected types.
        pub fn dimensionsForManifest(manifest: *const ManifestMod.Manifest) !wire.Dimensions {
            return (try derive(manifest)).dimensions;
        }

        const Derived = struct {
            geometry: layout_mod.EthereumWrapperGeometryV1,
            fri: fixed.FriSchedule,
            dimensions: wire.Dimensions,
            columns: u32,
        };
        fn derive(manifest: *const ManifestMod.Manifest) !Derived {
            const pcs = recursion.protocol.PCS_CONFIG;
            const geometry = if (ManifestMod == recursion.air.ethereum_initial_input_manifest_v1) try layout_mod.ethereumInitialWrapperFixedGeometryV1(manifest, pcs.fri_config.log_blowup_factor) else try layout_mod.ethereumWrapperFixedGeometry(manifest, pcs.fri_config.log_blowup_factor);
            const fri = try fixed.FriSchedule.init(geometry.composition_chunk_log_degree, pcs.fri_config);
            var columns: u32 = 0;
            for (geometry.tree_column_counts) |count| columns = try std.math.add(u32, columns, count);
            var max_width: usize = 0;
            var max_depth: usize = 0;
            for (geometry.tree_heights) |height| max_depth = @max(max_depth, height);
            for (fri.active()) |round| {
                max_width = @max(max_width, round.fold_width);
                max_depth = @max(max_depth, round.authentication_path_depth);
            }
            const dimensions = wire.Dimensions{
                .commitment_count = fixed.TREE_COUNT,
                .claimed_sum_count = manifest.roster_count,
                .sampled_value_count = geometry.sampled_value_count,
                .queried_value_count = try std.math.mul(usize, columns, recursion.protocol.FRI_QUERY_COUNT),
                .trace_path_count = try std.math.mul(usize, fixed.TREE_COUNT, recursion.protocol.FRI_QUERY_COUNT),
                .fri_layer_count = fri.count,
                .query_count = recursion.protocol.FRI_QUERY_COUNT,
                .maximum_fold_width = max_width,
                .last_layer_coefficient_count = fri.last_layer_coefficient_count,
                .maximum_merkle_depth = max_depth,
            };
            return .{ .geometry = geometry, .fri = fri, .dimensions = dimensions, .columns = columns };
        }
    };
}
