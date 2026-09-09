//! Thin Ethereum child adapter for the existing common-fold AIR. Child proofs
//! are field9 and keys are admitted separately; no native leaf/cohort is used.
//! This is preparation plumbing, not an activated whole-block proof endpoint.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("ethereum_wrapper_root_verifier_v1.zig");
const transcript_mod = @import("ethereum_wrapper_detached_transcript_v1.zig");
const composition_mod = @import("ethereum_wrapper_detached_composition_v1.zig");
const shape_mod = @import("ethereum_wrapper_child_shape_v1.zig");
const public = @import("recursive_field_node_public_v2.zig");
const field = @import("recursive_common_fold_field_public_v2.zig");
const fixed_source = @import("recursive_common_fold_fixed_wire_v2.zig");
const manifest = @import("recursive_common_fold_universal_manifest_v2.zig");
const rows = @import("recursive_secure_transcript_rows_v1.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const FOLD_ADMISSION_AVAILABLE = false;

/// An explicit fixed manifest selects the wire type; no bootstrap proof counts.
/// Child construction still independently validates its own key and shape.
pub fn TypesForManifest(comptime child_manifest: @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig").Manifest) type {
    @setEvalBranchQuota(50_000_000);
    const dimensions = shape_mod.dimensionsForManifest(&child_manifest) catch @compileError("invalid admitted Ethereum child manifest");
    return Types(dimensions);
}

pub fn Types(comptime dimensions: recursion.fixed_wire.Dimensions) type {
    dimensions.validate();
    return struct {
        const Adapter = @This();
        const Nonce = struct { interaction_pow_nonce: u64 };
        const ChildStorage = struct {
            allocator: std.mem.Allocator,
            transcript: *transcript_mod.OwnedV1,
            composition: *composition_mod.OwnedV1,
            shape: *shape_mod.OwnedV1,
            nonce: Nonce,
            identity: [32]u8,
        };

        pub const Child = opaque {
            pub fn init(allocator: std.mem.Allocator, key: *const verifier.KeyV1, node: *const public.NodePublicV2, claims: verifier.ClaimsV1, nonce: u64, proof: []const u8) !*Child {
                const shape = try shape_mod.OwnedV1.create(allocator, key);
                errdefer shape.deinit();
                if (!std.meta.eql(dimensions, shape.wireDimensions())) return error.EthereumFoldChildShapeMismatch;
                const transcript = try transcript_mod.OwnedV1.init(allocator, key, node, claims, nonce, proof);
                errdefer transcript.deinit();
                try shape.validateCaptureShape(allocator, transcript.proofCapture());
                const composition = try composition_mod.OwnedV1.init(allocator, transcript);
                errdefer composition.deinit();
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update("stwo-zig/ethereum-detached-fold-child/v1\x00");
                const proof_hash = @import("ethereum_wrapper_root_command_v1.zig").hash(proof);
                hash.update(&proof_hash);
                hash.update(&transcript.transcriptView().execution.identity_sha256);
                hash.update(&composition.circuit().identity_digest);
                const value = try allocator.create(ChildStorage);
                value.* = .{ .allocator = allocator, .transcript = transcript, .composition = composition, .shape = shape, .nonce = .{ .interaction_pow_nonce = nonce }, .identity = hash.finalResult() };
                return @ptrCast(value);
            }
            fn storage(self: *const Child) *const ChildStorage {
                return @ptrCast(@alignCast(self));
            }
            pub fn deinit(self: *Child) void {
                const value: *ChildStorage = @ptrCast(@alignCast(self));
                const allocator = value.allocator;
                value.composition.deinit();
                value.transcript.deinit();
                value.shape.deinit();
                allocator.destroy(value);
            }
        };

        const Projection = struct {
            role: @import("recursive_common_fold_child_capability_v2.zig").Role = .ethereum_incremental_leaf_wrapper_v4,
            node_public: *const public.NodePublicV2,
            claimed_sums: []const QM31,
            capture: *const verifier.ProofCapture,
            statement: *const Nonce,
            query_words: *const [193]M31,
            query_words_identity_sha256: *const [32]u8,
            graph: @import("recursive_common_fold_child_capability_v2.zig").ProjectionGraphV2,
        };
        fn project(child: *const Child) Projection {
            const value = child.storage();
            const transcript = value.transcript;
            const composition = value.composition;
            const execution = transcript.transcriptView().execution;
            return .{
                .node_public = transcript.publicNode(),
                .claimed_sums = &transcript.claimValues().values,
                .capture = transcript.proofCapture(),
                .statement = &value.nonce,
                .query_words = transcript.queryWords(),
                .query_words_identity_sha256 = &value.identity,
                .graph = .{
                    .capture_identity_sha256 = &value.identity,
                    .layout_identity_sha256 = &composition.captureLayout().identity,
                    .query_words = transcript.queryWords(),
                    .query_log_size = transcript.queryLogSize(),
                    .final_transcript_digest = &execution.final_digest,
                    .final_transcript_draw_count = execution.final_draw_count,
                    .query_words_identity_sha256 = &value.identity,
                    .lane = .{
                        .verifier_id = recursion.binary_fri_outer_source.LEFT_RECURSION_VERIFIER_ID,
                        .circuit_id = @import("recursive_common_ethereum_incremental_leaf_composition_capture_owner_v4.zig").CIRCUIT_ID,
                        .statement_scope = recursion.binary_fri_outer_source.LEFT_COMPOSITION_STATEMENT_SCOPE,
                        .graph = composition.circuit().graph(),
                        .profile = composition.inputProfile().graphProfile(),
                        .bindings = composition.inputBindings(),
                    },
                    .evaluation = .{ .circuit_identity = composition.circuit().identity_digest, .values = composition.nodeValues() },
                },
            };
        }
        const Input = struct {
            parent_coordinate: @import("recursive_node_artifact_v2.zig").TaskCoordinateV1,
            node: public.NodePublicV2,
            pub fn outputNodePublic(self: *const Input) *const public.NodePublicV2 {
                return &self.node;
            }
        };
        pub const Live = struct {
            pub const ETHEREUM_CHILD_PROFILE_VERSION: u32 = 1;
            pub const FoldChild = *const Child;
            pub const CapturedFriPair = @import("recursive_common_fold_universal_cohort_v2.zig").CapturedFriPairV2;
            children: [2]*const Child,
            input: Input,
            public_schedule: field.PoseidonScheduleV2,
            identity_sha256: [32]u8,

            pub fn init(children: [2]*const Child) !Live {
                const left = children[0].storage().transcript.publicNode();
                const right = children[1].storage().transcript.publicNode();
                const coordinate = try @import("recursive_node_artifact_v2.zig").TaskCoordinateV1.init(try std.math.add(u8, left.coordinate.height, 1), left.coordinate.index / 2);
                const schedule = try field.PoseidonScheduleV2.build(left, right, coordinate);
                var value = Live{ .children = children, .input = .{ .parent_coordinate = coordinate, .node = schedule.parent }, .public_schedule = schedule, .identity_sha256 = undefined };
                value.identity_sha256 = value.identity();
                try value.validate();
                return value;
            }
            pub fn validate(self: *const Live) !void {
                if (self.children[0] == self.children[1]) return error.EthereumFoldChildMismatch;
                for (self.children) |child| if (!std.meta.eql(dimensions, child.storage().shape.wireDimensions())) return error.EthereumFoldChildShapeMismatch;
                try self.public_schedule.validateAgainst(self.children[0].storage().transcript.publicNode(), self.children[1].storage().transcript.publicNode(), self.input.parent_coordinate);
                if (!std.meta.eql(self.input.node, self.public_schedule.parent) or !std.meta.eql(self.identity_sha256, self.identity())) return error.EthereumFoldChildMismatch;
            }
            pub fn requireFixedWireSource(self: *const Live) !void {
                try self.validate();
            }
            pub fn initCapturedFriPair(self: *const Live, allocator: std.mem.Allocator) !CapturedFriPair {
                try self.validate();
                const protocol = self.children[0].storage().transcript.admittedKey().session_fields.protocol;
                const config = recursion.captured_fri.ProfileConfig{ .log_blowup_factor = protocol.fri_log_blowup_factor, .log_last_layer_degree_bound = protocol.fri_log_last_layer_degree_bound, .interaction_pow_bits = protocol.interaction_pow_bits, .pcs_pow_bits = protocol.pcs_pow_bits, .claimed_sum_count = @intCast(dimensions.claimed_sum_count) };
                var left = try recursion.captured_fri.Owned.init(allocator, config, self.children[0].storage().transcript.proofCapture());
                errdefer left.deinit();
                const right = try recursion.captured_fri.Owned.init(allocator, config, self.children[1].storage().transcript.proofCapture());
                return .{ .children = .{ left, right } };
            }
            pub fn authenticatedCompositionLanes(self: *const Live) ![2]recursion.binary_fri_outer_source.AuthenticatedCompositionLane {
                try self.validate();
                var lanes: [2]recursion.binary_fri_outer_source.AuthenticatedCompositionLane = undefined;
                for (self.children, &lanes, 0..) |child, *lane, index| {
                    const graph = project(child).graph;
                    lane.* = .{ .circuit_id = if (index == 0) 761 else 762, .circuit_identity = graph.lane.graph.identity_digest, .graph = graph.lane.graph, .evaluation = graph.evaluation };
                    try lane.validate();
                }
                return lanes;
            }
            fn identity(self: *const Live) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update("stwo-zig/ethereum-detached-fold-parent/v1\x00");
                for (self.children) |child| hash.update(&child.storage().identity);
                return hash.finalResult();
            }
        };
        const Policy = struct {
            pub const RootPin = struct {
                identity_sha256: [32]u8,
                pub fn validateAgainst(self: @This(), live: *const Live) !void {
                    try live.validate();
                    if (!std.meta.eql(self.identity_sha256, live.identity_sha256)) return error.EthereumFoldChildMismatch;
                }
            };
            pub fn initRootPin(live: *const Live) !RootPin {
                try live.validate();
                return .{ .identity_sha256 = live.identity_sha256 };
            }
            pub fn validateRootPin(pin: RootPin, live: *const Live) !void {
                try pin.validateAgainst(live);
            }
            pub fn validateDimensions(comptime selected: recursion.fixed_wire.Dimensions, live: *const Live) !void {
                try live.validate();
                if (!std.meta.eql(selected, dimensions)) return error.EthereumFoldChildShapeMismatch;
            }
            pub fn projectChild(child: *const Child, live: *const Live) !Projection {
                if (child != live.children[0] and child != live.children[1]) return error.EthereumFoldChildMismatch;
                return Adapter.project(child);
            }
            pub fn transcriptView(child: *const Child, live: *const Live) !rows.View {
                _ = try projectChild(child, live);
                return child.storage().transcript.transcriptView();
            }
            pub fn validateChildCustody(actual: Projection, expected: Projection, _: *const Live) !void {
                if (!std.meta.eql(actual, expected)) return error.EthereumFoldChildMismatch;
            }
        };
        pub const Fixed = fixed_source.TypesForLive(dimensions, Live, Policy);
        pub const ManifestPolicy = manifest.DerivedPolicyForLive(Live, Fixed, "stwo-zig/ethereum-detached-fold-manifest/v1\x00");
        pub const Cohort = @import("recursive_common_fold_secure_cohort_v2.zig").CohortForLiveV2(dimensions, Live, Fixed, ManifestPolicy);
    };
}
