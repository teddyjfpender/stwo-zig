//! Independently owned original PAGE verifier geometry/claim metadata. This
//! frame is not proof authority: only the shared original captured verifier
//! creates a verified PAGE capture, and every recursive admission rederives it.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
const Composition = @import("block_v5_memory_source_page_composition_v1.zig");
pub const VERSION: u32 = 1;
pub const TRACE_TREES = Composition.TREE_COUNT;
pub const COMMITMENTS = Protocol.PROOF_COMMITMENTS;
comptime {
    if (TRACE_TREES != 9 or COMMITMENTS != TRACE_TREES + 1)
        @compileError("PAGE capture requires all nine original trace trees plus composition");
}
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const C = Components.ForKind(kind);
    return struct {
        const Self = @This();
        claims: C.Claims,
        semantic: Protocol.SemanticPin,
        geometry: C.Geometry,
        logs: [TRACE_TREES][]u32,
        constraint_count: usize,
        constraint_log: u32,
        split: u32,
        pub fn init(a: std.mem.Allocator, claims: C.Claims, semantic: Protocol.SemanticPin, geometry: C.Geometry, owner: *const C.Owner) !Self {
            const composite = owner.composition orelse return error.InvalidSourcePageCaptureFrame;
            var result = Self{ .claims = claims, .semantic = semantic, .geometry = geometry, .logs = undefined, .constraint_count = composite.nConstraints(), .constraint_log = composite.maxConstraintLogDegreeBound(), .split = composite.compositionLogSplit() };
            var completed: usize = 0;
            errdefer for (result.logs[0..completed]) |logs| a.free(logs);
            for (composite.logs, &result.logs) |logs, *copy| {
                copy.* = try a.dupe(u32, logs);
                completed += 1;
            }
            return result;
        }
        pub fn clone(self: *const Self, a: std.mem.Allocator) !Self {
            var result = self.*;
            var completed: usize = 0;
            errdefer for (result.logs[0..completed]) |logs| a.free(logs);
            for (self.logs, &result.logs) |logs, *copy| {
                copy.* = try a.dupe(u32, logs);
                completed += 1;
            }
            return result;
        }
        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            for (self.logs) |logs| a.free(logs);
            self.* = undefined;
        }
        /// Compare to an independently reconstructed original component owner,
        /// not another proposed frame or a mutable frame's self-checksum.
        pub fn require(self: *const Self, geometry: C.Geometry, semantic: Protocol.SemanticPin, owner: *const C.Owner) !void {
            const composite = owner.composition orelse return error.InvalidSourcePageCaptureFrame;
            if (!std.meta.eql(self.geometry, geometry) or !std.meta.eql(self.semantic, semantic) or
                self.constraint_count != composite.nConstraints() or self.constraint_log != composite.maxConstraintLogDegreeBound() or self.split != composite.compositionLogSplit())
                return error.InvalidSourcePageCaptureFrame;
            for (self.logs, composite.logs) |actual, expected| if (!std.mem.eql(u32, actual, expected)) return error.InvalidSourcePageCaptureFrame;
        }
        /// All mask points and FRI-extended logs come from the exact original
        /// owner. Captured values alone cannot choose openings or geometry.
        pub fn requireCaptured(self: *const Self, a: std.mem.Allocator, capture: *const core.verifier.ProofCapture(suite.Hasher), config: core.pcs.PcsConfig, owner: *const C.Owner) !void {
            if (capture.commitments.len != COMMITMENTS or capture.column_log_sizes.len != COMMITMENTS or capture.sampled_points.len != COMMITMENTS)
                return error.InvalidSourcePageCaptureGeometry;
            const composite = owner.composition orelse return error.InvalidSourcePageCaptureFrame;
            const split = composite.compositionLogSplit();
            const bound = composite.maxConstraintLogDegreeBound();
            const mask_log = core.verifier_types.compositionMaskLogSize(bound, split) orelse return error.InvalidSourcePageCaptureGeometry;
            const point = core.circle.secureFieldPointFromRandomSeed(capture.oods_seed);
            const handle = owner.asVerifierComponent();
            const all = core.air.components.Components{ .components = &.{handle}, .n_preprocessed_columns = self.logs[0].len };
            var masks = try all.maskPoints(a, point, mask_log, false);
            defer masks.deinitDeep(a);
            if (masks.items.len != TRACE_TREES) return error.InvalidSourcePageCaptureGeometry;
            var count: usize = 0;
            for (self.logs, capture.column_log_sizes[0..TRACE_TREES], capture.sampled_points[0..TRACE_TREES], masks.items) |logs, extended, columns, expected_masks| {
                if (logs.len != extended.len or logs.len != columns.len or logs.len != expected_masks.len) return error.InvalidSourcePageCaptureGeometry;
                for (logs, extended, columns, expected_masks) |log, actual_log, points, expected_points| {
                    if (try std.math.add(u32, log, config.fri_config.log_blowup_factor) != actual_log or points.len != expected_points.len) return error.InvalidSourcePageCaptureGeometry;
                    for (points, expected_points) |actual, expected| if (!actual.eql(expected)) return error.InvalidSourcePageCaptureGeometry;
                    count = try std.math.add(usize, count, points.len);
                }
            }
            const composition_count = core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidSourcePageCaptureGeometry;
            if (capture.column_log_sizes[TRACE_TREES].len != composition_count or capture.sampled_points[TRACE_TREES].len != composition_count) return error.InvalidSourcePageCaptureGeometry;
            for (capture.column_log_sizes[TRACE_TREES], capture.sampled_points[TRACE_TREES]) |log, points| {
                if (log != try std.math.add(u32, mask_log, config.fri_config.log_blowup_factor) or points.len != 1 or !points[0].eql(point)) return error.InvalidSourcePageCaptureGeometry;
                count = try std.math.add(usize, count, 1);
            }
            if (count != capture.sampled_values.len) return error.InvalidSourcePageCaptureGeometry;
        }
        pub fn mix(self: *const Self, channel: anytype) void {
            channel.mixU32s(&.{ 0x50474346, VERSION, @intFromEnum(kind), TRACE_TREES, COMMITMENTS, self.constraint_log, self.split }); // PGCF
            channel.mixU64(self.constraint_count);
            channel.mixU32s(&.{ self.geometry.source_log, self.geometry.capture_log });
            channel.mixU32s(&self.geometry.core_logs);
            channel.mixU32s(&self.geometry.arithmetic_logs);
            channel.mixU64(self.geometry.capture_requests);
            for (self.logs) |logs| {
                channel.mixU64(logs.len);
                channel.mixU32s(logs);
            }
            channel.mixRoot(self.semantic.premix_identity);
            channel.mixRoot(self.semantic.source_epoch);
            channel.mixRoot(self.semantic.graph_identity);
            channel.mixU32s(&.{self.semantic.circuit_id});
            channel.mixU64(self.semantic.input_requests);
            Protocol.mixClaims(channel, self.semantic.claims);
            for (self.semantic.roots) |root| channel.mixRoot(root);
            channel.mixFelts(&self.claims.core);
            channel.mixFelts(&self.claims.capture.sums);
            channel.mixU64(self.claims.capture.wire_requests);
            channel.mixFelts(&self.claims.source_inputs.sums);
            channel.mixU64(self.claims.source_inputs.requests);
            channel.mixFelts(&self.claims.capture_inputs.sums);
            channel.mixU64(self.claims.capture_inputs.requests);
            channel.mixFelts(&self.claims.arithmetic);
        }
        pub fn identity(self: *const Self) [32]u8 {
            var channel = suite.Channel{};
            self.mix(&channel);
            return channel.digestBytes();
        }
    };
}

/// Published transactionally only by the original full captured verifier.
/// Generic parameters are selected by original ForKind, never proof bytes.
/// Storage is independently owned on the supplied verifier allocator.
pub fn Capture(comptime kind: Semantic.Kind, comptime Pin: type, comptime Receipt: type) type {
    return struct {
        const Self = @This();
        proof: core.verifier.ProofCapture(suite.Hasher),
        frame: ForKind(kind),
        pin: Pin,
        config: core.pcs.PcsConfig,
        relations: @import("../recursion/air/universal_challenges.zig").UniversalRelations,
        /// Exact native state after registering interaction tree8, before
        /// the original composition draw. No original channel is restarted.
        proof_start: suite.Channel,
        final_channel: suite.Channel,
        receipt: Receipt,
        seal: [32]u8,
        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            self.frame.deinit(a);
            self.proof.deinit(a);
            self.* = undefined;
        }
        /// Mutation seal only, never substitute verification or independent
        /// expected-pin/recipe reconstruction with this mutable self-hash.
        pub fn identity(self: *const Self) [32]u8 {
            var channel = suite.Channel{};
            channel.mixU32s(&.{ 0x50474350, VERSION, @intFromEnum(kind), COMMITMENTS }); // PGCP
            channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
            self.frame.mix(&channel);
            self.config.mixInto(&channel);
            for (self.pin.roots) |root| channel.mixRoot(root);
            for (self.relations.elements) |element| {
                channel.mixFelts(&.{ element.z, element.alpha });
                channel.mixU32s(&.{element.arity});
                channel.mixFelts(&element.alpha_powers);
            }
            channel.mixRoot(self.proof_start.digestBytes());
            channel.mixU64(self.proof_start.n_draws);
            channel.mixRoot(self.final_channel.digestBytes());
            channel.mixU64(self.final_channel.n_draws);
            channel.mixRoot(self.receipt.admission_id);
            channel.mixRoot(self.receipt.source_seal);
            channel.mixRoot(self.receipt.premix_identity);
            channel.mixRoot(self.receipt.graph_identity);
            channel.mixU32s(&.{ self.receipt.page_index, @intFromEnum(self.receipt.kind) });
            channel.mixU64(self.receipt.input_requests);
            Protocol.mixClaims(&channel, self.receipt.claims);
            channel.mixRoot(self.receipt.final_channel);
            return channel.digestBytes();
        }
        pub fn requireIntegrity(self: *const Self) !void {
            if (self.receipt.kind != kind or self.proof.commitments.len != COMMITMENTS or
                !std.meta.eql(self.proof.commitments[0..6].*, self.pin.roots) or
                !std.meta.eql(self.proof.commitments[6..8].*, self.frame.semantic.roots) or
                !std.meta.eql(self.receipt.claims, self.frame.semantic.claims) or
                !std.meta.eql(self.receipt.premix_identity, self.frame.semantic.premix_identity) or
                !std.meta.eql(self.receipt.graph_identity, self.frame.semantic.graph_identity) or
                self.receipt.input_requests != self.frame.semantic.input_requests or
                !std.meta.eql(self.receipt.final_channel, self.final_channel.digestBytes()) or
                !std.meta.eql(self.seal, self.identity())) return error.InvalidSourcePageCapturedIntegrity;
        }
    };
}
