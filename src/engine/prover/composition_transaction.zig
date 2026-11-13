//! Ownership of composition splitting, commitment and OODS mask allocation.
const std = @import("std");
const core = @import("stwo_core");
const stage_profile = @import("stwo_prover_api").stage_profile;
const verifier_types = core.verifier_types;
pub fn ForField(comptime Secure: type, comptime ProvingError: type) type {
    const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
    const core_air_components = core.air.components.ForField(Secure);
    const pcs_prover = @import("pcs/mod.zig").ForField(Secure);
    const CirclePointQM31 = core.circle.CirclePoint(Secure);
    const prover_circle = struct {
        pub const SecureCirclePoly = @import("poly/circle/secure_poly.zig").ForField(Secure).SecureCirclePoly;
        pub const CircleCoefficients = @import("poly/circle/poly.zig").CircleCoefficients;
    };
    return struct {
        pub const CompositionChunks = struct {
            chunks: []prover_circle.SecureCirclePoly,
            owns_polynomials: bool,

            pub fn deinit(self: *CompositionChunks, allocator: std.mem.Allocator) void {
                if (self.owns_polynomials) {
                    for (self.chunks) |*chunk| chunk.deinit(allocator);
                }
                allocator.free(self.chunks);
                self.* = undefined;
            }
        };

        pub fn splitCompositionPair(
            allocator: std.mem.Allocator,
            pair: prover_circle.SecureCirclePoly.SplitPair,
            split_depth: u32,
        ) !CompositionChunks {
            if (split_depth == 0) return ProvingError.InvalidStructure;
            if (split_depth == 1) {
                return .{
                    .chunks = try allocator.dupe(
                        prover_circle.SecureCirclePoly,
                        &.{ pair.left, pair.right },
                    ),
                    .owns_polynomials = false,
                };
            }

            var left = try pair.left.splitIntoChunks(allocator, split_depth - 1);
            var left_moved = false;
            defer if (left_moved)
                allocator.free(left.chunks)
            else
                left.deinit(allocator);
            var right = try pair.right.splitIntoChunks(allocator, split_depth - 1);
            var right_moved = false;
            defer if (right_moved)
                allocator.free(right.chunks)
            else
                right.deinit(allocator);

            const chunks = try allocator.alloc(
                prover_circle.SecureCirclePoly,
                left.chunks.len + right.chunks.len,
            );
            @memcpy(chunks[0..left.chunks.len], left.chunks);
            @memcpy(chunks[left.chunks.len..], right.chunks);
            left_moved = true;
            right_moved = true;
            return .{ .chunks = chunks, .owns_polynomials = true };
        }

        pub fn commitCompositionChunks(
            comptime B: type,
            comptime H: type,
            comptime MC: type,
            allocator: std.mem.Allocator,
            commitment_scheme: *pcs_prover.CommitmentSchemeProver(B, H, MC),
            chunks: []const prover_circle.SecureCirclePoly,
            recorder: ?*stage_profile.Recorder,
            channel: anytype,
        ) !void {
            if (chunks.len == 0) return ProvingError.InvalidStructure;
            const split_log_size = chunks[0].logSize();
            for (chunks[1..]) |chunk| {
                if (chunk.logSize() != split_log_size) return ProvingError.InvalidStructure;
            }

            const n_polys = std.math.mul(
                usize,
                chunks.len,
                DEGREE,
            ) catch return ProvingError.InvalidStructure;
            const polys = try allocator.alloc(prover_circle.CircleCoefficients, n_polys);
            defer allocator.free(polys);

            for (chunks, 0..) |chunk, chunk_index| {
                for (chunk.polys, 0..) |coordinate, coordinate_index| {
                    polys[chunk_index * DEGREE + coordinate_index] =
                        coordinate;
                }
            }

            try commitment_scheme.commitPolysWithRecorder(
                allocator,
                polys,
                recorder,
                channel,
            );
        }

        pub fn appendCompositionMaskTree(
            allocator: std.mem.Allocator,
            sample_points: *core_air_components.MaskPoints,
            oods_point: CirclePointQM31,
            split_depth: u32,
        ) !void {
            const n_composition_cols = verifier_types.compositionColumnCount(
                split_depth,
                DEGREE,
            ) orelse return ProvingError.InvalidStructure;

            const composition_tree = try allocator.alloc([]CirclePointQM31, n_composition_cols);
            var initialized: usize = 0;
            errdefer {
                for (composition_tree[0..initialized]) |col| allocator.free(col);
                allocator.free(composition_tree);
            }

            for (composition_tree) |*col| {
                col.* = try allocator.alloc(CirclePointQM31, 1);
                col.*[0] = oods_point;
                initialized += 1;
            }

            const old_len = sample_points.items.len;
            const out = try allocator.alloc([][]CirclePointQM31, old_len + 1);
            @memcpy(out[0..old_len], sample_points.items);
            out[old_len] = composition_tree;

            allocator.free(sample_points.items);
            sample_points.items = out;
        }
    };
}
