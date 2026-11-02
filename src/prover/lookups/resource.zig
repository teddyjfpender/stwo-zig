//! Requested-live-byte bound for the borrowed-input/moving-layer GKR prover.
//! Caller matrices, proof/artifact and all numerical scratch are included;
//! allocator metadata, thread stacks, channel storage and embedding PCS are not.
const std = @import("std");
const core = @import("stwo_core");
const Circuit = @import("gkr_circuit.zig");
const Verify = @import("gkr_verifier.zig");
const Sumcheck = @import("sumcheck.zig");
pub const Kind = enum { grand_product, generic, multiplicities, singles };
pub const Shape = struct { kind: Kind, variables: u32 };
pub fn ForField(comptime S: type) type {
    return struct {
        comptime {
            // The metadata envelope below is reviewed for the four/eight-plane
            // authority, not arbitrary future oracle implementations.
            std.debug.assert(S == core.fields.qm31.QM31 or S == core.fields.om31.OM31);
            std.debug.assert(@import("verifier_kernel.zig").MAX_DEGREE <= 3);
            std.debug.assert(@sizeOf(std.ArrayList(u8)) <= 32);
            std.debug.assert(@sizeOf(Circuit.ForField(S).Layer) <= 128);
            std.debug.assert(@sizeOf(Circuit.ForField(S).EqEvals) <= 128);
            std.debug.assert(@sizeOf(@import("utils.zig").UnivariatePoly(S)) <= 32);
            std.debug.assert(@sizeOf(Verify.ForField(S).GkrArtifact) <= 64);
            std.debug.assert(@sizeOf(Circuit.ForField(S).GkrMultivariatePolyOracle) <= 256);
            std.debug.assert(@sizeOf(Verify.ForField(S).GkrMask) <= 32);
            std.debug.assert(@sizeOf(Sumcheck.ForField(S).SumcheckProof) <= 32);
        }
        pub const Plan = struct {
            input_bytes: usize = 0,
            working_plane_bytes: usize = 0,
            metadata_bytes: usize = 0,
            peak_bytes: usize = 0,
            instances: usize = 0,
            max_variables: u32 = 0,
            pub fn add(self: *Plan, shape: Shape) !void {
                if (shape.variables == 0 or shape.variables > 30) return error.InvalidGkrResourceShape;
                const facts = @as(usize, 1) << @intCast(shape.variables);
                const input_per_fact: usize = switch (shape.kind) {
                    .grand_product, .singles => @sizeOf(S),
                    .generic => 2 * @sizeOf(S),
                    .multiplicities => @sizeOf(core.fields.m31.M31) + @sizeOf(S),
                };
                self.input_bytes = try checkedAdd(self.input_bytes, try checkedMul(facts, input_per_fact));
                // Borrowed bottom; no initial clone. Reserve 3 secure values
                // plus one base value per fact for upper tree, fold overlap,
                // recursive Eq generation. The tighter tree+fold+Eq bound is
                // 2 secure values/fact (see design); retain the spare capacity.
                self.working_plane_bytes = try checkedAdd(self.working_plane_bytes, try checkedMul(facts, 3 * @sizeOf(S) + @sizeOf(core.fields.m31.M31)));
                self.instances = try checkedAdd(self.instances, 1);
                self.max_variables = @max(self.max_variables, shape.variables);
            }
            pub fn finish(self: *Plan) !void {
                if (self.instances == 0) return error.InvalidGkrResourceShape;
                const v = try checkedAdd(self.max_variables, 1);
                // Explicit shape-dependent envelope: per-instance/layer owner
                // descriptors+masks+outputs, plus per-layer/round sumcheck
                // coefficients/headers, including grow/shrink relocation.
                const units = try checkedAdd(try checkedMul(try checkedAdd(self.instances, 1), v), try checkedMul(v, v));
                self.metadata_bytes = try checkedMul(4096, units);
                self.peak_bytes = try checkedAdd(try checkedAdd(self.input_bytes, self.working_plane_bytes), self.metadata_bytes);
            }
            pub fn forShapes(shapes: []const Shape) !Plan {
                var p = Plan{};
                for (shapes) |shape| try p.add(shape);
                try p.finish();
                return p;
            }
        };
    };
}
fn checkedAdd(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b);
}
fn checkedMul(a: usize, b: usize) !usize {
    return std.math.mul(usize, a, b);
}
