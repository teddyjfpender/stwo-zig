const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const sumcheck_module = @import("sumcheck.zig");
const utils = @import("utils.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

const kernel = @import("verifier_kernel.zig");
pub const GkrError = kernel.GkrError;

/// One algorithm authority for the selected secure extension; Q entrypoints below remain compatible.
pub fn ForField(comptime Secure: type) type {
    return struct {
        const sumcheck_field = sumcheck_module.ForField(Secure);
        /// Values obtained from partial GKR verification.
        pub const GkrArtifact = kernel.Artifact(Secure);

        /// Stores two evaluations of each column in a GKR layer.
        pub const GkrMask = struct {
            columns: [][2]Secure,

            pub fn initOwned(columns: [][2]Secure) GkrMask {
                return .{ .columns = columns };
            }

            pub fn cloneOwned(self: GkrMask, allocator: std.mem.Allocator) !GkrMask {
                return .{ .columns = try allocator.dupe([2]Secure, self.columns) };
            }

            pub fn deinit(self: *GkrMask, allocator: std.mem.Allocator) void {
                allocator.free(self.columns);
                self.* = undefined;
            }

            pub fn columnsSlice(self: GkrMask) []const [2]Secure {
                return self.columns;
            }

            pub fn toRows(self: GkrMask, allocator: std.mem.Allocator) ![2][]Secure {
                var rows: [2][]Secure = undefined;
                rows[0] = try allocator.alloc(Secure, self.columns.len);
                errdefer allocator.free(rows[0]);
                rows[1] = try allocator.alloc(Secure, self.columns.len);
                errdefer allocator.free(rows[1]);

                for (self.columns, 0..) |column, i| {
                    rows[0][i] = column[0];
                    rows[1][i] = column[1];
                }
                return rows;
            }

            pub fn reduceAtPoint(self: GkrMask, allocator: std.mem.Allocator, x: Secure) ![]Secure {
                const out = try allocator.alloc(Secure, self.columns.len);
                for (self.columns, 0..) |column, i| {
                    out[i] = utils.foldMleEvalsFor(Secure, Secure, x, column[0], column[1]);
                }
                return out;
            }
        };

        /// Batch GKR proof.
        pub const GkrBatchProof = struct {
            sumcheck_proofs: []sumcheck_field.SumcheckProof,
            layer_masks_by_instance: [][]GkrMask,
            output_claims_by_instance: [][]Secure,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                for (self.sumcheck_proofs) |*proof| proof.deinit(allocator);
                allocator.free(self.sumcheck_proofs);

                for (self.layer_masks_by_instance) |masks| {
                    for (masks) |*mask| mask.deinit(allocator);
                    allocator.free(masks);
                }
                allocator.free(self.layer_masks_by_instance);

                for (self.output_claims_by_instance) |claims| allocator.free(claims);
                allocator.free(self.output_claims_by_instance);

                self.* = undefined;
            }
        };

        /// Local gate relation used by GKR.
        pub const Gate = enum {
            LogUp,
            GrandProduct,

            pub fn eval(
                self: Gate,
                allocator: std.mem.Allocator,
                mask: *const GkrMask,
            ) GkrError![]Secure {
                return kernel.evalGate(Secure, allocator, self, mask.columns);
            }
        };

        /// Partially verifies a batch GKR proof.
        pub const NativeChecks = struct {
            pub fn requireEq(_: NativeChecks, lhs: Secure, rhs: Secure, check: kernel.Check) GkrError!void {
                if (!lhs.eql(rhs)) return switch (check) {
                    .sum => error.InvalidSumcheck,
                    .gate, .terminal => error.CircuitCheckFailure,
                };
            }
        };
        pub fn partiallyVerifyBatch(a: std.mem.Allocator, gates: []const Gate, proof: *const GkrBatchProof, channel: anytype) (std.mem.Allocator.Error || GkrError)!GkrArtifact {
            return kernel.partiallyVerifyBatch(Secure, a, gates, proof, channel, NativeChecks{});
        }
    };
}
