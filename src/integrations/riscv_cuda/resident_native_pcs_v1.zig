//! Exact finite original native PCS plans. These are cold metadata, not a
//! proving controller or a verification receipt. Program outlives Plans.
const std = @import("std");
const Program = @import("resident_native_program_v1.zig");
const Shared = @import("resident_parent_pcs_v1.zig");
const GeometryModule = @import("../circuit_cuda/geometry.zig");
pub const Commit = Shared.Commit;
pub const Oods = Shared.Oods;
pub const Quotient = Shared.Quotient;
pub const Fri = Shared.Fri;
pub const CommitOps = Shared.CommitOps;
pub fn ForCommitments(comptime N: usize) type {
    if (N != 4 and N != 5) @compileError("native PCS requires four/five original commitments");
    return struct {
        pub const Geometry = struct { trees: [N]GeometryModule.Tree, fri_layers: []GeometryModule.FriLayer, composition_evaluation_log: u32, fri_input_log: u32, identity: [32]u8 };
        pub const Decommit = @import("../circuit_cuda/resident_decommit.zig").ForCommitments(N);
        pub const ProofLayout = @import("../circuit_cuda/resident_proof_layout.zig").ForCommitments(N);
        pub const Plans = struct {
            a: std.mem.Allocator,
            geometry: Geometry,
            commitments: [N]Commit.Plan,
            oods: Oods.Plan,
            quotient: Quotient.Topology,
            owns_quotient: bool = true,
            fri: Fri.Plan,
            decommit: Decommit,
            proof_layout: ProofLayout,
            numerical_bytes_lower_bound: usize,
            pub fn init(a: std.mem.Allocator, program: *const Program.ForCommitments(N).Owned, cap: usize) !Plans {
                const p = program.view();
                const config = p.profile.epoch.config;
                const blowup = config.fri_config.log_blowup_factor;
                var geometry = Geometry{ .trees = undefined, .fri_layers = try a.alloc(GeometryModule.FriLayer, p.fri_layers.len), .composition_evaluation_log = p.composition_log, .fri_input_log = p.fri_log, .identity = p.identity };
                errdefer a.free(geometry.fri_layers);
                for (p.trees, &geometry.trees) |tree, *out| out.* = .{ .role = switch (tree.kind) {
                    .fixed => .preprocessed,
                    .main, .access_witness => .main,
                    .interaction => .interaction,
                    .composition => .composition,
                }, .column_logs = tree.base_logs, .lifted_log = tree.lifted_log };
                for (p.fri_layers, geometry.fri_layers) |layer, *out| out.* = .{ .evaluation_log = layer.evaluation_log, .fold_step = layer.fold_step, .cumulative_fold = layer.cumulative_fold, .leaf_log = layer.leaf_log };
                var commitments: [N]Commit.Plan = undefined;
                var ready: usize = 0;
                errdefer for (commitments[0..ready]) |*c| c.deinit();
                for (geometry.trees, &commitments) |tree, *out| {
                    out.* = try Commit.Plan.init(a, tree, blowup);
                    ready += 1;
                }
                var column_count: usize = 0;
                for (p.trees) |tree| column_count = try std.math.add(usize, column_count, tree.base_logs.len);
                const offsets = try a.alloc([]const i32, column_count);
                defer a.free(offsets);
                var cursor: usize = 0;
                for (p.trees) |tree| for (tree.layouts, tree.mask_logs) |mask, step| {
                    if (step != p.mask_log) return error.UnsupportedResidentNativeMaskStep;
                    offsets[cursor] = switch (mask) {
                        .none => &.{},
                        .current => &.{0},
                        .current_previous => &.{ 0, -1 },
                        .previous_current => &.{ -1, 0 },
                        else => return error.UnsupportedResidentNativeMask,
                    };
                    cursor += 1;
                };
                var oods = try Oods.Plan.initForOriginalOffsets(a, &geometry, offsets, blowup, p.mask_log);
                errdefer oods.deinit();
                var quotient = try Quotient.deriveForOffsets(a, &geometry, &oods, blowup, offsets, p.mask_log);
                errdefer quotient.deinit();
                var fri = try Fri.Plan.init(a, &geometry, config, @as(usize, 1) << @intCast(@max(p.fri_log, p.composition_log) - 1));
                errdefer fri.deinit();
                var decommit = try Decommit.init(a, &geometry, config);
                errdefer decommit.deinit();
                var layout = try ProofLayout.initForOriginalMasks(a, &geometry, &oods, config);
                errdefer layout.deinit(a);
                var bytes = p.polynomial_bytes;
                bytes = try std.math.add(usize, bytes, try std.math.mul(usize, 16, try std.math.add(usize, oods.factor_count, try std.math.mul(usize, 2, oods.scratch_count))));
                bytes = try std.math.add(usize, bytes, try std.math.mul(usize, 16, @intCast(quotient.partial_offsets[quotient.partial_offsets.len - 1])));
                if (bytes > cap) return error.ResidentNativeResourceLimit;
                return .{ .a = a, .geometry = geometry, .commitments = commitments, .oods = oods, .quotient = quotient, .fri = fri, .decommit = decommit, .proof_layout = layout, .numerical_bytes_lower_bound = bytes };
            }
            pub fn takeQuotient(self: *Plans) !Quotient.Topology {
                if (!self.owns_quotient) return error.InvalidResidentNativeOwnership;
                self.owns_quotient = false;
                return self.quotient;
            }
            pub fn deinit(self: *Plans) void {
                self.proof_layout.deinit(self.a);
                self.decommit.deinit();
                self.fri.deinit();
                if (self.owns_quotient) self.quotient.deinit();
                self.oods.deinit();
                for (&self.commitments) |*c| c.deinit();
                self.a.free(self.geometry.fri_layers);
                self.* = undefined;
            }
        };
    };
}
