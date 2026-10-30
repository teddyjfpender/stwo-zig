//! Bounded four/five-tree original-native arena. All numeric sources, epoch
//! draws, claims, PCS buffers and counters are device-owned until terminal read.
const std = @import("std");
const cuda = @import("stwo_cuda_backend");
const arena = cuda.runtime.arena;
const common = cuda.runtime.stages.common;
const field = cuda.abi.field;
const Stage = cuda.runtime.telemetry.Stage;
const shared = @import("stwo_native_cuda_integration").common;
const Old = @import("../circuit_cuda/resident_memory_plan.zig");
const OldBinding = @import("../circuit_cuda/resident_memory_binding.zig");
const Commit = @import("resident_native_pcs_v1.zig").Commit;
const Tables = @import("../../frontends/riscv/air/lookups/tables/schema.zig");
pub const Kind = Old.Kind;
pub const EXTENSION_ID_START: u32 = 1 << 28;
pub fn id(kind: Kind, ordinal: usize) !u32 {
    if (ordinal >= 65536) return error.ResidentNativeResourceLimit;
    return (@as(u32, @intFromEnum(kind)) << 16) | @as(u32, @intCast(ordinal));
}
pub const TranscriptBindings = struct { state: cuda.runtime.column.DeviceSlice(cuda.abi.stages.blake3.Channel), static_words: common.Words };
pub fn ForCommitments(comptime N: usize) type {
    const Program = @import("resident_native_program_v1.zig").ForCommitments(N);
    const PCS = @import("resident_native_pcs_v1.zig").ForCommitments(N);
    const Terminal = @import("resident_native_terminal_v1.zig").ForCommitments(N);
    return struct {
        pub const Plan = struct {
            allocator: std.mem.Allocator,
            requirements: []arena.Requirement,
            placement: arena.Plan,
            owns_placement: bool = true,
            raw_words: usize,
            pub fn init(a: std.mem.Allocator, program: *const Program.Owned, pcs: *const PCS.Plans, terminal: *const Terminal.Bundle, static_words: usize, raw_input_bytes: usize, extra: []const arena.Requirement, maximum_bytes: usize) !Plan {
                const p = program.view();
                try Terminal.requireBundle(program, pcs, terminal);
                if (raw_input_bytes % 4 != 0 or static_words == 0 or maximum_bytes == 0) return error.ResidentNativeResourceLimit;
                var b = Builder{ .allocator = a };
                defer b.items.deinit(a);
                try b.add(.values, 0, @max(1, raw_input_bytes / 4), 64, .ingress, .trace_generation);
                for (0..N - 1) |tree| for (p.trees[tree].base_logs, 0..) |log, column| {
                    // Source rows still feed table counters and interaction generation
                    // after MAIN commitment. Lifetime ends only after tree2 commits.
                    try b.add(sourceKind(tree), sourceOrdinal(tree, column), pow(log), 64, if (tree == N - 2) .trace_commit else .ingress, .trace_commit);
                };
                for (pcs.commitments, 0..) |commitment, tree| {
                    const r = commitment.requirements;
                    const start: Stage = if (tree == N - 1) .constraint_evaluation else .trace_commit;
                    try b.add(.commit_coefficients, tree, r.coefficient_words, 64, start, .oods);
                    try b.add(.commit_evaluations, tree, r.evaluation_words, 64, start, .decommit);
                    try b.add(.commit_logs, tree, r.column_log_words, 1, .ingress, start);
                    try b.add(.commit_hashes, tree, try mul(r.merkle_hashes, 8), 64, start, .decommit);
                    try b.add(.commit_layers, tree, try mul(r.merkle_layers, @sizeOf(field.MerkleLayerDescriptor) / 4), 2, .ingress, .decommit);
                }
                const twiddles = pow(@max(p.fri_log, p.composition_log) - 1);
                try b.add(.twiddles_forward, 0, twiddles, 64, .ingress, .quotient);
                try b.add(.twiddles_inverse, 0, twiddles, 64, .ingress, .fri_commit);
                try b.add(.transcript_state, 0, @sizeOf(cuda.abi.stages.blake3.Channel) / 4, 4, .trace_commit, .proof_assembly);
                try b.add(.transcript_config, 0, static_words, 4, .ingress, .trace_commit);
                try b.add(.interaction_drawn, 0, 424, 4, .trace_commit, .constraint_evaluation);
                try b.add(.interaction_claims, 0, @max(1, 4 * p.physical_claim_count), 4, .trace_commit, .proof_assembly);
                try b.add(.composition_alpha, 0, 4, 4, .constraint_evaluation, .constraint_evaluation);
                try b.add(.pow_nonce, 0, 2, 2, .pow, .decommit);
                try b.add(.error_flag, 0, 1, 1, .ingress, .proof_assembly);
                for (0..6) |table| try b.add(.interaction_geometry, table, Tables.size(@enumFromInt(table)), 64, .ingress, .proof_assembly);
                try Old.Builder.addOods(&b, &pcs.oods);
                try Old.Builder.addQuotient(&b, &pcs.quotient, p.fri_log);
                try Old.Builder.addFri(&b, &pcs.fri);
                try Old.Builder.addDecommit(&b, &pcs.decommit);
                try b.add(.terminal_bundle, 0, terminal.total_words, 64, .ingress, .proof_assembly);
                for (extra, 0..) |r, i| {
                    if (r.id < EXTENSION_ID_START or r.words == 0) return error.InvalidResidentNativeExtension;
                    for (extra[0..i]) |previous| if (previous.id == r.id) return error.InvalidResidentNativeExtension;
                    try b.items.append(a, r);
                }
                const requirements = try b.items.toOwnedSlice(a);
                errdefer a.free(requirements);
                var placement = try arena.Plan.init(a, requirements);
                errdefer placement.deinit(a);
                if (try mul(placement.total_words, 4) > maximum_bytes) return error.ResidentNativeResourceLimit;
                return .{ .allocator = a, .requirements = requirements, .placement = placement, .raw_words = raw_input_bytes / 4 };
            }
            pub fn takePlacement(self: *Plan) !arena.Plan {
                if (!self.owns_placement) return error.InvalidResidentNativeExtension;
                self.owns_placement = false;
                return self.placement;
            }
            pub fn deinit(self: *Plan) void {
                if (self.owns_placement) self.placement.deinit(self.allocator);
                self.allocator.free(self.requirements);
                self.* = undefined;
            }
        };
        const Builder = struct {
            allocator: std.mem.Allocator,
            items: std.ArrayList(arena.Requirement) = .empty,
            pub fn add(self: *Builder, kind: Kind, ordinal: usize, words: usize, alignment: usize, from: Stage, through: Stage) !void {
                if (words == 0) return error.InvalidResidentNativeExtension;
                try self.items.append(self.allocator, .{ .id = try id(kind, ordinal), .words = words, .alignment_words = alignment, .live_from = from, .live_through = through });
            }
        };
        pub const Binder = struct {
            tx: *cuda.runtime.proof_transaction.ResidentProofTransaction,
            pub fn words(self: *const Binder, kind: Kind, ordinal: usize) !common.Words {
                return self.tx.slot(try id(kind, ordinal));
            }
            pub fn as(self: *const Binder, comptime T: type, kind: Kind, ordinal: usize) !cuda.runtime.column.DeviceSlice(T) {
                return (try self.words(kind, ordinal)).cast(T);
            }
        };
        pub const Views = struct {
            allocator: std.mem.Allocator,
            sources: [N - 1][]common.Words,
            coefficient_columns: [N - 1][]common.Words,
            evaluation_columns: [N - 1][]common.Words,
            commits: [N]Commit.Buffers,
            raw_input: common.Words,
            twiddles_forward: common.Words,
            twiddles_inverse: common.Words,
            transcript: TranscriptBindings,
            relations: common.SecureFields,
            claims: common.SecureFields,
            table_counters: [6]common.Words,
            composition_alpha: common.SecureFields,
            oods: shared.resident_views.Oods,
            quotient: @import("stwo_cairo_cuda_integration").executor.quotient.controller.QuotientBindings,
            fri: shared.resident_views.Fri,
            decommit: shared.resident_views.Decommit,
            proof: shared.resident_views.Proof,
            nonce: common.Nonce,
            error_flag: common.Words,
            pub fn producer(self: *const Views) !@import("resident_native_producer_v1.zig").ForCommitments(N).Views {
                var sources: [N - 1][]const common.Words = undefined;
                for (self.sources, &sources) |from, *to| to.* = from;
                return .{ .raw = self.raw_input, .sources = sources, .draws = try self.relations.cast(u32), .claims = try self.claims.cast(u32), .error_flag = self.error_flag, .table_counters = self.table_counters };
            }
            pub fn composition(self: *const Views) !@import("resident_native_composition_v1.zig").ForCommitments(N).Views {
                var coefficients: [N - 1][]const common.Words = undefined;
                for (self.coefficient_columns, &coefficients) |from, *to| to.* = from;
                return .{ .coefficients = coefficients, .draws = try self.relations.cast(u32), .claims = try self.claims.cast(u32), .alpha = try self.composition_alpha.cast(u32), .error_flag = self.error_flag, .twiddles_forward = self.twiddles_forward, .twiddles_inverse = self.twiddles_inverse, .composition_coefficients = self.commits[N - 1].coefficients };
            }
            pub fn deinit(self: *Views) void {
                for (self.sources) |s| self.allocator.free(s);
                for (self.coefficient_columns) |s| self.allocator.free(s);
                for (self.evaluation_columns) |s| self.allocator.free(s);
                self.* = undefined;
            }
        };
        pub fn bind(a: std.mem.Allocator, tx: *cuda.runtime.proof_transaction.ResidentProofTransaction, program: *const Program.Owned, pcs: *const PCS.Plans, terminal: *const Terminal.Bundle, raw_input_words: usize) !Views {
            try Terminal.requireBundle(program, pcs, terminal);
            const b = Binder{ .tx = tx };
            const forward = try b.words(.twiddles_forward, 0);
            const inverse = try b.words(.twiddles_inverse, 0);
            var sources: [N - 1][]common.Words = undefined;
            var coeff: [N - 1][]common.Words = undefined;
            var eval: [N - 1][]common.Words = undefined;
            var owned: usize = 0;
            errdefer for (0..owned) |i| {
                a.free(sources[i]);
                a.free(coeff[i]);
                a.free(eval[i]);
            };
            for (0..N - 1) |tree| {
                const n = pcs.commitments[tree].column_logs.len;
                const s = try a.alloc(common.Words, n);
                errdefer a.free(s);
                const c = try a.alloc(common.Words, n);
                errdefer a.free(c);
                const e = try a.alloc(common.Words, n);
                sources[tree] = s;
                coeff[tree] = c;
                eval[tree] = e;
                owned += 1;
            }
            var commits: [N]Commit.Buffers = undefined;
            for (pcs.commitments, &commits, 0..) |plan, *out, tree| {
                out.* = .{ .coefficients = try b.words(.commit_coefficients, tree), .evaluations = try b.words(.commit_evaluations, tree), .column_logs = try b.words(.commit_logs, tree), .merkle_hashes = try b.as(field.Blake2sHash, .commit_hashes, tree), .merkle_layers = try b.as(field.MerkleLayerDescriptor, .commit_layers, tree), .forward_twiddles = forward, .inverse_twiddles = inverse };
                try out.validate(&plan);
                if (tree < N - 1) for (plan.cohorts) |cohort| for (0..cohort.count) |local| {
                    const index = cohort.first_column + local;
                    sources[tree][index] = try b.words(sourceKind(tree), sourceOrdinal(tree, index));
                    coeff[tree][index] = try out.coefficients.sub(cohort.coefficient_offset + local * pow(cohort.trace_log), pow(cohort.trace_log));
                    eval[tree][index] = try out.evaluations.sub(cohort.evaluation_offset + local * pow(cohort.evaluation_log), pow(cohort.evaluation_log));
                };
            }
            var tables: [6]common.Words = undefined;
            for (&tables, 0..) |*t, i| t.* = try b.words(.interaction_geometry, i);
            return .{ .table_counters = tables, .allocator = a, .sources = sources, .coefficient_columns = coeff, .evaluation_columns = eval, .commits = commits, .raw_input = try (try b.words(.values, 0)).sub(0, raw_input_words), .twiddles_forward = forward, .twiddles_inverse = inverse, .transcript = .{ .state = try b.as(cuda.abi.stages.blake3.Channel, .transcript_state, 0), .static_words = try b.words(.transcript_config, 0) }, .relations = try b.as(field.SecureField, .interaction_drawn, 0), .claims = try (try (try b.words(.interaction_claims, 0)).sub(0, 4 * program.view().physical_claim_count)).cast(field.SecureField), .composition_alpha = try b.as(field.SecureField, .composition_alpha, 0), .oods = .{ .parameter = try b.as(field.SecureField, .oods_parameter, 0), .offset_points = try b.as(field.CirclePointBaseField, .oods_offsets, 0), .fold_counts = try b.words(.oods_folds, 0), .output_indices = try b.words(.oods_indices, 0), .sample_points = try b.as(field.SecureCirclePoint, .oods_sample_points, 0), .evaluation_points = try b.as(field.SecureCirclePoint, .oods_evaluation_points, 0), .folding_factors = try b.as(field.SecureField, .oods_factors, 0), .reduce_a = try b.as(field.SecureField, .oods_reduce_a, 0), .reduce_b = try b.as(field.SecureField, .oods_reduce_b, 0), .sampled_values = try b.as(field.SecureField, .oods_values, 0) }, .quotient = try OldBinding.bindQuotient(&b, pcs.geometry.fri_input_log), .fri = try OldBinding.bindFri(&b, &pcs.fri), .decommit = try OldBinding.bindDecommit(&b), .proof = try shared.resident_proof_binding.bindAt(shared.proof_bundle, tx, try id(.terminal_bundle, 0), 0, .{ .proof = terminal.* }), .nonce = try b.as(u64, .pow_nonce, 0), .error_flag = try b.words(.error_flag, 0) };
        }
        fn sourceKind(tree: usize) Kind {
            if (tree == 0) return .preprocessed_source;
            if (tree == 1) return .base_source;
            if (tree == N - 2) return .interaction_source;
            if (N == 5 and tree == 2) return .values;
            unreachable;
        }
        fn sourceOrdinal(tree: usize, column: usize) usize {
            return column + @intFromBool(N == 5 and tree == 2);
        }
        fn pow(log: u32) usize {
            return @as(usize, 1) << @intCast(log);
        }
        fn mul(a: usize, b: usize) !usize {
            return std.math.mul(usize, a, b);
        }
    };
}
