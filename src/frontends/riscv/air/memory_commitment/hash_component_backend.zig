//! Cold backend-capability projection for the mixed Poseidon component.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const poseidon2_air = @import("poseidon2_air.zig");
const runtime_program = @import("hash_runtime_program.zig");

pub fn Namespace(comptime HashComponent: type) type {
    return struct {
        pub fn capability() prover_component.BackendCompositionCapability {
            return .{ .base_lookup_polynomial_v1 = .{
                .export_capabilities = exportCapabilities,
            } };
        }

        fn exportCapabilities(
            ctx: *const anyopaque,
        ) !prover_component.BaseLookupPolynomialCapabilitiesV1 {
            const self: *const HashComponent = @ptrCast(@alignCast(ctx));
            if (self.kind != .poseidon2) return error.InvalidHashRuntimeProgram;
            const mode: runtime_program.DirectMode = switch (self.poseidon_shell) {
                .narrow_memory => .narrow_memory,
                .universal => .universal,
            };
            const direct_count = runtime_program.directConstraintCount(mode);
            var result = prover_component.BaseLookupPolynomialCapabilitiesV1{
                .base_partition_count = runtime_program.DIRECT_PARTITION_COUNT,
                .lookup = .{
                    .program_id = (@as(u64, 4) << 32) | 1,
                    .trace_log_size = self.log_size,
                    .selector_tree_index = 0,
                    .selector_column = self.is_first_col_idx,
                    .main_tree_index = 1,
                    .first_main_column = self.main_col_offset,
                    .main_column_count = poseidon2_air.N_MAIN_COLUMNS,
                    .interaction_tree_index = 2,
                    .first_interaction_column = self.interaction_col_offset,
                    .interaction_column_count = poseidon2_air.N_INTERACTION_COLUMNS,
                    .export_program = exportLookupProgram,
                    .export_parameters = exportParameters,
                },
                .lookup_constraints = .{
                    .start = direct_count,
                    .count = poseidon2_air.N_SUMS,
                },
            };
            const exporters = [_]*const fn (
                *const anyopaque,
                std.mem.Allocator,
            ) anyerror!prover_component.OwnedBasePolynomialProgram{
                exportDirectProgram0,
                exportDirectProgram1,
                exportDirectProgram2,
                exportDirectProgram3,
            };
            for (0..runtime_program.DIRECT_PARTITION_COUNT) |partition| {
                result.base_partitions[partition] = .{
                    .capability = .{
                        .program_id = (@as(u64, 3) << 32) |
                            (@as(u64, @intFromEnum(self.poseidon_shell)) << 8) |
                            @as(u64, @intCast(partition)),
                        .trace_log_size = self.log_size,
                        .selector_tree_index = 0,
                        .selector_column = switch (self.poseidon_shell) {
                            .narrow_memory => self.is_active_col_idx,
                            .universal => self.is_first_col_idx,
                        },
                        .main_tree_index = 1,
                        .first_main_column = self.main_col_offset,
                        .main_column_count = poseidon2_air.N_MAIN_COLUMNS,
                        .export_program = exporters[partition],
                    },
                    .constraints = runtime_program.directPartitionRange(mode, partition),
                };
            }
            return result;
        }

        fn exportDirectProgramFor(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
            comptime partition: usize,
        ) !prover_component.OwnedBasePolynomialProgram {
            const self: *const HashComponent = @ptrCast(@alignCast(ctx));
            if (self.kind != .poseidon2) return error.InvalidHashRuntimeProgram;
            const mode: runtime_program.DirectMode = switch (self.poseidon_shell) {
                .narrow_memory => .narrow_memory,
                .universal => .universal,
            };
            return runtime_program.buildPoseidonDirectRange(
                allocator,
                mode,
                runtime_program.directPartitionRange(mode, partition),
            );
        }

        fn exportDirectProgram0(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
            return exportDirectProgramFor(ctx, allocator, 0);
        }
        fn exportDirectProgram1(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
            return exportDirectProgramFor(ctx, allocator, 1);
        }
        fn exportDirectProgram2(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
            return exportDirectProgramFor(ctx, allocator, 2);
        }
        fn exportDirectProgram3(ctx: *const anyopaque, allocator: std.mem.Allocator) !prover_component.OwnedBasePolynomialProgram {
            return exportDirectProgramFor(ctx, allocator, 3);
        }

        fn exportLookupProgram(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) !prover_component.OwnedLookupPolynomialProgram {
            const self: *const HashComponent = @ptrCast(@alignCast(ctx));
            if (self.kind != .poseidon2) return error.InvalidHashRuntimeProgram;
            return runtime_program.buildPoseidonLookups(allocator);
        }

        fn exportParameters(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) ![]QM31 {
            const self: *const HashComponent = @ptrCast(@alignCast(ctx));
            if (self.kind != .poseidon2) return error.InvalidHashRuntimeProgram;
            return runtime_program.poseidonParameters(
                allocator,
                self.relations,
                &self.poseidon_claims,
            );
        }
    };
}
