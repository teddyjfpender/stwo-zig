//! Backend-neutral DAGs recorded from the same compact Poseidon AIR used by
//! native and recursive verification. Device activation also requires these
//! programs in the authenticated AOT inventory.
const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const component = @import("stwo_prover_engine").air.component_prover;
const symbolic = @import("../extract/symbolic.zig");
const runtime = @import("../extract/runtime_program.zig");
const legacy_runtime = @import("hash_runtime_program.zig");
const Narrow = Factory(@import("poseidon2_narrow_degree3_v1.zig"), 0x5032_4e31_0000_0000);
pub const Universal = Factory(@import("poseidon2_universal_degree3_v1.zig"), 0x5032_5531_0000_0000);
// Preserve the admitted narrow program IDs and public API.
pub const DIRECT_PARTITION_COUNT = Narrow.DIRECT_PARTITION_COUNT;
pub const DIRECT_PROGRAM_ID = Narrow.DIRECT_PROGRAM_ID;
pub const LOOKUP_PROGRAM_ID = Narrow.LOOKUP_PROGRAM_ID;
pub const directRange = Narrow.directRange;
pub const buildDirect = Narrow.buildDirect;
pub const buildLookup = Narrow.buildLookup;
pub const Namespace = Narrow.Namespace;

fn Factory(comptime air: type, comptime program_id: u64) type {
    return struct {
        const Self = @This();
        const binds_active = if (@hasDecl(air, "BINDS_ACTIVE_SELECTOR")) air.BINDS_ACTIVE_SELECTOR else true;
        pub const DIRECT_PARTITION_COUNT: usize = 4;
        pub const DIRECT_PROGRAM_ID: u64 = program_id;
        pub const LOOKUP_PROGRAM_ID: u64 = program_id | 0x100;

        pub fn directRange(partition: usize) !component.ComponentConstraintRangeV1 {
            if (partition >= Self.DIRECT_PARTITION_COUNT) return error.InvalidPoseidonNarrowPartitionV1;
            const start = air.N_CONSTRAINTS * partition / Self.DIRECT_PARTITION_COUNT;
            return .{ .start = start, .count = air.N_CONSTRAINTS * (partition + 1) / Self.DIRECT_PARTITION_COUNT - start };
        }

        pub fn buildDirect(allocator: std.mem.Allocator, partition: usize) !component.OwnedBasePolynomialProgram {
            const range = try Self.directRange(partition);
            var arena = symbolic.Arena.init(allocator);
            defer arena.deinit();
            symbolic.begin(&arena);
            defer symbolic.end();
            var main: [air.N_MAIN_COLUMNS]symbolic.Scalar = undefined;
            for (&main) |*column| column.* = arena.column("main");
            const active = arena.column("selector");
            const constraints = if (binds_active) air.evaluateGeneric(symbolic.Scalar, main, active) else air.evaluateGeneric(symbolic.Scalar, main);
            return runtime.ownDirectProgram(allocator, &arena, constraints[range.start..][0..range.count], air.N_MAIN_COLUMNS);
        }

        pub fn buildLookup(allocator: std.mem.Allocator) !component.OwnedLookupPolynomialProgram {
            var arena = symbolic.Arena.init(allocator);
            defer arena.deinit();
            symbolic.begin(&arena);
            defer symbolic.end();
            var main: [air.N_MAIN_COLUMNS]symbolic.Scalar = undefined;
            for (&main) |*column| column.* = arena.column("main");
            var entries = air.entriesGeneric(symbolic.Scalar, main);
            return runtime.ownLookupProgram(allocator, &arena, &entries, air.N_MAIN_COLUMNS);
        }

        pub fn Namespace(comptime Component: type) type {
            return struct {
                pub fn capability() component.BackendCompositionCapability {
                    return .{ .base_lookup_polynomial_v1 = .{ .export_capabilities = exportCapabilities } };
                }
                fn exportCapabilities(context: *const anyopaque) !component.BaseLookupPolynomialCapabilitiesV1 {
                    const self: *const Component = @ptrCast(@alignCast(context));
                    try self.validate();
                    var result = component.BaseLookupPolynomialCapabilitiesV1{
                        .base_partition_count = Self.DIRECT_PARTITION_COUNT,
                        .lookup = .{ .program_id = Self.LOOKUP_PROGRAM_ID, .trace_log_size = self.log_size, .selector_tree_index = 0, .selector_column = self.is_first_col_idx, .main_tree_index = 1, .first_main_column = self.main_col_offset, .main_column_count = air.N_MAIN_COLUMNS, .interaction_tree_index = 2, .first_interaction_column = self.interaction_col_offset, .interaction_column_count = air.N_INTERACTION_COLUMNS, .export_program = exportLookup, .export_parameters = exportParameters },
                        .lookup_constraints = .{ .start = air.N_CONSTRAINTS, .count = air.N_SUMS },
                    };
                    inline for (0..Self.DIRECT_PARTITION_COUNT) |partition| {
                        result.base_partitions[partition] = .{
                            .capability = .{ .program_id = Self.DIRECT_PROGRAM_ID | partition, .trace_log_size = self.log_size, .selector_tree_index = 0, .selector_column = if (binds_active) self.is_active_col_idx else self.is_first_col_idx, .main_tree_index = 1, .first_main_column = self.main_col_offset, .main_column_count = air.N_MAIN_COLUMNS, .export_program = DirectExporter(partition).exportProgram },
                            .constraints = try Self.directRange(partition),
                        };
                    }
                    return result;
                }
                fn DirectExporter(comptime partition: usize) type {
                    return struct {
                        fn exportProgram(context: *const anyopaque, allocator: std.mem.Allocator) !component.OwnedBasePolynomialProgram {
                            const self: *const Component = @ptrCast(@alignCast(context));
                            try self.validate();
                            return Self.buildDirect(allocator, partition);
                        }
                    };
                }
                fn exportLookup(context: *const anyopaque, allocator: std.mem.Allocator) !component.OwnedLookupPolynomialProgram {
                    const self: *const Component = @ptrCast(@alignCast(context));
                    try self.validate();
                    return Self.buildLookup(allocator);
                }
                fn exportParameters(context: *const anyopaque, allocator: std.mem.Allocator) ![]QM31 {
                    const self: *const Component = @ptrCast(@alignCast(context));
                    try self.validate();
                    // The relation entries and two claims deliberately preserve the
                    // exact legacy order, so their parameter authority is shared.
                    return legacy_runtime.poseidonParameters(allocator, self.relations, &self.claims);
                }
            };
        }
    };
}
