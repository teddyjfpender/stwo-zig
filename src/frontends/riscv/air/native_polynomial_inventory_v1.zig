//! Offline inventory exported from the actual native AIR capabilities.
//! Program ownership stays here until emission; no witness, proof or device runs.
const std = @import("std");
const core = @import("stwo_core");
const semantic_eval = @import("semantic_eval.zig");
const batching = @import("lang/lookup_batch_execution.zig");
const polynomial_v2 = @import("lang/lookup_polynomial_program_v2.zig");
const trace = @import("../runner/trace.zig");
const semantic = @import("semantic_component.zig");
const opcode = @import("lookups/opcode_component.zig");
const entries = @import("lookups/opcode_entries.zig");
const relations_mod = @import("relation_challenges.zig");

pub fn Inventory(comptime codegen: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        base: std.ArrayList(codegen.base.Entry) = .empty,
        lookup: std.ArrayList(codegen.lookup.Entry) = .empty,
        lookup_v2: std.ArrayList(codegen.lookup_v2.Entry) = .empty,

        pub fn init(a: std.mem.Allocator) !Self {
            var result = Self{ .allocator = a };
            errdefer result.deinit();
            try result.appendNative(false);
            const hash_program = @import("memory_commitment/hash_runtime_program.zig");
            for (0..hash_program.DIRECT_PARTITION_COUNT) |partition| {
                var program = try hash_program.buildPoseidonDirectRange(a, .narrow_memory, hash_program.directPartitionRange(.narrow_memory, partition));
                errdefer program.deinit();
                try result.base.append(a, .{ .program_id = (@as(u64, 3) << 32) | @as(u64, @intCast(partition)), .program = program });
            }
            {
                var program = try hash_program.buildPoseidonLookups(a);
                errdefer program.deinit();
                try result.lookup.append(a, .{ .program_id = (@as(u64, 4) << 32) | 1, .program = program });
            }
            var candidate = try @import("lang/typed_poseidon2_degree_bounded_candidate.zig").Candidate.init(a, .degree5);
            defer candidate.deinit();
            const degree5 = @import("lang/typed_poseidon2_degree5_backend.zig");
            for (0..degree5.DIRECT_PARTITION_COUNT) |partition| {
                var program = try degree5.exportDirectProgram(a, &candidate, degree5.directPartitionRange(partition));
                errdefer program.deinit();
                try result.base.append(a, .{ .program_id = (@as(u64, 5) << 32) | @as(u64, @intCast(partition)), .program = program });
            }
            {
                var program = try degree5.exportLookupProgram(a, &candidate);
                errdefer program.deinit();
                try result.lookup.append(a, .{ .program_id = (@as(u64, 6) << 32) | 1, .program = program });
            }
            // Retained protocols stay available. The explicit new recipe is admitted
            // independently, without activating its statement or custody policy.
            try result.appendNative(true);
            try result.validateProgramIds();
            return result;
        }

        pub fn deinit(self: *Self) void {
            for (self.base.items) |*item| item.program.deinit();
            for (self.lookup.items) |*item| item.program.deinit();
            for (self.lookup_v2.items) |*item| item.program.deinit();
            self.base.deinit(self.allocator);
            self.lookup.deinit(self.allocator);
            self.lookup_v2.deinit(self.allocator);
            self.* = undefined;
        }

        fn appendNative(self: *Self, local_zero: bool) !void {
            const a = self.allocator;
            // Exporting programs never consults these concrete relation values.
            // Use initialized values rather than an invalid/dangling context pointer.
            const relations = relations_mod.Relations.dummy();
            for (0..trace.N_FAMILIES) |family_index| {
                const family: trace.OpcodeFamily = @enumFromInt(family_index);
                if (!semantic_eval.isTraceCompatible(family)) continue;
                const component = if (local_zero)
                    try semantic.SemanticComponent.initLocalZero(family, 2, 0, 0)
                else
                    try semantic.SemanticComponent.init(family, 2, 0, 0);
                const exported = component.asProverComponent();
                const capability = exported.backend_composition_capability.?.base_polynomial_v1;
                {
                    var program = try capability.export_program(exported.ctx, a);
                    errdefer program.deinit();
                    if (program.column_count != capability.main_column_count + 1) return error.InvalidNativePolynomialInventory;
                    try self.base.append(a, .{ .program_id = capability.program_id, .program = program });
                }
                const claims = [_]core.fields.qm31.QM31{core.fields.qm31.QM31.zero()} ** @import("lookups/entry.zig").MAX_BATCHES;
                const n_batches = entries.batchCount(family);
                const lookup_component = if (local_zero)
                    try opcode.OpcodeLookupComponent.initLocalZero(family, 2, 0, 0, 0, &relations, claims[0..n_batches])
                else
                    try opcode.OpcodeLookupComponent.initProver(family, 2, 0, 0, 0, &relations, claims[0..n_batches]);
                const lookup_exported = lookup_component.asProverComponent();
                const lookup_capability = lookup_exported.backend_composition_capability.?.lookup_polynomial_v1;
                {
                    var program = try lookup_capability.export_program(lookup_exported.ctx, a);
                    errdefer program.deinit();
                    if (program.column_count != lookup_capability.main_column_count or 4 * program.batchCount() != lookup_capability.interaction_column_count) return error.InvalidNativePolynomialInventory;
                    try self.lookup.append(a, .{ .program_id = lookup_capability.program_id, .program = program });
                }
                if (local_zero) continue; // V2 is a separately authenticated recipe.
                var plan = try batching.FamilyPlan.initNativeV1(a, family);
                defer plan.deinit();
                var selected = try polynomial_v2.lowerSelected(a, &plan);
                errdefer selected.deinit();
                try self.lookup_v2.append(a, .{ .authority = try selected.authority(), .program = selected });
            }
        }

        /// Runtime caches index base/compatibility programs by program_id. Distinct
        /// recipes must not alias even when content-addressed kernel names differ.
        pub fn validateProgramIds(self: *const Self) !void {
            for (self.base.items, 0..) |item, i| {
                for (self.base.items[0..i]) |earlier| if (item.program_id == earlier.program_id) return error.DuplicateBasePolynomialProgramId;
            }
            for (self.lookup.items, 0..) |item, i| {
                for (self.lookup.items[0..i]) |earlier| if (item.program_id == earlier.program_id) return error.DuplicateLookupPolynomialProgramId;
            }
        }
    };
}
