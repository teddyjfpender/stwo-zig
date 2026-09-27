//! Canonical lightweight ROM census with versioned fused projection identity.
//! The existing host census is shared; no second commitment or fetch count.
const Memory = @import("block_execution_sidecar_batch_v2.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Census = @import("block_v5_program_census_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Seal = @import("block_v5_source_seal_v1.zig");
pub fn ForCapacity(comptime capacity: bool) type {
    return struct {
        const Source = if (capacity) @import("block_v5_native_capacity_fused_source_v1.zig") else @import("block_v5_native_projection_fused_source_v1.zig");
        const Fused = if (capacity) @import("block_v5_native_capacity_fused_proof_v1.zig") else @import("block_v5_native_projection_fused_proof_v2.zig");
        pub fn add(self: anytype, fetches: []const Census.Fetch, statement: *const Shape, template_id: [32]u8, instance_id: [32]u8, roots: Seal.Roots, request_roots: Seal.Roots, external_retirements: u32, register_custody_mode: u32, frame: Frame, witness_root: [32]u8) !void {
            // Validate/allocate before mutating shared census bookkeeping. Once add
            // succeeds, the pure ID replacement below cannot fail or double-count.
            const slots = try Source.slotsFromShapeForMode(self.allocator, statement, external_retirements, register_custody_mode);
            defer self.allocator.free(slots);
            const memory_slots = if (capacity) try Source.memorySlots(self.allocator, statement, external_retirements, frame, register_custody_mode) else try Memory.slotsFromStatementForMode(self.allocator, statement, frame, register_custody_mode);
            defer self.allocator.free(memory_slots);
            const index = self.next;
            const projection = Fused.entry(template_id, instance_id, roots, witness_root, index, frame, slots, memory_slots);
            try @import("block_v5_program_lightweight_first_round_v1.zig").add(self, fetches, statement, template_id, instance_id, roots, request_roots);
            self.request_entries[index] = projection;
        }
    };
}
