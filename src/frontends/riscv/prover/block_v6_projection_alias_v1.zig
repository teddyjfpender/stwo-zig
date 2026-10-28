//! Exact common-subexpression elimination, only inside a fresh joint STARK.
//! No aggregate, sampled value or unverified receipt establishes an alias.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Shape = @import("../air/statement.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Interaction = @import("../air/lookups/opcode_interaction.zig");

pub fn claim(a: std.mem.Allocator, shape: *const Shape.Blake3ExecutionStatement, claims: *const Shape.RiscVInteractionClaim, slot: Source.Slot) !?Q {
    var cache = Cache{};
    defer cache.deinit();
    return cache.claim(a, shape, claims, slot);
}

/// Canonical slots group by family; avoid rebuilding the symbolic DAG for
/// every projection while deriving exactly the same independent identities.
pub const Cache = struct {
    plan: ?Interaction.Plan = null,
    pub fn deinit(self: *@This()) void {
        if (self.plan) |*plan| plan.deinit();
        self.* = .{};
    }
    pub fn claim(self: *@This(), a: std.mem.Allocator, shape: *const Shape.Blake3ExecutionStatement, claims: *const Shape.RiscVInteractionClaim, slot: Source.Slot) !?Q {
        // The x0 recipe changes three weights per register effect. It needs its
        // own identity proof, not an accidental match to the old entry ordinals.
        if (shape.localZeroCustody()) return null;
        var offset: usize = 0;
        for (shape.component_descs[0..shape.n_components], 0..) |desc, index| {
            defer offset += desc.n_columns;
            if (offset != slot.main_offset) continue;
            if (desc.n_columns != slot.width or desc.log_size != slot.log_size or desc.n_rows != slot.n_rows)
                return error.InvalidProjectionAliasGeometry;
            if (self.plan) |*plan| if (plan.family != desc.family) {
                plan.deinit();
                self.plan = null;
            };
            if (self.plan == null) self.plan = try Interaction.Plan.init(a, desc.family);
            const selected = try batchFor(self.plan.?, slot);
            if (selected) |batch| return (try claims.opcodeClaims(desc.family, index))[batch];
            return null;
        }
        for (shape.infra_descs[0..shape.n_infra], 0..) |desc, index| {
            defer offset += desc.n_columns;
            if (offset != slot.main_offset) continue;
            if (desc.kind != .clock_update or desc.n_columns != slot.width or desc.log_size != slot.log_size or desc.n_rows != slot.n_rows)
                return error.InvalidProjectionAliasGeometry;
            // The native clock batch is unweighted. A mode-one RAM/register
            // partition multiplies its numerator by space or (1-space).
            const lookup = switch (slot.kind) {
                .program => return null,
                .lookup => |v| v,
            };
            if (std.meta.activeTag(lookup.source) != .clock or lookup.register_custody_mode != 0 or
                lookup.partition != .clock_memory_access or lookup.entry_count != 2 or
                !std.meta.eql(lookup.entries, [2]u8{ 0, 1 })) return null;
            return try claims.infraClaim(.clock_update, index, 0);
        }
        return error.InvalidProjectionAliasGeometry;
    }
};

/// An identity over symbolic typed entries, not a comparison at zero witness.
/// Returning null means the original companion equation must still be proved.
pub fn batchFor(plan: Interaction.Plan, slot: Source.Slot) !?usize {
    var ordinals: [2]usize = undefined;
    var count: usize = 0;
    switch (slot.kind) {
        .program => |family| {
            if (family != plan.family) return error.InvalidProjectionAliasGeometry;
            for (plan.domains[0..plan.program.entries.len], 0..) |domain, i| if (domain == .program_access) {
                if (count != 0) return error.InvalidProjectionAliasProgram;
                ordinals[0] = i;
                count = 1;
            };
        },
        .lookup => |lookup| {
            const family = switch (lookup.source) {
                .clock => return null,
                .opcode => |f| f,
            };
            if (family != plan.family) return error.InvalidProjectionAliasGeometry;
            count = lookup.entry_count;
            if (count == 0 or count > 2) return error.InvalidProjectionAliasEntry;
            for (lookup.entries[0..count], 0..) |ordinal, i| {
                if (ordinal >= plan.program.entries.len) return error.InvalidProjectionAliasEntry;
                const domain = plan.domains[ordinal];
                const matches = switch (lookup.partition) {
                    .registers_state => domain == .registers_state,
                    .register_memory_access => domain == .memory_access,
                    .bitwise => domain == .bitwise,
                    .range_check_20 => domain == .range_check_20,
                    .range_check_8_11 => domain == .range_check_8_11,
                    .range_check_8_8_4 => domain == .range_check_8_8_4,
                    .range_check_8_8 => domain == .range_check_8_8,
                    .range_check_m31 => domain == .range_check_m31,
                    else => false,
                };
                if (!matches) return null;
                if (domain == .memory_access and lookup.register_custody_mode == 1) {
                    const space = plan.program.nodes[plan.program.entries[ordinal].values[0]];
                    // Only the polynomial constant zero makes (1-space)
                    // identically one. A load/store witness value is not enough.
                    if (space.op != .constant or space.value != 0) return null;
                }
                ordinals[i] = ordinal;
            }
        },
    }
    if (count == 0 or plan.program.batch_size == 0 or plan.program.batch_size > 2) return null;
    const first = ordinals[0];
    const size = plan.program.batch_size;
    if (first % size != 0 or count != @min(size, plan.program.entries.len - first)) return null;
    for (ordinals[0..count], 0..) |ordinal, i| if (ordinal != first + i) return null;
    return first / size;
}
