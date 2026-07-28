const std = @import("std");

const arena_plan = @import("../arena_plan.zig");
const recovery = @import("../recovery.zig");
const runtime = @import("../runtime.zig");
const telemetry = @import("../telemetry.zig");

pub const RelationInstanceBindings = struct {
    rows: u32,
    real_rows: u32,
    source_offset_rows: u32 = 0,
    sources: []const arena_plan.Binding,
    descriptors: []const u32,
    outputs: []const arena_plan.Binding,
    claimed_sum: arena_plan.Binding,
};

/// Exact CommonLookupElements execution over sparse arena columns. The fused
/// fraction chain and normalized coset scan are one prepared Metal command.
pub const RelationRecipe = struct {
    allocator: std.mem.Allocator,
    metal: *runtime.Runtime,
    arena: *arena_plan.ResidentArena,
    destinations: []arena_plan.Binding,
    prepared: runtime.RelationPlan,
    last_tick: ?u16 = null,
    accumulated_gpu_ms: f64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        metal: *runtime.Runtime,
        resident_arena: *arena_plan.ResidentArena,
        instances: []const RelationInstanceBindings,
        alpha_powers: arena_plan.Binding,
        z: arena_plan.Binding,
        scan_scratch: arena_plan.Binding,
    ) !RelationRecipe {
        if (instances.len == 0 or alpha_powers.offset_bytes % 4 != 0 or z.offset_bytes % 4 != 0 or
            scan_scratch.offset_bytes % 4 != 0 or z.size_bytes < 16)
            return recovery.RecoveryError.BindingSizeMismatch;
        var geometry = std.ArrayList(u32).empty;
        defer geometry.deinit(allocator);
        var source_offsets = std.ArrayList(u32).empty;
        defer source_offsets.deinit(allocator);
        var descriptors = std.ArrayList(u32).empty;
        defer descriptors.deinit(allocator);
        var output_offsets = std.ArrayList(u32).empty;
        defer output_offsets.deinit(allocator);
        var destinations = std.ArrayList(arena_plan.Binding).empty;
        errdefer destinations.deinit(allocator);
        var total_blocks: u32 = 0;
        var max_alpha_powers: u32 = 0;
        for (instances, 0..) |instance, instance_index| {
            if (instance.rows == 0 or !std.math.isPowerOfTwo(instance.rows) or instance.real_rows > instance.rows or
                instance.sources.len == 0 or instance.descriptors.len == 0 or instance.descriptors.len % 16 != 0)
                return recovery.RecoveryError.BindingSizeMismatch;
            const columns = instance.descriptors.len / 16;
            if (instance.outputs.len != columns * 4 or instance.claimed_sum.size_bytes < 16 or
                instance.claimed_sum.offset_bytes % 4 != 0)
                return recovery.RecoveryError.BindingSizeMismatch;
            var descriptor_index: usize = 0;
            while (descriptor_index < instance.descriptors.len) : (descriptor_index += 16) {
                const descriptor = instance.descriptors[descriptor_index .. descriptor_index + 16];
                if (descriptor[0] < 1 or descriptor[0] > 2) return recovery.RecoveryError.BindingSizeMismatch;
                max_alpha_powers = @max(max_alpha_powers, descriptor[3]);
                if (descriptor[0] == 2) max_alpha_powers = @max(max_alpha_powers, descriptor[10]);
            }
            const source_base = source_offsets.items.len;
            for (instance.sources) |binding| {
                if (binding.offset_bytes % 4 != 0 or binding.size_bytes < @as(u64, instance.rows) * 4)
                    return recovery.RecoveryError.BindingSizeMismatch;
                try source_offsets.append(allocator, std.math.cast(u32, binding.offset_bytes / 4) orelse {
                    std.debug.print("relation_source_offset_overflow instance={d} logical_id={d} offset={d} size={d}\n", .{
                        instance_index, binding.logical_id, binding.offset_bytes, binding.size_bytes,
                    });
                    return recovery.RecoveryError.BindingSizeMismatch;
                });
            }
            const descriptor_base = descriptors.items.len;
            try descriptors.appendSlice(allocator, instance.descriptors);
            const output_base = output_offsets.items.len;
            for (instance.outputs) |binding| {
                if (binding.offset_bytes % 4 != 0 or binding.size_bytes != @as(u64, instance.rows) * 4)
                    return recovery.RecoveryError.BindingSizeMismatch;
                try output_offsets.append(allocator, std.math.cast(u32, binding.offset_bytes / 4) orelse {
                    std.debug.print("relation_output_offset_overflow instance={d} logical_id={d} offset={d} size={d}\n", .{
                        instance_index, binding.logical_id, binding.offset_bytes, binding.size_bytes,
                    });
                    return recovery.RecoveryError.BindingSizeMismatch;
                });
                try destinations.append(allocator, binding);
            }
            try destinations.append(allocator, instance.claimed_sum);
            const blocks = std.math.divCeil(u32, instance.rows, 256) catch return recovery.RecoveryError.BindingSizeMismatch;
            try geometry.appendSlice(allocator, &.{
                total_blocks,
                blocks,
                instance.rows,
                @intCast(columns),
                instance.real_rows,
                instance.source_offset_rows,
                @intCast(source_base),
                @intCast(descriptor_base),
                @intCast(output_base),
                std.math.cast(u32, instance.claimed_sum.offset_bytes / 4) orelse {
                    std.debug.print("relation_claimed_sum_offset_overflow instance={d} logical_id={d} offset={d}\n", .{
                        instance_index, instance.claimed_sum.logical_id, instance.claimed_sum.offset_bytes,
                    });
                    return recovery.RecoveryError.BindingSizeMismatch;
                },
            });
            total_blocks = std.math.add(u32, total_blocks, blocks) catch return recovery.RecoveryError.BindingSizeMismatch;
        }
        if (scan_scratch.size_bytes < @as(u64, total_blocks) * 16)
            return recovery.RecoveryError.BindingSizeMismatch;
        if (alpha_powers.size_bytes < @as(u64, max_alpha_powers) * 16)
            return recovery.RecoveryError.BindingSizeMismatch;
        const alpha_offset = std.math.cast(u32, alpha_powers.offset_bytes / 4) orelse {
            std.debug.print("relation_alpha_offset_overflow offset={d}\n", .{alpha_powers.offset_bytes});
            return recovery.RecoveryError.BindingSizeMismatch;
        };
        const z_offset = std.math.cast(u32, z.offset_bytes / 4) orelse {
            std.debug.print("relation_z_offset_overflow offset={d}\n", .{z.offset_bytes});
            return recovery.RecoveryError.BindingSizeMismatch;
        };
        const scratch_offset = std.math.cast(u32, scan_scratch.offset_bytes / 4) orelse {
            std.debug.print("relation_scratch_offset_overflow offset={d} size={d}\n", .{ scan_scratch.offset_bytes, scan_scratch.size_bytes });
            return recovery.RecoveryError.BindingSizeMismatch;
        };
        var prepared = try metal.prepareRelation(
            geometry.items,
            source_offsets.items,
            descriptors.items,
            output_offsets.items,
            total_blocks,
            alpha_offset,
            z_offset,
            scratch_offset,
        );
        errdefer prepared.deinit();
        return .{
            .allocator = allocator,
            .metal = metal,
            .arena = resident_arena,
            .destinations = try destinations.toOwnedSlice(allocator),
            .prepared = prepared,
        };
    }

    pub fn deinit(self: *RelationRecipe) void {
        self.prepared.deinit();
        self.allocator.free(self.destinations);
        self.* = undefined;
    }

    pub fn makeRecipes(self: *RelationRecipe, allocator: std.mem.Allocator) ![]recovery.Recipe {
        const recipes = try allocator.alloc(recovery.Recipe, self.destinations.len);
        for (self.destinations, recipes) |binding, *recipe_entry| {
            recipe_entry.* = .{ .logical_id = binding.logical_id, .context = self, .run = run };
        }
        return recipes;
    }

    pub fn execute(self: *RelationRecipe) !void {
        self.accumulated_gpu_ms += try self.metal.relationPrepared(self.arena.buffer, self.prepared);
        telemetry.record(.metal_relation_epoch);
    }

    fn run(raw: *anyopaque, tick: u16, requested: arena_plan.Binding, _: []u8) !void {
        const self: *RelationRecipe = @ptrCast(@alignCast(raw));
        if (self.last_tick == tick) return;
        var found = false;
        for (self.destinations) |binding| found = found or binding.logical_id == requested.logical_id;
        if (!found) return recovery.RecoveryError.MissingRecipe;
        try self.execute();
        self.last_tick = tick;
    }
};
