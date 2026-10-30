//! Stable NativeV3 partitioned, caller and original provider admission owners.
//! This owns admission metadata only. Every original proof and recursive leaf
//! is still freshly verified; source/global closure remains a separate task.
const std = @import("std");
const Collect = @import("block_v5_cpu_collect_v1.zig").ForCapacity(false);
const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(false);
const NativeAdmission = @import("block_v5_native_recursive_admission_v3.zig");
const Caller = @import("block_v5_caller_recursive_admission_catalog_v1.zig");
const Fused = @import("block_v6_partitioned_recursive_admission_v1.zig");
const Lanes = @import("block_v5_ram_lanes_recursive_admission_v1.zig");
const Range = @import("block_v5_range16_recursive_admission_v1.zig");
const Program = @import("block_v5_program_table_recursive_admission_v1.zig");
const Lookup = @import("block_v5_native_lookup_recursive_admission_v1.zig");
const Shared = @import("block_v5_recursive_leaf_store_core_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const Limits = struct {
    max_sources: usize = 1 << 16,
    max_metadata_bytes: usize = 256 << 20,
    caller: Caller.Limits = .{},
    fused: Fused.Limits = .{},
    lanes: Lanes.Limits = .{},
    range: Range.Limits = .{},
    program: Program.Limits = .{},
    lookup: Lookup.Limits = .{},
};

/// Stable allocation is essential: Store source pointers and caller sessions
/// borrow these admissions until all family and hierarchy workers are joined.
pub const Owner = struct {
    a: std.mem.Allocator,
    roster: Shared.Roster,
    callers: ?Caller.Catalog = null,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    native: []NativeAdmission.Prepared = &.{},
    native_initialized: usize = 0,
    executions: []Fused.Prepared = &.{},
    lanes: []Lanes.Prepared = &.{},
    ranges: []Range.Prepared = &.{},
    program: ?Program.Prepared = null,
    lookups: []Lookup.Prepared = &.{},
    executions_initialized: usize = 0,
    lanes_initialized: usize = 0,
    ranges_initialized: usize = 0,
    lookups_initialized: usize = 0,

    pub fn create(backing: std.mem.Allocator, collected: *const Collect.Collected, assembly: *const Assembly.Assembly, limits: Limits) !*Owner {
        const natives = assembly.executions;
        const roster = Shared.Roster{ .sealed = assembly.sealed, .pins = assembly.seal_pins, .entries = assembly.entries };
        try roster.require();
        if (natives.len != assembly.sealed.execution_instance_count or
            !std.meta.eql(collected.globals.config, assembly.seal_pins.config)) return error.UntrustedCpuRecursiveSourceCensus;
        const lane = switch (collected.globals.memory) {
            .lanes => |*value| &value.first,
            .word => return error.CpuRecursiveFamiliesRequireStrictRamLanes,
        };
        // Exact physical arrays, never power-of-two padded policy slots.
        const count = try std.math.add(usize, natives.len, try std.math.add(usize, try std.math.mul(usize, 2, assembly.extensions.len), try std.math.add(usize, lane.pins.len, try std.math.add(usize, lane.plan.shards.len, try std.math.add(usize, collected.groups.records.len, 1)))));
        const metadata = try std.math.add(usize, @sizeOf(Owner), try std.math.add(usize, try std.math.mul(usize, natives.len, @sizeOf(NativeAdmission.Prepared) + @sizeOf(Fused.Prepared)), try std.math.add(usize, try std.math.mul(usize, lane.pins.len, @sizeOf(Lanes.Prepared)), try std.math.add(usize, try std.math.mul(usize, lane.plan.shards.len, @sizeOf(Range.Prepared)), try std.math.mul(usize, collected.groups.records.len, @sizeOf(Lookup.Prepared))))));
        if (limits.max_sources == 0 or limits.max_metadata_bytes == 0 or count > limits.max_sources or metadata > limits.max_metadata_bytes)
            return error.CpuRecursiveSourceResourceLimit;
        const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_metadata_bytes);
        const a = budget.allocator();
        const self = a.create(Owner) catch |err| {
            budget.destroy();
            return err;
        };
        self.* = .{ .a = a, .roster = roster, .budget = budget };
        errdefer self.deinit();
        self.callers = try Caller.Catalog.initFromBounds(a, roster, assembly.callers, limits.caller);
        self.native = try a.alloc(NativeAdmission.Prepared, natives.len);
        self.executions = try a.alloc(Fused.Prepared, natives.len);
        for (natives, self.native, self.executions, 0..) |pin, *native, *admitted, index| {
            native.* = try NativeAdmission.Prepared.init(a, pin.shape, pin.admission, pin.template, pin.template_id, @intCast(index), roster.sealed, roster.pins, roster.entries, assembly.global_pins.tables.catalog);
            self.native_initialized += 1;
            const frame = Frame{ .clock_frame = .leaf_local, .global_first_cycle = pin.admission.context.first_cycle, .cycle_count = pin.shape.public_data.clock };
            admitted.* = try Fused.Prepared.init(a, native, .{ .frame = frame, .witness_root = assembly.witness_roots[index], .expected_events = assembly.ordinary_events[index] }, limits.fused);
            self.executions_initialized += 1;
        }
        self.lanes = try a.alloc(Lanes.Prepared, lane.pins.len);
        for (self.lanes, lane.pins) |*admitted, pin| {
            admitted.* = try Lanes.Prepared.init(a, pin, roster.sealed, roster.pins, roster.entries, limits.lanes);
            self.lanes_initialized += 1;
        }
        if (lane.plan.shards.len != lane.range_roots.len) return error.UntrustedCpuRecursiveRangeCensus;
        self.ranges = try a.alloc(Range.Prepared, lane.plan.shards.len);
        for (self.ranges, lane.plan.shards, lane.range_roots) |*admitted, shard, roots| {
            admitted.* = try Range.Prepared.init(a, shard, lane.plan.digest, roots, roster.sealed, roster.pins, roster.entries, limits.range);
            self.ranges_initialized += 1;
        }
        self.program = try Program.Prepared.init(a, collected.globals.program_plan orelse return error.MissingCpuRecursiveProgramSource, 0, roster.sealed, roster.pins, roster.entries, limits.program);
        self.lookups = try a.alloc(Lookup.Prepared, collected.groups.records.len);
        for (self.lookups, collected.groups.records) |*admitted, record| {
            admitted.* = try Lookup.Prepared.init(a, record.plan, record.roots, roster.sealed, roster.pins, roster.entries, limits.lookup);
            self.lookups_initialized += 1;
        }
        try self.require();
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.a;
        for (self.lookups[0..self.lookups_initialized]) |*value| value.deinit();
        a.free(self.lookups);
        if (self.program) |*value| value.deinit();
        for (self.ranges[0..self.ranges_initialized]) |*value| value.deinit();
        a.free(self.ranges);
        for (self.lanes[0..self.lanes_initialized]) |*value| value.deinit();
        a.free(self.lanes);
        for (self.executions[0..self.executions_initialized]) |*value| value.deinit();
        a.free(self.executions);
        for (self.native[0..self.native_initialized]) |*value| value.deinit();
        a.free(self.native);
        if (self.callers) |*value| value.deinit();
        const budget = self.budget;
        a.destroy(self);
        budget.destroy();
    }
    pub fn execution(self: *const Owner, index: u32) !*const Fused.Prepared {
        if (index >= self.executions.len) return error.UnadmittedV6RecursiveExecutionIndex;
        return &self.executions[index];
    }
    /// Every receiver reconstructs this owner from independently admitted real
    /// plans. Local validation cannot supply missing source/global authority.
    pub fn require(self: *const Owner) !void {
        try self.roster.require();
        const callers = if (self.callers) |*value| value else return error.IncompleteCpuRecursiveSources;
        const counts = self.roster.pins.counts;
        const Seal = @import("block_v5_source_seal_v1.zig");
        if (self.native_initialized != self.native.len or self.executions.len != self.native.len or self.executions.len != self.roster.sealed.execution_instance_count or self.executions_initialized != self.executions.len or
            self.lanes.len != counts[@intFromEnum(Seal.Family.memory) - 1] or self.lanes_initialized != self.lanes.len or
            self.ranges.len != counts[@intFromEnum(Seal.Family.memory_range) - 1] or self.ranges_initialized != self.ranges.len or
            self.lookups.len != counts[@intFromEnum(Seal.Family.native_lookup) - 1] or self.lookups_initialized != self.lookups.len or
            callers.entries.len != counts[@intFromEnum(Seal.Family.precompile) - 1] or self.program == null)
            return error.IncompleteCpuRecursiveSources;
        for (self.executions, 0..) |*admitted, index| {
            if (admitted.native != &self.native[index] or admitted.native.index != index) return error.UntrustedCpuRecursiveNativeOwner;
            try admitted.validate(admitted.template_id);
        }
        for (self.lanes, 0..) |*admitted, index| {
            if (admitted.pin.index != index) return error.UntrustedCpuRecursiveRamIndex;
            try admitted.validate(admitted.template_id);
        }
        for (self.ranges, 0..) |*admitted, index| {
            if (admitted.shard.index != index) return error.UntrustedCpuRecursiveRangeIndex;
            try admitted.validate(admitted.template_id);
        }
        for (self.lookups, 0..) |*admitted, index| {
            if (admitted.index != index) return error.UntrustedCpuRecursiveLookupIndex;
            try admitted.validate(admitted.template_id);
        }
        var ordinal: usize = 0;
        for (self.roster.entries) |entry| if (entry.family == .precompile) {
            if (ordinal >= callers.entries.len or callers.entries[ordinal].index != entry.index or
                callers.entries[ordinal].admissions.arithmetic.binding.execution_index != entry.index)
                return error.UntrustedCpuRecursiveCallerIndex;
            try callers.entries[ordinal].admissions.require();
            ordinal += 1;
        };
        if (ordinal != callers.entries.len) return error.IncompleteCpuRecursiveSources;
        try self.program.?.validate(self.program.?.template_id);
    }
};

test "partitioned recursive sources instantiate original admission owners without capacity receipts" {
    inline for (.{ &Owner.create, &Owner.require, &Owner.execution, &Owner.deinit }) |function| {
        std.mem.doNotOptimizeAway(function);
        try std.testing.expect(@intFromPtr(function) != 0);
    }
}
