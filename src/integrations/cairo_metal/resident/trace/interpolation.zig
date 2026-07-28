//! Base-trace circle interpolation and prepared recipe ownership.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const protocol_recipes = @import("../../../../backends/metal/protocol_recipes.zig");
const fixed_table_bundle_mod = @import("stwo_cairo_frontend").witness.fixed_table_bundle;
const cairo_proof_plan = @import("stwo_cairo_frontend").proof_plan;
const M31 = @import("stwo_core").fields.m31.M31;
const schedule_bindings = @import("../../schedule_bindings.zig");
const resident_binding = @import("../binding.zig");
const resident_twiddles = @import("../twiddles.zig");
const trace_diagnostics = @import("diagnostics.zig");
const Error = @import("../errors.zig").Error;

const collectComponent = schedule_bindings.collectComponent;
const collectComponentBindingGroups = schedule_bindings.collectComponentBindingGroups;
const collectScheduleOrder = schedule_bindings.collectScheduleOrder;
const logicalId = schedule_bindings.logicalId;
const one = schedule_bindings.one;
const oneComponent = schedule_bindings.oneComponent;
const oneOrdinal = schedule_bindings.oneOrdinal;
const ordinal = schedule_bindings.ordinal;
const purpose = schedule_bindings.purpose;
const twiddleBankBinding = resident_twiddles.twiddleBankBinding;
const twiddleBindingForLog = resident_twiddles.twiddleBindingForLog;
const twiddleOffsetForLog = resident_twiddles.twiddleOffsetForLog;
const wordOffset = resident_binding.wordOffset;

pub const RecordedBaseInterpolationBatch = struct {
    allocator: std.mem.Allocator,
    resident_arena: *arena_plan.ResidentArena,
    recipes: []protocol_recipes.CircleIfftRecipe,
    ec_op_recipe: ?protocol_recipes.CircleIfftRecipe,
    ec_op_owner: ?u32,

    pub fn deinit(self: *RecordedBaseInterpolationBatch) void {
        if (self.ec_op_recipe) |*recipe| recipe.deinit();
        for (self.recipes) |*recipe| recipe.deinit();
        self.allocator.free(self.recipes);
        self.* = undefined;
    }

    pub fn resetForRequest(self: *RecordedBaseInterpolationBatch) void {
        for (self.recipes) |*recipe| recipe.resetForRequest();
        if (self.ec_op_recipe) |*recipe| recipe.resetForRequest();
    }

    pub fn executeIndex(self: *RecordedBaseInterpolationBatch, component_index: u32) !f64 {
        if (component_index >= self.recipes.len) return Error.InvalidCardinality;
        var gpu_ms: f64 = 0;
        const recipe = &self.recipes[component_index];
        const initial = recipe.accumulated_gpu_ms;
        try recipe.execute();
        gpu_ms += recipe.accumulated_gpu_ms - initial;
        return gpu_ms;
    }

    pub fn interpolateEcOp(self: *RecordedBaseInterpolationBatch, component_index: u32) !f64 {
        if (self.ec_op_owner == null or self.ec_op_owner.? != component_index)
            return Error.InvalidCardinality;
        if (self.ec_op_recipe) |*ec_op| {
            const initial = ec_op.accumulated_gpu_ms;
            try ec_op.execute();
            return ec_op.accumulated_gpu_ms - initial;
        }
        return Error.MissingBinding;
    }
};

const FixedBaseTraceOperation = struct {
    allocator: std.mem.Allocator,
    component: []const u8,
    copy: metal_runtime.ArenaCopyPlan,
    interpolation: protocol_recipes.CircleIfftRecipe,

    fn init(
        allocator: std.mem.Allocator,
        component: []const u8,
        copy: metal_runtime.ArenaCopyPlan,
        interpolation: protocol_recipes.CircleIfftRecipe,
    ) !FixedBaseTraceOperation {
        return .{
            .allocator = allocator,
            .component = try allocator.dupe(u8, component),
            .copy = copy,
            .interpolation = interpolation,
        };
    }

    fn deinit(self: *FixedBaseTraceOperation) void {
        self.interpolation.deinit();
        self.copy.deinit();
        self.allocator.free(self.component);
        self.* = undefined;
    }
};

pub const NativeBaseInterpolationBatch = struct {
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    memory_address: protocol_recipes.CircleIfftRecipe,
    memory_values: []protocol_recipes.CircleIfftRecipe,
    fixed: []FixedBaseTraceOperation,

    pub fn deinit(self: *NativeBaseInterpolationBatch) void {
        for (self.fixed) |*operation| operation.deinit();
        self.allocator.free(self.fixed);
        for (self.memory_values) |*recipe| recipe.deinit();
        self.allocator.free(self.memory_values);
        self.memory_address.deinit();
        self.* = undefined;
    }

    pub fn resetForRequest(self: *NativeBaseInterpolationBatch) void {
        self.memory_address.resetForRequest();
        for (self.memory_values) |*recipe| recipe.resetForRequest();
        for (self.fixed) |*operation| operation.interpolation.resetForRequest();
    }

    pub fn interpolateMemoryAddress(self: *NativeBaseInterpolationBatch) !f64 {
        const initial = self.memory_address.accumulated_gpu_ms;
        try self.memory_address.execute();
        return self.memory_address.accumulated_gpu_ms - initial;
    }

    pub fn interpolateMemoryValues(self: *NativeBaseInterpolationBatch) !f64 {
        var gpu_ms: f64 = 0;
        for (self.memory_values) |*recipe| {
            const initial = recipe.accumulated_gpu_ms;
            try recipe.execute();
            gpu_ms += recipe.accumulated_gpu_ms - initial;
        }
        return gpu_ms;
    }

    pub fn executeFixed(
        self: *NativeBaseInterpolationBatch,
        schedule: []const std.json.Value,
        plan: arena_plan.Plan,
    ) !f64 {
        var gpu_ms: f64 = 0;
        for (self.fixed) |*operation| {
            gpu_ms += try self.metal.arenaCopyPrepared(self.resident_arena.buffer, operation.copy);
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_BASE_EVAL_DIGESTS"))
                try trace_diagnostics.logComponentBaseEvalDigests(
                    self.resident_arena,
                    schedule,
                    plan,
                    operation.component,
                );
            const initial = operation.interpolation.accumulated_gpu_ms;
            try operation.interpolation.execute();
            gpu_ms += operation.interpolation.accumulated_gpu_ms - initial;
        }
        return gpu_ms;
    }

    pub fn fixedIndex(self: NativeBaseInterpolationBatch, component: []const u8) !?u32 {
        var found: ?u32 = null;
        for (self.fixed, 0..) |operation, index| {
            if (!std.mem.eql(u8, operation.component, component)) continue;
            if (found != null) return Error.DuplicateBinding;
            found = @intCast(index);
        }
        return found;
    }

    /// Recreates only the fixed component's BaseTrace evaluations. Interaction
    /// replay consumes them immediately and does not need to rewrite the base
    /// coefficient tree.
    pub fn materializeFixed(self: *NativeBaseInterpolationBatch, component: []const u8) !f64 {
        const index = try self.fixedIndex(component) orelse return Error.MissingBinding;
        return self.metal.arenaCopyPrepared(self.resident_arena.buffer, self.fixed[index].copy);
    }
};

pub fn prepareRecordedBaseInterpolation(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    proof: *const cairo_proof_plan.CairoProofPlan,
    twiddle_storage: arena_plan.Binding,
) !RecordedBaseInterpolationBatch {
    const recipes = try allocator.alloc(protocol_recipes.CircleIfftRecipe, proof.components.len);
    var initialized: usize = 0;
    errdefer {
        for (recipes[0..initialized]) |*recipe| recipe.deinit();
        allocator.free(recipes);
    }
    while (initialized < recipes.len) : (initialized += 1) {
        const component = proof.components[initialized];
        recipes[initialized] = try prepareComponentInterpolation(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            component.name,
            twiddle_storage,
        );
    }
    const ec_op_owner = proof.componentIndex("partial_ec_mul_generic");
    var ec_op_recipe: ?protocol_recipes.CircleIfftRecipe = null;
    errdefer if (ec_op_recipe) |*recipe| recipe.deinit();
    if (ec_op_owner != null) {
        ec_op_recipe = try prepareComponentInterpolation(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            "ec_op_builtin",
            twiddle_storage,
        );
    }
    return .{
        .allocator = allocator,
        .resident_arena = resident_arena,
        .recipes = recipes,
        .ec_op_recipe = ec_op_recipe,
        .ec_op_owner = ec_op_owner,
    };
}

pub fn prepareNativeBaseInterpolation(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    fixed_bundle: fixed_table_bundle_mod.Bundle,
    twiddle_storage: arena_plan.Binding,
) !NativeBaseInterpolationBatch {
    var memory_address = try prepareComponentInterpolation(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        "memory_address_to_id",
        twiddle_storage,
    );
    errdefer memory_address.deinit();
    const memory_values = try prepareComponentInterpolationGroups(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        "memory_id_to_big",
        twiddle_storage,
    );
    errdefer {
        for (memory_values) |*recipe| recipe.deinit();
        allocator.free(memory_values);
    }

    var operations = std.ArrayList(FixedBaseTraceOperation).empty;
    errdefer {
        for (operations.items) |*operation| operation.deinit();
        operations.deinit(allocator);
    }
    for (fixed_bundle.entries) |entry| {
        const traces = collectComponent(allocator, schedule, plan, "BaseTrace", entry.component) catch |err| switch (err) {
            schedule_bindings.Error.MissingBinding => continue,
            else => return err,
        };
        defer allocator.free(traces);
        if (traces.len != entry.trace_multiplicity_columns.len or traces.len == 0)
            return Error.InvalidCardinality;
        const multiplicity = try oneComponent(schedule, plan, "FixedMultiplicity", entry.component);
        const column_bytes = @as(u64, entry.row_count) * 4;
        if (multiplicity.size_bytes != column_bytes * entry.multiplicity_columns)
            return Error.InvalidBindingSize;
        const ranges = try allocator.alloc(metal_runtime.ArenaCopyRange, traces.len);
        defer allocator.free(ranges);
        for (entry.trace_multiplicity_columns, traces, ranges) |source_column, trace, *range| {
            if (trace.size_bytes != column_bytes) return Error.InvalidBindingSize;
            const source_bytes = multiplicity.offset_bytes + @as(u64, source_column) * column_bytes;
            if (source_bytes % 4 != 0 or trace.offset_bytes % 4 != 0)
                return Error.InvalidBindingSize;
            range.* = .{
                .source_word_offset = std.math.cast(u32, source_bytes / 4) orelse return Error.InvalidBindingSize,
                .destination_word_offset = try wordOffset(trace),
                .word_count = entry.row_count,
            };
        }
        var copy_owner: ?metal_runtime.ArenaCopyPlan = try metal.prepareArenaCopies(ranges);
        errdefer if (copy_owner) |*copy| copy.deinit();
        var interpolation_owner: ?protocol_recipes.CircleIfftRecipe = try prepareComponentInterpolation(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            entry.component,
            twiddle_storage,
        );
        errdefer if (interpolation_owner) |*interpolation| interpolation.deinit();
        var operation = try FixedBaseTraceOperation.init(
            allocator,
            entry.component,
            copy_owner.?,
            interpolation_owner.?,
        );
        copy_owner = null;
        interpolation_owner = null;
        errdefer operation.deinit();
        try operations.append(allocator, operation);
    }
    return .{
        .allocator = allocator,
        .metal = metal,
        .resident_arena = resident_arena,
        .memory_address = memory_address,
        .memory_values = memory_values,
        .fixed = try operations.toOwnedSlice(allocator),
    };
}

fn prepareComponentInterpolation(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    component: []const u8,
    twiddle_storage: arena_plan.Binding,
) !protocol_recipes.CircleIfftRecipe {
    const recipes = try prepareComponentInterpolationGroups(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        component,
        twiddle_storage,
    );
    if (recipes.len != 1) {
        for (recipes) |*recipe| recipe.deinit();
        allocator.free(recipes);
        return Error.InvalidCardinality;
    }
    const result = recipes[0];
    allocator.free(recipes);
    return result;
}

fn prepareComponentInterpolationGroups(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    component: []const u8,
    twiddle_storage: arena_plan.Binding,
) ![]protocol_recipes.CircleIfftRecipe {
    return prepareComponentInterpolationGroupsForPurposes(
        allocator,
        metal,
        resident_arena,
        schedule,
        plan,
        component,
        "BaseTrace",
        "BaseCoefficients",
        twiddle_storage,
    );
}

pub fn prepareComponentInterpolationGroupsForPurposes(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    component: []const u8,
    source_purpose: []const u8,
    destination_purpose: []const u8,
    twiddle_storage: arena_plan.Binding,
) ![]protocol_recipes.CircleIfftRecipe {
    const source_groups = try collectComponentBindingGroups(allocator, schedule, plan, source_purpose, component);
    defer {
        for (source_groups) |group| allocator.free(group);
        allocator.free(source_groups);
    }
    const destination_groups = try collectComponentBindingGroups(allocator, schedule, plan, destination_purpose, component);
    defer {
        for (destination_groups) |group| allocator.free(group);
        allocator.free(destination_groups);
    }
    if (source_groups.len != destination_groups.len) return Error.InvalidCardinality;
    const recipes = try allocator.alloc(protocol_recipes.CircleIfftRecipe, source_groups.len);
    var initialized: usize = 0;
    errdefer {
        for (recipes[0..initialized]) |*recipe| recipe.deinit();
        allocator.free(recipes);
    }
    while (initialized < recipes.len) : (initialized += 1) {
        const sources = source_groups[initialized];
        const destinations = destination_groups[initialized];
        if (sources.len == 0 or sources.len != destinations.len or sources[0].size_bytes % 4 != 0)
            return Error.InvalidCardinality;
        const rows = sources[0].size_bytes / 4;
        if (rows < 16 or !std.math.isPowerOfTwo(rows)) return Error.InvalidBindingSize;
        for (sources, destinations) |source, destination| {
            if (source.size_bytes / 4 != rows or destination.size_bytes != source.size_bytes)
                return Error.InvalidBindingSize;
        }
        const log_size: u32 = std.math.log2_int(u64, rows);
        recipes[initialized] = try protocol_recipes.CircleIfftRecipe.init(
            allocator,
            metal,
            resident_arena,
            sources,
            destinations,
            try twiddleBindingForLog(twiddle_storage, log_size),
            log_size,
            try M31.fromCanonical(@as(u32, 1) << @intCast(log_size)).inv(),
        );
    }
    return recipes;
}

pub fn interpolateTraceColumns(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    source_purpose: []const u8,
    destination_purpose: []const u8,
    inverse_twiddle_purpose: []const u8,
    twiddle_storage: ?arena_plan.Binding,
) !f64 {
    const sources = try collectScheduleOrder(allocator, schedule, plan, source_purpose);
    defer allocator.free(sources);
    const destinations = try collectScheduleOrder(allocator, schedule, plan, destination_purpose);
    defer allocator.free(destinations);
    if (sources.len != destinations.len) return Error.InvalidCardinality;
    const inverse_twiddles = try one(schedule, plan, inverse_twiddle_purpose);
    var gpu_ms: f64 = 0;
    for (4..25) |log_size_usize| {
        const log_size: u32 = @intCast(log_size_usize);
        const expected_bytes = (@as(u64, 1) << @intCast(log_size)) * 4;
        var source_offsets = std.ArrayList(u64).empty;
        defer source_offsets.deinit(allocator);
        var destination_offsets = std.ArrayList(u64).empty;
        defer destination_offsets.deinit(allocator);
        for (sources, destinations) |source, destination| {
            if (source.size_bytes != expected_bytes) continue;
            if (destination.size_bytes != expected_bytes) return Error.InvalidBindingSize;
            try source_offsets.append(allocator, source.offset_bytes / 4);
            try destination_offsets.append(allocator, destination.offset_bytes / 4);
        }
        if (source_offsets.items.len == 0) continue;
        const scale = (try M31.fromCanonical(@as(u32, 1) << @intCast(log_size)).inv()).v;
        var prepared = try metal.prepareCircleIfft(
            source_offsets.items,
            destination_offsets.items,
            log_size,
            try twiddleOffsetForLog(if (twiddle_storage) |storage| twiddleBankBinding(storage, log_size) else inverse_twiddles, log_size),
            scale,
        );
        defer prepared.deinit();
        gpu_ms += try metal.circleIfftPrepared(resident_arena.buffer, prepared);
    }
    return gpu_ms;
}

pub fn interpolateAvailablePreprocessedColumns(
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
) !f64 {
    const inverse_twiddles = try one(schedule, plan, "PreprocessedInverseTwiddles");
    var gpu_ms: f64 = 0;
    for (4..25) |log_size_usize| {
        const log_size: u32 = @intCast(log_size_usize);
        const expected_bytes = (@as(u64, 1) << @intCast(log_size)) * 4;
        var source_offsets = std.ArrayList(u64).empty;
        defer source_offsets.deinit(allocator);
        var destination_offsets = std.ArrayList(u64).empty;
        defer destination_offsets.deinit(allocator);
        for (schedule) |entry| {
            if (!std.mem.eql(u8, try purpose(entry), "PreprocessedEvaluations")) continue;
            const source = plan.binding(try logicalId(entry)) catch return Error.MissingBinding;
            if (source.size_bytes != expected_bytes) continue;
            const destination = try oneOrdinal(
                schedule,
                plan,
                "PreprocessedCoefficients",
                try ordinal(entry),
            );
            if (destination.size_bytes != source.size_bytes) return Error.InvalidBindingSize;
            try source_offsets.append(allocator, source.offset_bytes / 4);
            try destination_offsets.append(allocator, destination.offset_bytes / 4);
        }
        if (source_offsets.items.len == 0) continue;
        const scale = (try M31.fromCanonical(@as(u32, 1) << @intCast(log_size)).inv()).v;
        var prepared = try metal.prepareCircleIfft(
            source_offsets.items,
            destination_offsets.items,
            log_size,
            try twiddleOffsetForLog(inverse_twiddles, log_size),
            scale,
        );
        defer prepared.deinit();
        gpu_ms += try metal.circleIfftPrepared(resident_arena.buffer, prepared);
    }
    return gpu_ms;
}

test "Cairo native fixed trace operations are addressed by component" {
    var operations = [_]FixedBaseTraceOperation{
        .{ .allocator = undefined, .component = "range_check_6", .copy = undefined, .interpolation = undefined },
        .{ .allocator = undefined, .component = "range_check_8", .copy = undefined, .interpolation = undefined },
    };
    var batch: NativeBaseInterpolationBatch = undefined;
    batch.fixed = &operations;
    try std.testing.expectEqual(@as(?u32, 0), try batch.fixedIndex("range_check_6"));
    try std.testing.expectEqual(@as(?u32, 1), try batch.fixedIndex("range_check_8"));
    try std.testing.expectEqual(@as(?u32, null), try batch.fixedIndex("range_check_9_9"));
}

test "Cairo native fixed trace operation owns its component name" {
    var source = [_]u8{ 'r', 'a', 'n', 'g', 'e', '_', 'c', 'h', 'e', 'c', 'k', '_', '6' };
    const operation = try FixedBaseTraceOperation.init(
        std.testing.allocator,
        &source,
        undefined,
        undefined,
    );
    defer std.testing.allocator.free(operation.component);
    source[0] = 'X';
    try std.testing.expectEqualStrings("range_check_6", operation.component);
}

test "Cairo base interpolation batches reset only request bookkeeping" {
    const Helpers = struct {
        fn circle(last_tick: u16, accumulated_gpu_ms: f64) protocol_recipes.CircleIfftRecipe {
            return .{
                .allocator = std.testing.allocator,
                .metal = undefined,
                .arena = undefined,
                .sources = &.{},
                .destinations = &.{},
                .prepared = undefined,
                .log_size = 19,
                .inverse_twiddle_offset_words = 0,
                .scale_factor = 1,
                .last_tick = last_tick,
                .accumulated_gpu_ms = accumulated_gpu_ms,
            };
        }
    };

    var recorded_recipes = [_]protocol_recipes.CircleIfftRecipe{
        Helpers.circle(3, 1.5),
        Helpers.circle(4, 2.5),
    };
    var recorded = RecordedBaseInterpolationBatch{
        .allocator = std.testing.allocator,
        .resident_arena = undefined,
        .recipes = &recorded_recipes,
        .ec_op_recipe = Helpers.circle(5, 3.5),
        .ec_op_owner = 1,
    };
    recorded.resetForRequest();
    for (recorded.recipes) |recipe| {
        try std.testing.expectEqual(@as(?u16, null), recipe.last_tick);
        try std.testing.expectEqual(@as(f64, 0), recipe.accumulated_gpu_ms);
    }
    try std.testing.expectEqual(@as(?u16, null), recorded.ec_op_recipe.?.last_tick);
    try std.testing.expectEqual(@as(f64, 0), recorded.ec_op_recipe.?.accumulated_gpu_ms);

    var memory_values = [_]protocol_recipes.CircleIfftRecipe{Helpers.circle(7, 4.5)};
    var fixed = [_]FixedBaseTraceOperation{.{
        .allocator = undefined,
        .component = "range_check_6",
        .copy = undefined,
        .interpolation = Helpers.circle(8, 5.5),
    }};
    var native = NativeBaseInterpolationBatch{
        .allocator = std.testing.allocator,
        .metal = undefined,
        .resident_arena = undefined,
        .memory_address = Helpers.circle(6, 3.5),
        .memory_values = &memory_values,
        .fixed = &fixed,
    };
    native.resetForRequest();
    try std.testing.expectEqual(@as(?u16, null), native.memory_address.last_tick);
    try std.testing.expectEqual(@as(f64, 0), native.memory_address.accumulated_gpu_ms);
    try std.testing.expectEqual(@as(?u16, null), native.memory_values[0].last_tick);
    try std.testing.expectEqual(@as(f64, 0), native.memory_values[0].accumulated_gpu_ms);
    try std.testing.expectEqual(@as(?u16, null), native.fixed[0].interpolation.last_tick);
    try std.testing.expectEqual(@as(f64, 0), native.fixed[0].interpolation.accumulated_gpu_ms);
}
