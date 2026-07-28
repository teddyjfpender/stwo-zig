//! Relation-component binding, prepared ownership, and execution.

const std = @import("std");
const arena_plan = @import("../../../../backends/metal/arena_plan.zig");
const metal_runtime = @import("../../../../backends/metal/runtime.zig");
const protocol_recipes = @import("../../../../backends/metal/protocol_recipes.zig");
const cairo_proof_plan = @import("stwo_cairo_frontend").proof_plan;
const relation_bundle_mod = @import("stwo_cairo_frontend").witness.relation_bundle;
const witness_bundle_mod = @import("stwo_cairo_frontend").witness.bundle;
const schedule_bindings = @import("../../schedule_bindings.zig");
const trace_interpolation = @import("../trace/interpolation.zig");
const claims = @import("claims.zig");
const Error = @import("../errors.zig").Error;

const NamedBinding = schedule_bindings.NamedBinding;
const collectNamed = schedule_bindings.collectNamed;
const namedGroupRanges = schedule_bindings.namedGroupRanges;
const one = schedule_bindings.one;
const oneComponent = schedule_bindings.oneComponent;

pub const Bindings = struct {
    claimed_sums: []const arena_plan.Binding,
    alpha_powers: arena_plan.Binding,
    z: arena_plan.Binding,
    scan_scratch: arena_plan.Binding,
};

pub const RelationComponentTelemetry = struct {
    relation_gpu_ms: f64,
    interpolation_gpu_ms: f64,
};

pub const RelationComponentOperation = struct {
    component_index: u32,
    component: []const u8,
    claimed_sum_start: u32,
    claimed_sum_count: u32,
    relation: protocol_recipes.RelationRecipe,
    interpolations: []protocol_recipes.CircleIfftRecipe,

    fn deinit(self: *RelationComponentOperation, allocator: std.mem.Allocator) void {
        for (self.interpolations) |*interpolation| interpolation.deinit();
        allocator.free(self.interpolations);
        self.relation.deinit();
        self.* = undefined;
    }

    pub fn execute(self: *RelationComponentOperation) !RelationComponentTelemetry {
        const relation_before = self.relation.accumulated_gpu_ms;
        try self.relation.execute();
        var interpolation_gpu_ms: f64 = 0;
        for (self.interpolations) |*interpolation| {
            const before = interpolation.accumulated_gpu_ms;
            try interpolation.execute();
            interpolation_gpu_ms += interpolation.accumulated_gpu_ms - before;
        }
        return .{
            .relation_gpu_ms = self.relation.accumulated_gpu_ms - relation_before,
            .interpolation_gpu_ms = interpolation_gpu_ms,
        };
    }
};

/// Relation components remain in canonical relation-bundle order. Each entry
/// owns the exact consecutive claimed-sum range produced by its relation plan.
pub const PreparedRelationComponents = struct {
    allocator: std.mem.Allocator,
    operations: []RelationComponentOperation,

    pub fn deinit(self: *PreparedRelationComponents) void {
        for (self.operations) |*operation| operation.deinit(self.allocator);
        self.allocator.free(self.operations);
        self.* = undefined;
    }

    pub fn componentIndex(self: PreparedRelationComponents, name: []const u8) !?u32 {
        var found: ?u32 = null;
        for (self.operations, 0..) |operation, index| {
            if (!std.mem.eql(u8, operation.component, name)) continue;
            if (found != null) return Error.DuplicateBinding;
            found = @intCast(index);
        }
        return found;
    }

    pub fn executeIndex(self: *PreparedRelationComponents, index: u32) !RelationComponentTelemetry {
        if (index >= self.operations.len) return Error.InvalidCardinality;
        return self.operations[index].execute();
    }

    pub fn executeComponent(self: *PreparedRelationComponents, name: []const u8) !RelationComponentTelemetry {
        const index = try self.componentIndex(name) orelse return Error.MissingBinding;
        return self.executeIndex(index);
    }
};

const BoundRelationComponent = struct {
    allocator: std.mem.Allocator,
    instances: []protocol_recipes.RelationInstanceBindings,

    fn deinit(self: *BoundRelationComponent) void {
        for (self.instances) |instance| {
            self.allocator.free(instance.sources);
            self.allocator.free(instance.outputs);
        }
        self.allocator.free(self.instances);
        self.* = undefined;
    }
};

pub fn prepare(
    bindings: Bindings,
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    bundle: relation_bundle_mod.Bundle,
    witness_bundle: witness_bundle_mod.Bundle,
) !protocol_recipes.RelationRecipe {
    try claims.validateClaimedSumOrder(schedule, plan, bindings.claimed_sums);
    const interaction_named = try collectNamed(allocator, schedule, plan, "InteractionTrace");
    defer allocator.free(interaction_named);
    const base_named = try collectNamed(allocator, schedule, plan, "BaseTrace");
    defer allocator.free(base_named);
    var components = std.ArrayList(BoundRelationComponent).empty;
    defer {
        for (components.items) |*component| component.deinit();
        components.deinit(allocator);
    }
    var instances = std.ArrayList(protocol_recipes.RelationInstanceBindings).empty;
    defer instances.deinit(allocator);
    var claimed_index: usize = 0;
    for (bundle.components) |component| {
        var bound = (try bindRelationComponent(
            allocator,
            schedule,
            plan,
            component,
            interaction_named,
            base_named,
            witness_bundle,
            bindings.claimed_sums,
            claimed_index,
        )) orelse continue;
        errdefer bound.deinit();
        claimed_index = std.math.add(usize, claimed_index, bound.instances.len) catch return Error.InvalidClaimedSumCount;
        try instances.appendSlice(allocator, bound.instances);
        try components.append(allocator, bound);
    }
    if (claimed_index != bindings.claimed_sums.len) return Error.InvalidClaimedSumCount;
    return protocol_recipes.RelationRecipe.init(
        allocator,
        metal,
        resident_arena,
        instances.items,
        bindings.alpha_powers,
        bindings.z,
        bindings.scan_scratch,
    );
}

pub fn prepareComponents(
    bindings: Bindings,
    allocator: std.mem.Allocator,
    metal: *metal_runtime.Runtime,
    resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    bundle: relation_bundle_mod.Bundle,
    witness_bundle: witness_bundle_mod.Bundle,
    twiddle_storage: arena_plan.Binding,
) !PreparedRelationComponents {
    try claims.validateClaimedSumOrder(schedule, plan, bindings.claimed_sums);
    const interaction_named = try collectNamed(allocator, schedule, plan, "InteractionTrace");
    defer allocator.free(interaction_named);
    const base_named = try collectNamed(allocator, schedule, plan, "BaseTrace");
    defer allocator.free(base_named);
    var operations = std.ArrayList(RelationComponentOperation).empty;
    errdefer {
        for (operations.items) |*operation| operation.deinit(allocator);
        operations.deinit(allocator);
    }
    var claimed_index: usize = 0;
    for (bundle.components, 0..) |component, component_index| {
        if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_LOG_STAGE_TIMINGS"))
            std.debug.print("relation_prepare component={s} index={d}\n", .{ component.name, component_index });
        var bound = (try bindRelationComponent(
            allocator,
            schedule,
            plan,
            component,
            interaction_named,
            base_named,
            witness_bundle,
            bindings.claimed_sums,
            claimed_index,
        )) orelse continue;
        defer bound.deinit();
        for (operations.items) |operation| {
            if (std.mem.eql(u8, operation.component, component.name)) return Error.DuplicateBinding;
        }
        var relation = try protocol_recipes.RelationRecipe.init(
            allocator,
            metal,
            resident_arena,
            bound.instances,
            bindings.alpha_powers,
            bindings.z,
            bindings.scan_scratch,
        );
        var relation_owned = true;
        defer if (relation_owned) relation.deinit();
        const interpolations = try trace_interpolation.prepareComponentInterpolationGroupsForPurposes(
            allocator,
            metal,
            resident_arena,
            schedule,
            plan,
            component.name,
            "InteractionTrace",
            "InteractionCoefficients",
            twiddle_storage,
        );
        var interpolations_owned = true;
        defer if (interpolations_owned) {
            for (interpolations) |*interpolation| interpolation.deinit();
            allocator.free(interpolations);
        };
        if (interpolations.len != bound.instances.len) return Error.InvalidCardinality;
        try operations.append(allocator, .{
            .component_index = @intCast(component_index),
            .component = component.name,
            .claimed_sum_start = @intCast(claimed_index),
            .claimed_sum_count = @intCast(bound.instances.len),
            .relation = relation,
            .interpolations = interpolations,
        });
        relation_owned = false;
        interpolations_owned = false;
        claimed_index = std.math.add(usize, claimed_index, bound.instances.len) catch return Error.InvalidClaimedSumCount;
    }
    if (claimed_index != bindings.claimed_sums.len or operations.items.len == 0)
        return Error.InvalidClaimedSumCount;
    return .{ .allocator = allocator, .operations = try operations.toOwnedSlice(allocator) };
}

pub fn logDiagnostics(
    bindings: Bindings,
    resident_arena: *arena_plan.ResidentArena,
    relations: PreparedRelationComponents,
) !void {
    const z_bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(bindings.z));
    const alpha_bytes: []align(4) u8 = @alignCast(try resident_arena.bytes(bindings.alpha_powers));
    const z = std.mem.bytesAsSlice(u32, z_bytes);
    const alpha_powers = std.mem.bytesAsSlice(u32, alpha_bytes);
    if (z.len < 4 or alpha_powers.len < 8) return Error.InvalidBindingSize;
    std.debug.print(
        "relation_challenge z={},{},{},{} alpha={},{},{},{}\n",
        .{ z[0], z[1], z[2], z[3], alpha_powers[4], alpha_powers[5], alpha_powers[6], alpha_powers[7] },
    );
    for (relations.operations) |operation| {
        for (0..operation.claimed_sum_count) |instance_index| {
            const claimed_index = @as(usize, operation.claimed_sum_start) + instance_index;
            if (claimed_index >= bindings.claimed_sums.len) return Error.InvalidClaimedSumCount;
            const claimed_bytes: []align(4) u8 = @alignCast(
                try resident_arena.bytes(bindings.claimed_sums[claimed_index]),
            );
            const claimed = std.mem.bytesAsSlice(u32, claimed_bytes);
            if (claimed.len < 4) return Error.InvalidBindingSize;
            std.debug.print(
                "relation_claimed ordinal={} component={s} instance={} value={},{},{},{}\n",
                .{ claimed_index, operation.component, instance_index, claimed[0], claimed[1], claimed[2], claimed[3] },
            );
        }
    }
}

fn countFixedRelationTraces(traces: []const relation_bundle_mod.Trace) usize {
    var count: usize = 0;
    for (traces) |trace| count += switch (trace.part) {
        .component, .memory_small => 1,
        .each_memory_big => 0,
    };
    return count;
}

fn relationTraceUsesRowEnabler(trace: relation_bundle_mod.Trace) bool {
    var descriptor_index: usize = 0;
    while (descriptor_index < trace.descriptors.len) : (descriptor_index += 16) {
        const descriptor = trace.descriptors[descriptor_index .. descriptor_index + 16];
        for (0..descriptor[0]) |use_index| {
            if (descriptor[1 + use_index * 7 + 4] == 1) return true;
        }
    }
    return false;
}

fn gatheredWitnessRealRows(
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    witness_bundle: witness_bundle_mod.Bundle,
    consumer: []const u8,
) !u32 {
    const edges = cairo_proof_plan.gatheredProducerEdges(consumer) orelse return Error.MissingBinding;
    var real_rows: u32 = 0;
    for (edges) |edge| {
        const producer = witness_bundle.find(edge.producer) orelse return Error.MissingBinding;
        const source = try oneComponent(schedule, plan, "SubcomponentInputs", edge.producer);
        if (producer.program.n_sub_words == 0 or source.size_bytes % (@as(u64, producer.program.n_sub_words) * 4) != 0)
            return Error.InvalidBindingSize;
        const producer_rows = std.math.cast(u32, source.size_bytes / 4 / producer.program.n_sub_words) orelse
            return Error.InvalidBindingSize;
        const contributed = std.math.mul(u32, producer_rows, edge.instances) catch return Error.InvalidBindingSize;
        real_rows = std.math.add(u32, real_rows, contributed) catch return Error.InvalidBindingSize;
    }
    return real_rows;
}

fn bindRelationComponent(
    allocator: std.mem.Allocator,
    schedule: []const std.json.Value,
    plan: arena_plan.Plan,
    component: relation_bundle_mod.Component,
    interaction_named: []const NamedBinding,
    base_named: []const NamedBinding,
    witness_bundle: witness_bundle_mod.Bundle,
    claimed_sums: []const arena_plan.Binding,
    claimed_start: usize,
) !?BoundRelationComponent {
    var component_outputs = std.ArrayList(NamedBinding).empty;
    defer component_outputs.deinit(allocator);
    for (interaction_named) |item| {
        if (std.mem.eql(u8, item.component, component.name)) try component_outputs.append(allocator, item);
    }
    if (component_outputs.items.len == 0) return null;

    var component_base = std.ArrayList(NamedBinding).empty;
    defer component_base.deinit(allocator);
    for (base_named) |item| {
        if (std.mem.eql(u8, item.component, component.name)) try component_base.append(allocator, item);
    }
    const output_groups = try namedGroupRanges(allocator, component_outputs.items);
    defer allocator.free(output_groups);
    const base_groups = try namedGroupRanges(allocator, component_base.items);
    defer allocator.free(base_groups);

    var instances = std.ArrayList(protocol_recipes.RelationInstanceBindings).empty;
    errdefer {
        for (instances.items) |instance| {
            allocator.free(instance.sources);
            allocator.free(instance.outputs);
        }
        instances.deinit(allocator);
    }
    var output_group_index: usize = 0;
    var big_source_offset: u32 = 0;
    for (component.traces, 0..) |trace, trace_index| {
        const remaining_fixed = countFixedRelationTraces(component.traces[trace_index + 1 ..]);
        if (output_group_index + remaining_fixed > output_groups.len) return Error.InvalidCardinality;
        const trace_instances: usize = switch (trace.part) {
            .component, .memory_small => 1,
            .each_memory_big => output_groups.len - output_group_index - remaining_fixed,
        };
        if (trace_instances == 0) return Error.InvalidCardinality;
        for (0..trace_instances) |instance_index| {
            const claimed_index = std.math.add(usize, claimed_start, instances.items.len) catch return Error.InvalidClaimedSumCount;
            if (output_group_index >= output_groups.len or claimed_index >= claimed_sums.len)
                return Error.InvalidCardinality;
            const output_range = output_groups[output_group_index];
            const output_named = component_outputs.items[output_range.start .. output_range.start + output_range.len];
            if (output_named.len != @as(usize, trace.output_columns) * 4) return Error.InvalidCardinality;
            const outputs = try allocator.alloc(arena_plan.Binding, output_named.len);
            var outputs_owned = true;
            defer if (outputs_owned) allocator.free(outputs);
            for (output_named, outputs) |item, *binding| binding.* = item.binding;
            const rows = std.math.cast(u32, outputs[0].size_bytes / 4) orelse return Error.InvalidBindingSize;
            if (rows == 0 or !std.math.isPowerOfTwo(rows)) return Error.InvalidBindingSize;
            for (outputs) |binding| {
                if (binding.size_bytes != @as(u64, rows) * 4) return Error.InvalidBindingSize;
            }

            const source_group_index: usize = switch (trace.part) {
                .component => 0,
                .each_memory_big => instance_index,
                .memory_small => if (base_groups.len == 0) return Error.InvalidCardinality else base_groups.len - 1,
            };
            const source_count: usize = switch (trace.layout) {
                .lookup_words => 1,
                .memory_address => @as(usize, trace.layout_arg) * 2,
                .memory_big, .memory_small => @as(usize, trace.layout_arg) + 1,
                .bitwise_xor_12 => trace.layout_arg,
            };
            const sources = try allocator.alloc(arena_plan.Binding, source_count);
            var sources_owned = true;
            defer if (sources_owned) allocator.free(sources);
            if (trace.layout == .lookup_words) {
                sources[0] = try oneComponent(schedule, plan, "LookupInputs", component.name);
            } else {
                if (source_group_index >= base_groups.len) return Error.InvalidCardinality;
                const source_range = base_groups[source_group_index];
                if (source_range.len < source_count) return Error.InvalidCardinality;
                for (component_base.items[source_range.start .. source_range.start + source_count], sources) |item, *binding| {
                    binding.* = item.binding;
                }
            }
            for (sources) |binding| {
                if (binding.size_bytes < @as(u64, rows) * 4) return Error.InvalidBindingSize;
            }
            const real_rows = if (relationTraceUsesRowEnabler(trace))
                try gatheredWitnessRealRows(schedule, plan, witness_bundle, component.name)
            else
                rows;
            if (real_rows > rows) return Error.InvalidBindingSize;
            if (std.process.hasEnvVarConstant("STWO_ZIG_SN2_DIFF_ADD_OPCODE_INTERACTION") and
                (std.mem.eql(u8, component.name, "add_ap_opcode") or
                    std.mem.eql(u8, component.name, "add_opcode") or
                    std.mem.eql(u8, component.name, "add_opcode_small")))
            {
                std.debug.print(
                    "relation_binding component={s} rows={} real_rows={} sources={} columns={} source_offset_rows={}\n",
                    .{ component.name, rows, real_rows, sources.len, trace.output_columns, if (trace.part == .each_memory_big) big_source_offset else 0 },
                );
                for (sources, 0..) |binding, source_index| std.debug.print(
                    "relation_range component={s} kind=source ordinal={} words=[{}, {})\n",
                    .{ component.name, source_index, binding.offset_bytes / 4, (binding.offset_bytes + binding.size_bytes) / 4 },
                );
                for (outputs, 0..) |binding, output_index| std.debug.print(
                    "relation_range component={s} kind=output ordinal={} words=[{}, {})\n",
                    .{ component.name, output_index, binding.offset_bytes / 4, (binding.offset_bytes + binding.size_bytes) / 4 },
                );
                const debug_scratch = try one(schedule, plan, "RelationScanEvalScratch");
                std.debug.print(
                    "relation_range component={s} kind=scratch ordinal=0 words=[{}, {})\n",
                    .{ component.name, debug_scratch.offset_bytes / 4, (debug_scratch.offset_bytes + debug_scratch.size_bytes) / 4 },
                );
                std.debug.print(
                    "relation_range component={s} kind=claimed ordinal=0 words=[{}, {})\n",
                    .{ component.name, claimed_sums[claimed_index].offset_bytes / 4, (claimed_sums[claimed_index].offset_bytes + claimed_sums[claimed_index].size_bytes) / 4 },
                );
                var debug_descriptor_index: usize = 0;
                while (debug_descriptor_index < trace.descriptors.len) : (debug_descriptor_index += 16) {
                    const descriptor = trace.descriptors[debug_descriptor_index..][0..16];
                    std.debug.print(
                        "relation_descriptor component={s} column={} uses={} a={},{},{},{},{},{},{} b={},{},{},{},{},{},{}\n",
                        .{
                            component.name,
                            debug_descriptor_index / 16,
                            descriptor[0],
                            descriptor[1],
                            descriptor[2],
                            descriptor[3],
                            descriptor[4],
                            descriptor[5],
                            descriptor[6],
                            descriptor[7],
                            descriptor[8],
                            descriptor[9],
                            descriptor[10],
                            descriptor[11],
                            descriptor[12],
                            descriptor[13],
                            descriptor[14],
                        },
                    );
                }
            }
            try instances.append(allocator, .{
                .rows = rows,
                .real_rows = real_rows,
                .source_offset_rows = if (trace.part == .each_memory_big) big_source_offset else 0,
                .sources = sources,
                .descriptors = trace.descriptors,
                .outputs = outputs,
                .claimed_sum = claimed_sums[claimed_index],
            });
            sources_owned = false;
            outputs_owned = false;
            if (trace.part == .each_memory_big) {
                big_source_offset = std.math.add(u32, big_source_offset, rows) catch return Error.InvalidBindingSize;
            }
            output_group_index += 1;
        }
    }
    if (output_group_index != output_groups.len) return Error.InvalidCardinality;
    return .{ .allocator = allocator, .instances = try instances.toOwnedSlice(allocator) };
}
