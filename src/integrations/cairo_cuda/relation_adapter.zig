//! Authenticated Cairo relation templates compiled into the resident CUDA
//! relation graph.
//!
//! The adapter owns only host policy. Device addresses remain request-plan
//! inputs, while relation descriptors and heterogeneous geometry are fixed by
//! the Cairo proof plan and semantic bundle.

const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const ingress = @import("relation_adapter/ingress.zig");

const pointer_words = @sizeOf(usize) / @sizeOf(u32);
const m31_modulus: u64 = 0x7fff_ffff;
const large_memory_value_id_base: u32 = 0x4000_0000;
const xor_12_rows: u32 = 1 << 20;

comptime {
    std.debug.assert(pointer_words == 2);
}

pub const Error = error{
    DuplicateRelationComponent,
    GeometryOverflow,
    InvalidComponentOrder,
    InvalidPreparedInputShape,
    InvalidProofGeometry,
    InvalidRelationTrace,
    MissingRelationComponent,
};

pub const Instance = struct {
    component_index: u32,
    component_instance: u32,
    relation_component_index: u32,
    relation_trace_index: u32,
    component: []u8,
    part: relation_bundle.TracePart,
    layout: relation_bundle.SourceLayout,
    source_pointer_count: u32,
    lookup_word_columns: u32,
    descriptors: []relation_abi.ColumnDescriptor,
    geometry: relation_abi.Geometry,
};

pub const PreparedInputShape = struct {
    instance_count: u32,
    top_level_pointer_words: u32,
    geometry_records: u32,
    max_alpha_powers: u32,
    source_pointer_words: u64,
    descriptor_words: u64,
    output_pointer_words: u64,
    denominator_secure_fields: u64,
    interaction_coordinate_cells: u64,
    scratch_words: u32,
};

/// Device-owned fields supplied after arena placement. Descriptor policy,
/// lookup bounds, and topology are deliberately absent.
pub const DeviceInstanceBinding = struct {
    source_pointer_table: common.Words,
    source_columns: []const common.Words,
    descriptor_storage: common.Words,
    output_pointer_table: common.Words,
    output_coordinates: []const common.Words,
    denominator_slab: common.SecureFields,
    claimed_sum: common.SecureFields,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    instances: []Instance,
    descriptor_storage: []relation_abi.ColumnDescriptor,
    geometry: []relation_abi.Geometry,
    max_alpha_powers: u32,
    total_pair_blocks: u32,
    total_inverse_blocks: u32,
    total_row_blocks: u32,
    topology_identity: [32]u8,

    pub fn compile(
        allocator: std.mem.Allocator,
        proof: *const proof_plan.CairoProofPlan,
        relations: relation_bundle.Bundle,
    ) !Plan {
        if (relations.graph_hash != relation_bundle.expected_graph_hash)
            return Error.InvalidRelationTrace;
        try validateRelationNames(relations);
        const selections = try selectCanonicalTraces(allocator, proof, relations);
        defer allocator.free(selections);
        try validateActiveTraceCoverage(proof, relations, selections);

        var descriptor_count: usize = 0;
        var max_alpha_powers: u32 = 0;
        for (selections) |selection| {
            const trace = selection.trace;
            if (trace.output_columns == 0 or
                trace.descriptors.len !=
                    try checkedMulUsize(trace.output_columns, relation_abi.descriptor_words))
            {
                return Error.InvalidRelationTrace;
            }
            descriptor_count = std.math.add(
                usize,
                descriptor_count,
                trace.output_columns,
            ) catch return Error.GeometryOverflow;
            max_alpha_powers = @max(
                max_alpha_powers,
                try traceAlphaPowers(trace),
            );
        }
        if (max_alpha_powers == 0) return Error.InvalidRelationTrace;

        const instances = try allocator.alloc(Instance, selections.len);
        var initialized: usize = 0;
        errdefer {
            for (instances[0..initialized]) |instance|
                allocator.free(instance.component);
            allocator.free(instances);
        }
        const descriptors = try allocator.alloc(
            relation_abi.ColumnDescriptor,
            descriptor_count,
        );
        errdefer allocator.free(descriptors);
        const geometry = try allocator.alloc(
            relation_abi.Geometry,
            selections.len,
        );
        errdefer allocator.free(geometry);

        var descriptor_cursor: usize = 0;
        var pair_cursor: u32 = 0;
        var inverse_cursor: u32 = 0;
        var row_cursor: u32 = 0;
        var big_source_offset: u32 = 0;
        for (selections, instances, geometry) |selection, *instance, *record| {
            const trace = selection.trace;
            const rows = try rowsFor(selection.planned, trace.part);
            const real_rows = if (traceUsesRowEnabler(trace))
                try relationRealRows(proof, selection)
            else
                rows;
            if (real_rows == 0 or real_rows > rows)
                return Error.InvalidProofGeometry;
            const row_blocks = blocks(rows, relation_abi.launch_block);
            const pair_blocks = try checkedMulU32(
                row_blocks,
                trace.output_columns,
            );
            const values = try checkedMulU32(rows, trace.output_columns);
            const inverse_blocks = blocks(
                values,
                relation_abi.inverse_block_values,
            );
            record.* = .{
                .pair_first = pair_cursor,
                .pair_blocks = pair_blocks,
                .inverse_first = inverse_cursor,
                .inverse_blocks = inverse_blocks,
                .row_first = row_cursor,
                .row_blocks = row_blocks,
                .rows = rows,
                .columns = trace.output_columns,
                .real_rows = real_rows,
                .source_offset_rows = if (trace.part == .each_memory_big)
                    big_source_offset
                else
                    0,
                .inverse_rows = inverseRows(rows),
            };
            try validateLayoutDomain(trace, record.*);
            pair_cursor = try checkedAddU32(pair_cursor, pair_blocks);
            inverse_cursor = try checkedAddU32(
                inverse_cursor,
                inverse_blocks,
            );
            row_cursor = try checkedAddU32(row_cursor, row_blocks);
            if (trace.part == .each_memory_big)
                big_source_offset = try checkedAddU32(
                    big_source_offset,
                    rows,
                );

            const descriptor_end = std.math.add(
                usize,
                descriptor_cursor,
                trace.output_columns,
            ) catch return Error.GeometryOverflow;
            const destination = descriptors[descriptor_cursor..descriptor_end];
            try translateDescriptors(
                destination,
                trace,
                max_alpha_powers,
            );
            const component_name = try allocator.dupe(
                u8,
                selection.planned.name,
            );
            instance.* = .{
                .component_index = selection.component_index,
                .component_instance = selection.planned.instance,
                .relation_component_index = selection.relation_component_index,
                .relation_trace_index = selection.relation_trace_index,
                .component = component_name,
                .part = trace.part,
                .layout = trace.layout,
                .source_pointer_count = try sourcePointerCount(trace),
                .lookup_word_columns = if (trace.layout == .lookup_words)
                    trace.layout_arg
                else
                    0,
                .descriptors = destination,
                .geometry = record.*,
            };
            initialized += 1;
            descriptor_cursor = descriptor_end;
        }
        std.debug.assert(descriptor_cursor == descriptors.len);

        var result = Plan{
            .allocator = allocator,
            .instances = instances,
            .descriptor_storage = descriptors,
            .geometry = geometry,
            .max_alpha_powers = max_alpha_powers,
            .total_pair_blocks = pair_cursor,
            .total_inverse_blocks = inverse_cursor,
            .total_row_blocks = row_cursor,
            .topology_identity = [_]u8{0} ** 32,
        };
        try result.topology().validate();
        result.topology_identity = topologyIdentity(
            relations.graph_hash,
            &result,
        );
        return result;
    }

    pub fn deinit(self: *Plan) void {
        for (self.instances) |instance|
            self.allocator.free(instance.component);
        self.allocator.free(self.instances);
        self.allocator.free(self.descriptor_storage);
        self.allocator.free(self.geometry);
        self.* = undefined;
    }

    pub fn topology(self: *const Plan) relation_stage.Topology {
        return .{
            .geometry = self.geometry,
            .max_alpha_powers = self.max_alpha_powers,
            .total_pair_blocks = self.total_pair_blocks,
            .total_inverse_blocks = self.total_inverse_blocks,
            .total_chain_blocks = self.total_row_blocks,
            .total_row_blocks = self.total_row_blocks,
            .topology_identity = self.topology_identity,
        };
    }

    pub fn preparedInputShape(self: *const Plan) !PreparedInputShape {
        var source_pointer_words: u64 = 0;
        var descriptor_words: u64 = 0;
        var output_pointer_words: u64 = 0;
        var denominator_secure_fields: u64 = 0;
        var interaction_coordinate_cells: u64 = 0;
        for (self.instances) |instance| {
            source_pointer_words = try checkedAddU64(
                source_pointer_words,
                try checkedMulU64(instance.source_pointer_count, pointer_words),
            );
            descriptor_words = try checkedAddU64(
                descriptor_words,
                try checkedMulU64(
                    instance.geometry.columns,
                    relation_abi.descriptor_words,
                ),
            );
            output_pointer_words = try checkedAddU64(
                output_pointer_words,
                try checkedMulU64(
                    try checkedMulU64(instance.geometry.columns, 4),
                    pointer_words,
                ),
            );
            const values = try checkedMulU64(
                instance.geometry.rows,
                instance.geometry.columns,
            );
            denominator_secure_fields = try checkedAddU64(
                denominator_secure_fields,
                values,
            );
            interaction_coordinate_cells = try checkedAddU64(
                interaction_coordinate_cells,
                try checkedMulU64(values, 4),
            );
        }
        const count = std.math.cast(u32, self.instances.len) orelse
            return Error.GeometryOverflow;
        return .{
            .instance_count = count,
            .top_level_pointer_words = try checkedMulU32(
                count,
                pointer_words,
            ),
            .geometry_records = count,
            .max_alpha_powers = self.max_alpha_powers,
            .source_pointer_words = source_pointer_words,
            .descriptor_words = descriptor_words,
            .output_pointer_words = output_pointer_words,
            .denominator_secure_fields = denominator_secure_fields,
            .interaction_coordinate_cells = interaction_coordinate_cells,
            .scratch_words = try self.topology().scratchWords(),
        };
    }

    /// Uploads the canonical relation graph and only then returns an immutable
    /// runtime plan. Callers provide arena storage and semantic source/output
    /// slices; pointer tables, descriptors, geometry, and top-level tables are
    /// always derived here from the authenticated plan.
    pub fn prepareAndUpload(
        self: *const Plan,
        allocator: std.mem.Allocator,
        uploader: anytype,
        buffers: relation_stage.DeviceBuffers,
        device: []const DeviceInstanceBinding,
    ) !*relation_stage.PreparedPlan {
        if (device.len != self.instances.len)
            return Error.InvalidPreparedInputShape;
        const bindings = try allocator.alloc(
            relation_stage.InstanceBinding,
            device.len,
        );
        defer allocator.free(bindings);
        var extent_count: usize = 0;
        for (self.instances) |instance| {
            extent_count = std.math.add(
                usize,
                extent_count,
                instance.source_pointer_count,
            ) catch return Error.GeometryOverflow;
        }
        const source_extents = try allocator.alloc(u32, extent_count);
        defer allocator.free(source_extents);
        var extent_cursor: usize = 0;
        for (self.instances, device, bindings) |instance, resident, *binding| {
            if (resident.source_columns.len != instance.source_pointer_count or
                resident.output_coordinates.len !=
                    try checkedMulU32(instance.geometry.columns, 4))
            {
                return Error.InvalidPreparedInputShape;
            }
            const extent_end = std.math.add(
                usize,
                extent_cursor,
                instance.source_pointer_count,
            ) catch return Error.GeometryOverflow;
            const extents = source_extents[extent_cursor..extent_end];
            try ingress.sourceWordExtents(instance, extents);
            binding.* = .{
                .source_pointer_table = resident.source_pointer_table,
                .source_columns = resident.source_columns,
                .source_word_extents = extents,
                .lookup_word_columns = instance.lookup_word_columns,
                .descriptor_storage = resident.descriptor_storage,
                .descriptors = instance.descriptors,
                .output_pointer_table = resident.output_pointer_table,
                .output_coordinates = resident.output_coordinates,
                .denominator_slab = resident.denominator_slab,
                .claimed_sum = resident.claimed_sum,
            };
            extent_cursor = extent_end;
        }
        std.debug.assert(extent_cursor == source_extents.len);
        const prepared = try relation_stage.prepare(allocator, .{
            .topology = self.topology(),
            .buffers = buffers,
            .instances = bindings,
        });
        errdefer relation_stage.deinit(allocator, prepared);
        const prepared_identity = relation_stage.topologyIdentity(prepared);
        if (!std.mem.eql(
            u8,
            &prepared_identity,
            &self.topology_identity,
        )) {
            return Error.InvalidRelationTrace;
        }
        try ingress.uploadCanonical(
            allocator,
            uploader,
            self,
            buffers,
            device,
        );
        return prepared;
    }
};

const Selection = struct {
    component_index: u32,
    relation_component_index: u32,
    relation_trace_index: u32,
    planned: *const proof_plan.Component,
    planned_rows: proof_plan.RowExtent,
    trace: *const relation_bundle.Trace,
};

fn selectCanonicalTraces(
    allocator: std.mem.Allocator,
    proof: *const proof_plan.CairoProofPlan,
    relations: relation_bundle.Bundle,
) ![]Selection {
    if (proof.components.len == 0 or
        proof.canonical_order.len != proof.components.len)
    {
        return Error.InvalidComponentOrder;
    }
    const selections = try allocator.alloc(Selection, proof.components.len);
    errdefer allocator.free(selections);
    for (proof.canonical_order, 0..) |component_index, canonical_ordinal| {
        if (component_index >= proof.components.len)
            return Error.InvalidComponentOrder;
        const planned = &proof.components[component_index];
        if (planned.canonical_ordinal != canonical_ordinal)
            return Error.InvalidComponentOrder;
        const relation_name = relationName(planned.name);
        const relation_index = findRelationComponent(
            relations,
            relation_name,
        ) orelse return Error.MissingRelationComponent;
        const relation_component = &relations.components[relation_index];
        const wanted_part = relationPart(planned.name);
        const trace_index = findTrace(
            relation_component.traces,
            wanted_part,
        ) orelse return Error.InvalidRelationTrace;
        const rows = try traceRows(planned, wanted_part);
        selections[canonical_ordinal] = .{
            .component_index = component_index,
            .relation_component_index = @intCast(relation_index),
            .relation_trace_index = @intCast(trace_index),
            .planned = planned,
            .planned_rows = rows,
            .trace = &relation_component.traces[trace_index],
        };
    }
    return selections;
}

fn validateRelationNames(relations: relation_bundle.Bundle) !void {
    for (relations.components, 0..) |component, index| {
        for (relations.components[0..index]) |previous| {
            if (std.mem.eql(u8, component.name, previous.name))
                return Error.DuplicateRelationComponent;
        }
    }
}

fn validateActiveTraceCoverage(
    proof: *const proof_plan.CairoProofPlan,
    relations: relation_bundle.Bundle,
    selections: []const Selection,
) !void {
    for (relations.components, 0..) |component, relation_index| {
        var active = false;
        for (proof.components) |planned| {
            if (std.mem.eql(u8, relationName(planned.name), component.name)) {
                active = true;
                break;
            }
        }
        if (!active) continue;
        for (component.traces, 0..) |_, trace_index| {
            var selected = false;
            for (selections) |selection| {
                if (selection.relation_component_index == relation_index and
                    selection.relation_trace_index == trace_index)
                {
                    selected = true;
                    break;
                }
            }
            if (!selected) return Error.InvalidRelationTrace;
        }
    }
}

fn relationName(component: []const u8) []const u8 {
    return if (std.mem.eql(u8, component, "memory_id_to_small"))
        "memory_id_to_big"
    else
        component;
}

fn relationPart(component: []const u8) relation_bundle.TracePart {
    if (std.mem.eql(u8, component, "memory_id_to_big"))
        return .each_memory_big;
    if (std.mem.eql(u8, component, "memory_id_to_small"))
        return .memory_small;
    return .component;
}

fn findRelationComponent(
    relations: relation_bundle.Bundle,
    name: []const u8,
) ?usize {
    for (relations.components, 0..) |component, index| {
        if (std.mem.eql(u8, component.name, name)) return index;
    }
    return null;
}

fn findTrace(
    traces: []const relation_bundle.Trace,
    part: relation_bundle.TracePart,
) ?usize {
    var found: ?usize = null;
    for (traces, 0..) |trace, index| {
        if (trace.part != part) continue;
        if (found != null) return null;
        found = index;
    }
    return found;
}

fn traceRows(
    component: *const proof_plan.Component,
    part: relation_bundle.TracePart,
) !proof_plan.RowExtent {
    const wanted: proof_plan.TracePartId = switch (part) {
        .component => .main,
        .each_memory_big => .{ .memory_big = component.instance },
        .memory_small => .memory_small,
    };
    var found: ?proof_plan.RowExtent = null;
    for (component.trace_parts) |trace_part| {
        if (!std.meta.eql(trace_part.id, wanted)) continue;
        if (found != null) return Error.InvalidProofGeometry;
        found = trace_part.rows;
    }
    if (found) |rows| return rows;

    // The current proof plan represents the split memory components with one
    // main part each. Keep that compatibility exact and name-gated.
    const split_memory = (part == .each_memory_big and
        std.mem.eql(u8, component.name, "memory_id_to_big")) or
        (part == .memory_small and
            std.mem.eql(u8, component.name, "memory_id_to_small"));
    if (!split_memory or component.trace_parts.len != 1 or
        component.trace_parts[0].id != .main)
    {
        return Error.InvalidProofGeometry;
    }
    return component.trace_parts[0].rows;
}

fn rowsFor(
    component: *const proof_plan.Component,
    part: relation_bundle.TracePart,
) !u32 {
    const extent = try traceRows(component, part);
    try extent.validate();
    if (extent.padded_rows >= 0x7fff_ffff)
        return Error.InvalidProofGeometry;
    return extent.padded_rows;
}

fn traceUsesRowEnabler(trace: *const relation_bundle.Trace) bool {
    var descriptor_index: usize = 0;
    while (descriptor_index < trace.descriptors.len) : (descriptor_index += relation_abi.descriptor_words) {
        const descriptor = trace.descriptors[descriptor_index .. descriptor_index + relation_abi.descriptor_words];
        for (0..descriptor[0]) |use_index| {
            if (descriptor[1 + use_index * relation_abi.use_words + 4] ==
                @intFromEnum(relation_abi.MultiplicityKind.enabler))
            {
                return true;
            }
        }
    }
    return false;
}

fn relationRealRows(
    proof: *const proof_plan.CairoProofPlan,
    selection: Selection,
) !u32 {
    if (selection.planned_rows.real_rows) |rows| return rows;
    const edges = selection.planned.producer_edges;
    if (edges.len == 0) return Error.InvalidProofGeometry;
    const compact = proof_plan.compactGeometry(
        selection.planned.name,
    ) != null;
    var total: u32 = 0;
    for (edges) |edge| {
        const producer = proof.find(edge.producer) orelse
            return Error.InvalidProofGeometry;
        const source = try traceRows(producer, .component);
        const producer_rows = if (compact)
            source.real_rows orelse return Error.InvalidProofGeometry
        else
            source.padded_rows;
        total = try checkedAddU32(
            total,
            try checkedMulU32(producer_rows, edge.instances),
        );
    }
    if (total == 0 or total > selection.planned_rows.padded_rows)
        return Error.InvalidProofGeometry;
    return total;
}

fn traceAlphaPowers(trace: *const relation_bundle.Trace) !u32 {
    var maximum: u32 = 0;
    var descriptor_index: usize = 0;
    while (descriptor_index < trace.descriptors.len) : (descriptor_index += relation_abi.descriptor_words) {
        const descriptor = trace.descriptors[descriptor_index .. descriptor_index + relation_abi.descriptor_words];
        if (descriptor[0] == 0 or descriptor[0] > 2)
            return Error.InvalidRelationTrace;
        for (0..descriptor[0]) |use_index| {
            maximum = @max(
                maximum,
                descriptor[1 + use_index * relation_abi.use_words + 2],
            );
        }
    }
    return maximum;
}

fn translateDescriptors(
    destination: []relation_abi.ColumnDescriptor,
    trace: *const relation_bundle.Trace,
    max_alpha_powers: u32,
) !void {
    const bounds = relation_abi.SourceBounds{
        .source_pointer_count = try sourcePointerCount(trace),
        .lookup_word_columns = if (trace.layout == .lookup_words)
            trace.layout_arg
        else
            0,
        .max_alpha_powers = max_alpha_powers,
    };
    for (destination, 0..) |*descriptor, index| {
        const first = index * relation_abi.descriptor_words;
        const words = trace.descriptors[first .. first + relation_abi.descriptor_words];
        descriptor.* = .{
            .arity = words[0],
            .first = useDescriptor(words[1..8]),
            .second = useDescriptor(words[8..15]),
            .reserved = words[15],
        };
        try descriptor.validate(bounds);
    }
}

fn useDescriptor(words: []const u32) relation_abi.UseDescriptor {
    std.debug.assert(words.len == relation_abi.use_words);
    return .{
        .tuple_kind = words[0],
        .tuple_argument = words[1],
        .tuple_words = words[2],
        .relation_id = words[3],
        .multiplicity_kind = words[4],
        .multiplicity_argument = words[5],
        .negative = words[6],
    };
}

fn sourcePointerCount(trace: *const relation_bundle.Trace) !u32 {
    return switch (trace.layout) {
        .lookup_words => 1,
        .memory_address => checkedMulU32(trace.layout_arg, 2),
        .memory_big, .memory_small => checkedAddU32(trace.layout_arg, 1),
        .bitwise_xor_12 => trace.layout_arg,
    };
}

fn validateLayoutDomain(
    trace: *const relation_bundle.Trace,
    geometry: relation_abi.Geometry,
) !void {
    const part_valid = switch (trace.layout) {
        .lookup_words, .memory_address, .bitwise_xor_12 => trace.part == .component,
        .memory_big => trace.part == .each_memory_big,
        .memory_small => trace.part == .memory_small,
    };
    if (!part_valid) return Error.InvalidRelationTrace;

    switch (trace.layout) {
        .lookup_words, .memory_small => {
            if (geometry.source_offset_rows != 0)
                return Error.InvalidProofGeometry;
        },
        .memory_address => {
            const address_end = try checkedMulU64(
                trace.layout_arg,
                geometry.rows,
            );
            if (geometry.source_offset_rows != 0 or
                address_end >= m31_modulus)
            {
                return Error.InvalidProofGeometry;
            }
        },
        .memory_big => {
            const end = try checkedAddU64(
                geometry.source_offset_rows,
                geometry.rows,
            );
            if (end > large_memory_value_id_base)
                return Error.InvalidProofGeometry;
        },
        .bitwise_xor_12 => {
            if (geometry.source_offset_rows != 0 or
                geometry.rows != xor_12_rows or
                geometry.real_rows != xor_12_rows)
            {
                return Error.InvalidProofGeometry;
            }
        },
    }
}

fn topologyIdentity(graph_hash: u64, plan: *const Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/relation-topology/v1\x00");
    hashInt(&hash, u64, graph_hash);
    hashInt(&hash, u64, plan.instances.len);
    hashInt(&hash, u32, plan.max_alpha_powers);
    hashInt(&hash, u32, plan.total_pair_blocks);
    hashInt(&hash, u32, plan.total_inverse_blocks);
    hashInt(&hash, u32, plan.total_row_blocks);
    for (plan.instances) |instance| {
        hashInt(&hash, u32, instance.component_index);
        hashInt(&hash, u32, instance.component_instance);
        hashInt(&hash, u32, instance.relation_component_index);
        hashInt(&hash, u32, instance.relation_trace_index);
        hashInt(&hash, u64, instance.component.len);
        hash.update(instance.component);
        hashInt(&hash, u32, @intFromEnum(instance.part));
        hashInt(&hash, u32, @intFromEnum(instance.layout));
        hashInt(&hash, u32, instance.source_pointer_count);
        hashInt(&hash, u32, instance.lookup_word_columns);
        inline for (std.meta.fields(relation_abi.Geometry)) |field| {
            hashInt(
                &hash,
                u32,
                @field(instance.geometry, field.name),
            );
        }
        hashInt(&hash, u64, instance.descriptors.len);
        for (instance.descriptors) |descriptor| {
            hashInt(&hash, u32, descriptor.arity);
            hashUse(&hash, descriptor.first);
            hashUse(&hash, descriptor.second);
            hashInt(&hash, u32, descriptor.reserved);
        }
    }
    return hash.finalResult();
}

fn hashUse(
    hash: *std.crypto.hash.sha2.Sha256,
    use: relation_abi.UseDescriptor,
) void {
    inline for (std.meta.fields(relation_abi.UseDescriptor)) |field|
        hashInt(hash, u32, @field(use, field.name));
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: T,
) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn inverseRows(rows: u32) u32 {
    std.debug.assert(rows != 0 and std.math.isPowerOfTwo(rows));
    const log_rows = std.math.log2_int(u32, rows);
    return if (log_rows == 0)
        1
    else
        @as(u32, 1) << @intCast(31 - log_rows);
}

fn blocks(values: u32, block_size: u32) u32 {
    return values / block_size + @intFromBool(values % block_size != 0);
}

fn checkedAddU32(left: anytype, right: anytype) !u32 {
    const lhs = std.math.cast(u32, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u32, right) orelse return Error.GeometryOverflow;
    return std.math.add(u32, lhs, rhs) catch Error.GeometryOverflow;
}

fn checkedMulU32(left: anytype, right: anytype) !u32 {
    const lhs = std.math.cast(u32, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u32, right) orelse return Error.GeometryOverflow;
    return std.math.mul(u32, lhs, rhs) catch Error.GeometryOverflow;
}

fn checkedMulUsize(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return Error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return Error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch Error.GeometryOverflow;
}

fn checkedAddU64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return Error.GeometryOverflow;
    return std.math.add(u64, lhs, rhs) catch Error.GeometryOverflow;
}

fn checkedMulU64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return Error.GeometryOverflow;
    return std.math.mul(u64, lhs, rhs) catch Error.GeometryOverflow;
}
