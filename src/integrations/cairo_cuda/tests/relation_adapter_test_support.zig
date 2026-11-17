//! Shared fixtures and independent relation oracles for this test owner.
const std = @import("std");
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const field = @import("stwo_cuda_backend").abi.field;
const column = @import("stwo_cuda_backend").runtime.column;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const adapter = @import("../relation_adapter.zig");

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    composition: composition_bundle.Bundle,
    relations: relation_bundle.Bundle,
    proof: proof_plan.CairoProofPlan,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        var composition = try composition_bundle.Bundle.readFile(
            allocator,
            "vectors/cairo/sn_pie_2_composition.bin",
        );
        errdefer composition.deinit();
        var relations = try relation_bundle.Bundle.readFile(
            allocator,
            "vectors/cairo/cairo_relation_templates.bin",
        );
        errdefer relations.deinit();
        const parts = try allocator.alloc(
            proof_plan.TracePart,
            composition.components.len,
        );
        defer allocator.free(parts);
        const components = try allocator.alloc(
            proof_plan.Component,
            composition.components.len,
        );
        defer allocator.free(components);
        for (
            composition.components,
            parts,
            components,
            0..,
        ) |component, *part, *planned, index| {
            const rows = @as(u32, 1) <<
                @intCast(component.trace_log_size);
            part.* = .{
                .id = .main,
                .rows = .{
                    .real_rows = if (derivedRelationRows(component.label))
                        null
                    else
                        rows,
                    .padded_rows = rows,
                },
            };
            planned.* = .{
                .name = component.label,
                .instance = component.instance,
                .canonical_ordinal = @intCast(index),
                .writer = .recorded_aot,
                .trace_parts = parts[index .. index + 1],
                .producer_edges = if (derivedRelationRows(component.label))
                    proof_plan.gatheredProducerEdges(component.label).?
                else
                    &.{},
                .capacity_feeds = &.{},
            };
        }
        return .{
            .allocator = allocator,
            .composition = composition,
            .relations = relations,
            .proof = try proof_plan.CairoProofPlan.init(
                allocator,
                components,
            ),
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.proof.deinit();
        self.relations.deinit();
        self.composition.deinit();
        self.* = undefined;
    }
};

pub const device_owner: usize = 71;
pub const device_generation: u64 = 13;

pub const DeviceFixture = struct {
    allocator: std.mem.Allocator,
    buffers: relation_stage.DeviceBuffers,
    instances: []adapter.DeviceInstanceBinding,
    source_storage: []common.Words,
    output_storage: []common.Words,

    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const adapter.Plan,
    ) !DeviceFixture {
        var source_count: usize = 0;
        var output_count: usize = 0;
        for (plan.instances) |instance| {
            source_count = try checkedAdd(source_count, instance.source_pointer_count);
            output_count = try checkedAdd(
                output_count,
                try mul(instance.geometry.columns, 4),
            );
        }
        const instances = try allocator.alloc(
            adapter.DeviceInstanceBinding,
            plan.instances.len,
        );
        errdefer allocator.free(instances);
        const sources = try allocator.alloc(common.Words, source_count);
        errdefer allocator.free(sources);
        const outputs = try allocator.alloc(common.Words, output_count);
        errdefer allocator.free(outputs);

        var cursor: usize = 0x10_0000;
        var source_cursor: usize = 0;
        var output_cursor: usize = 0;
        for (plan.instances, instances) |instance, *resident| {
            const source_end = try checkedAdd(
                source_cursor,
                instance.source_pointer_count,
            );
            const source_columns = sources[source_cursor..source_end];
            for (source_columns, 0..) |*source, source_index| {
                const extent = if (instance.layout == .lookup_words)
                    try mul(
                        instance.geometry.rows,
                        instance.lookup_word_columns,
                    )
                else
                    instance.geometry.rows;
                if (instance.layout == .lookup_words and source_index != 0)
                    return error.InvalidTestFixture;
                source.* = try deviceSlice(u32, &cursor, extent);
            }
            const coordinates = try mul(instance.geometry.columns, 4);
            const output_end = try checkedAdd(output_cursor, coordinates);
            const output_columns = outputs[output_cursor..output_end];
            for (output_columns) |*output| {
                output.* = try deviceSlice(
                    u32,
                    &cursor,
                    instance.geometry.rows,
                );
            }
            resident.* = .{
                .source_pointer_table = try deviceSlice(
                    u32,
                    &cursor,
                    try mul(instance.source_pointer_count, 2),
                ),
                .source_columns = source_columns,
                .descriptor_storage = try deviceSlice(
                    u32,
                    &cursor,
                    try mul(
                        instance.geometry.columns,
                        relation_abi.descriptor_words,
                    ),
                ),
                .output_pointer_table = try deviceSlice(
                    u32,
                    &cursor,
                    try mul(coordinates, 2),
                ),
                .output_coordinates = output_columns,
                .denominator_slab = try deviceSlice(
                    field.SecureField,
                    &cursor,
                    try mul(
                        instance.geometry.rows,
                        instance.geometry.columns,
                    ),
                ),
                .claimed_sum = try deviceSlice(
                    field.SecureField,
                    &cursor,
                    1,
                ),
            };
            source_cursor = source_end;
            output_cursor = output_end;
        }
        std.debug.assert(source_cursor == sources.len);
        std.debug.assert(output_cursor == outputs.len);

        const count = plan.instances.len;
        const pointer_table_words = try mul(count, 2);
        const scratch_words = try plan.topology().scratchWords();
        const buffers = relation_stage.DeviceBuffers{
            .drawn_z_alpha = try deviceSlice(
                field.SecureField,
                &cursor,
                2,
            ),
            .alpha_powers = try deviceSlice(
                field.SecureField,
                &cursor,
                plan.max_alpha_powers,
            ),
            .z = try deviceSlice(field.SecureField, &cursor, 1),
            .source_tables = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .descriptors = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .output_tables = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .denominator_slabs = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .geometry = try deviceSlice(
                relation_abi.Geometry,
                &cursor,
                count,
            ),
            .claimed_sums = try deviceSlice(
                u32,
                &cursor,
                pointer_table_words,
            ),
            .reduction_partials = try deviceSlice(
                u32,
                &cursor,
                scratch_words,
            ),
            .scan_block_sums = try deviceSlice(
                u32,
                &cursor,
                scratch_words,
            ),
        };
        return .{
            .allocator = allocator,
            .buffers = buffers,
            .instances = instances,
            .source_storage = sources,
            .output_storage = outputs,
        };
    }

    pub fn deinit(self: *DeviceFixture) void {
        self.allocator.free(self.output_storage);
        self.allocator.free(self.source_storage);
        self.allocator.free(self.instances);
        self.* = undefined;
    }
};

pub const UploadRecorder = struct {
    calls: u32 = 0,
    descriptor_records: usize = 0,
    geometry_records: usize = 0,
    first_pointer: usize = 0,

    pub fn uploadSlice(
        self: *UploadRecorder,
        comptime F: type,
        destination: column.DeviceSlice(F),
        source: []const F,
    ) !void {
        if (destination.len != source.len) return error.InvalidUpload;
        if (self.calls == 0 and F == u32 and source.len >= 2) {
            self.first_pointer =
                @as(usize, source[0]) |
                (@as(usize, source[1]) << 32);
        }
        if (F == relation_abi.ColumnDescriptor)
            self.descriptor_records += source.len;
        if (F == relation_abi.Geometry)
            self.geometry_records += source.len;
        self.calls += 1;
    }
};

pub fn deviceSlice(
    comptime F: type,
    cursor: *usize,
    len: usize,
) !column.DeviceSlice(F) {
    if (len == 0) return error.InvalidTestFixture;
    const address = std.mem.alignForward(usize, cursor.*, @alignOf(F));
    const bytes = try mul(len, @sizeOf(F));
    cursor.* = try checkedAdd(address, bytes);
    return .{
        .address = address,
        .len = len,
        .owner = device_owner,
        .generation = device_generation,
    };
}

pub fn derivedRelationRows(component: []const u8) bool {
    return std.mem.eql(u8, component, "blake_round") or
        std.mem.eql(u8, component, "partial_ec_mul_window_bits_18") or
        std.mem.eql(u8, component, "cube_252");
}

pub fn expectedRelationRealRows(component: []const u8, padded_rows: u32) u32 {
    if (std.mem.eql(u8, component, "blake_round")) return 655_360;
    if (std.mem.eql(u8, component, "partial_ec_mul_window_bits_18"))
        return 917_504;
    if (std.mem.eql(u8, component, "cube_252")) return 499_712;
    return padded_rows;
}

pub fn checkedAdd(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.add(usize, lhs, rhs) catch error.SizeOverflow;
}

pub fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}

pub fn findInstance(
    plan: *const adapter.Plan,
    name: []const u8,
) ?*const adapter.Instance {
    for (plan.instances) |*instance| {
        if (std.mem.eql(u8, instance.component, name)) return instance;
    }
    return null;
}

pub fn ceilDiv(value: u32, divisor: u32) u32 {
    return value / divisor + @intFromBool(value % divisor != 0);
}

pub fn inverseRows(rows: u32) u32 {
    const log_rows = std.math.log2_int(u32, rows);
    return if (log_rows == 0)
        1
    else
        @as(u32, 1) << @intCast(31 - log_rows);
}
