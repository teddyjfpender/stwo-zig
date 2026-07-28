//! Exact-height SN2 relation fixture derived from the authenticated plan.
//!
//! Lookup-word sources use deterministic constant columns. This makes the
//! checked-in oracle compact while retaining the exact row domain, descriptor
//! graph, multiplicity policy, and claimed-sum arithmetic. Address, memory,
//! and bitwise layouts still evaluate every canonical row because their tuple
//! semantics depend on the row index.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const proof_plan = @import("stwo_cairo_frontend").proof_plan;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const interaction = @import("stwo_cairo_frontend").witness.interaction_trace;
const relation_bundle = @import("stwo_cairo_frontend").witness.relation_bundle;
const relation_abi = @import(
    "../../backends/cuda/abi/stages/relation.zig",
);
const adapter = @import("relation_adapter.zig");

pub const drawn_z = [4]u32{ 101, 103, 107, 109 };
pub const drawn_alpha = [4]u32{ 3, 5, 7, 11 };

pub const Instance = struct {
    component: []const u8,
    component_index: u32,
    component_instance: u32,
    layout: relation_bundle.SourceLayout,
    geometry: relation_abi.Geometry,
    source_pointer_count: u32,
    lookup_word_columns: u32,
    descriptor_offset: u32,
    claimed_sum: [4]u32,
    cumulative_sum: [4]u32,
};

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    graph_hash: u64,
    topology_identity: [32]u8,
    max_alpha_powers: u32,
    alpha_powers: [][4]u32,
    descriptors: []u32,
    instances: []Instance,

    pub fn deinit(self: *Fixture) void {
        self.allocator.free(self.alpha_powers);
        self.allocator.free(self.descriptors);
        self.allocator.free(self.instances);
        self.* = undefined;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    composition: composition_bundle.Bundle,
    relations: relation_bundle.Bundle,
) !Fixture {
    var proof = try proofFromComposition(allocator, composition);
    defer proof.deinit();
    var plan = try adapter.Plan.compile(allocator, &proof, relations);
    defer plan.deinit();

    const alpha_powers = try allocator.alloc(
        [4]u32,
        plan.max_alpha_powers,
    );
    errdefer allocator.free(alpha_powers);
    const alpha = qm31(drawn_alpha);
    var power = QM31.one();
    for (alpha_powers) |*words| {
        words.* = coordinates(power);
        power = power.mul(alpha);
    }
    const scalar_powers = try allocator.alloc(QM31, alpha_powers.len);
    defer allocator.free(scalar_powers);
    for (alpha_powers, scalar_powers) |words, *value| value.* = qm31(words);

    const descriptors = try allocator.alloc(
        u32,
        plan.descriptor_storage.len * relation_abi.descriptor_words,
    );
    errdefer allocator.free(descriptors);
    const instances = try allocator.alloc(Instance, plan.instances.len);
    errdefer allocator.free(instances);

    var descriptor_cursor: usize = 0;
    var cumulative = QM31.zero();
    for (plan.instances, instances, 0..) |planned, *fixture, ordinal| {
        const trace = relations.components[planned.relation_component_index]
            .traces[planned.relation_trace_index];
        const descriptor_words = trace.descriptors;
        const descriptor_end = descriptor_cursor + descriptor_words.len;
        @memcpy(descriptors[descriptor_cursor..descriptor_end], descriptor_words);
        const claimed_sum = try claimedSum(
            allocator,
            @intCast(ordinal),
            planned,
            trace,
            qm31(drawn_z),
            scalar_powers,
        );
        cumulative = cumulative.add(claimed_sum);
        fixture.* = .{
            .component = planned.component,
            .component_index = planned.component_index,
            .component_instance = planned.component_instance,
            .layout = planned.layout,
            .geometry = localGeometry(planned.geometry),
            .source_pointer_count = planned.source_pointer_count,
            .lookup_word_columns = planned.lookup_word_columns,
            .descriptor_offset = @intCast(descriptor_cursor),
            .claimed_sum = coordinates(claimed_sum),
            .cumulative_sum = coordinates(cumulative),
        };
        descriptor_cursor = descriptor_end;
    }
    std.debug.assert(descriptor_cursor == descriptors.len);
    return .{
        .allocator = allocator,
        .graph_hash = relations.graph_hash,
        .topology_identity = plan.topology_identity,
        .max_alpha_powers = plan.max_alpha_powers,
        .alpha_powers = alpha_powers,
        .descriptors = descriptors,
        .instances = instances,
    };
}

pub fn renderHeader(
    allocator: std.mem.Allocator,
    fixture: Fixture,
) ![]u8 {
    var output = std.ArrayList(u8).empty;
    errdefer output.deinit(allocator);
    const writer = output.writer(allocator);
    try writer.writeAll(
        \\#ifndef STWO_ZIG_CUDA_SN2_RELATION_PARITY_FIXTURE_H
        \\#define STWO_ZIG_CUDA_SN2_RELATION_PARITY_FIXTURE_H
        \\
        \\#include <cstddef>
        \\#include <cstdint>
        \\
        \\namespace stwo::cuda::test::sn2_relation {
        \\
        \\struct Geometry {
        \\    std::uint32_t pair_first;
        \\    std::uint32_t pair_blocks;
        \\    std::uint32_t inverse_first;
        \\    std::uint32_t inverse_blocks;
        \\    std::uint32_t row_first;
        \\    std::uint32_t row_blocks;
        \\    std::uint32_t rows;
        \\    std::uint32_t columns;
        \\    std::uint32_t real_rows;
        \\    std::uint32_t source_offset_rows;
        \\    std::uint32_t inverse_rows;
        \\};
        \\
        \\struct Instance {
        \\    const char *component;
        \\    std::uint32_t component_index;
        \\    std::uint32_t component_instance;
        \\    std::uint32_t layout;
        \\    Geometry geometry;
        \\    std::uint32_t source_pointer_count;
        \\    std::uint32_t lookup_word_columns;
        \\    std::uint32_t descriptor_offset;
        \\    std::uint32_t claimed_sum[4];
        \\    std::uint32_t cumulative_sum[4];
        \\};
        \\
    );
    try writer.print(
        "inline constexpr std::uint64_t kGraphHash = 0x{x:0>16}ull;\n",
        .{fixture.graph_hash},
    );
    try writer.print(
        "inline constexpr std::uint32_t kMaxAlphaPowers = {}u;\n",
        .{fixture.max_alpha_powers},
    );
    try writeWords(writer, "kDrawnZAlpha", &(drawn_z ++ drawn_alpha));
    try writeBytes(
        writer,
        "kTopologyIdentity",
        &fixture.topology_identity,
    );
    try writeQm31Words(writer, "kAlphaPowers", fixture.alpha_powers);
    try writeWords(writer, "kDescriptors", fixture.descriptors);
    try writer.writeAll("inline constexpr Instance kInstances[] = {\n");
    for (fixture.instances) |instance| {
        const geometry = instance.geometry;
        try writer.print(
            "    {{\"{s}\", {}u, {}u, {}u, " ++
                "{{{}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u}}, " ++
                "{}u, {}u, {}u, " ++
                "{{{}u, {}u, {}u, {}u}}, " ++
                "{{{}u, {}u, {}u, {}u}}}},\n",
            .{
                instance.component,
                instance.component_index,
                instance.component_instance,
                @intFromEnum(instance.layout),
                geometry.pair_first,
                geometry.pair_blocks,
                geometry.inverse_first,
                geometry.inverse_blocks,
                geometry.row_first,
                geometry.row_blocks,
                geometry.rows,
                geometry.columns,
                geometry.real_rows,
                geometry.source_offset_rows,
                geometry.inverse_rows,
                instance.source_pointer_count,
                instance.lookup_word_columns,
                instance.descriptor_offset,
                instance.claimed_sum[0],
                instance.claimed_sum[1],
                instance.claimed_sum[2],
                instance.claimed_sum[3],
                instance.cumulative_sum[0],
                instance.cumulative_sum[1],
                instance.cumulative_sum[2],
                instance.cumulative_sum[3],
            },
        );
    }
    try writer.writeAll(
        \\};
        \\inline constexpr std::size_t kInstanceCount =
        \\    sizeof(kInstances) / sizeof(kInstances[0]);
        \\
        \\}  // namespace stwo::cuda::test::sn2_relation
        \\
        \\#endif
        \\
    );
    return output.toOwnedSlice(allocator);
}

fn proofFromComposition(
    allocator: std.mem.Allocator,
    composition: composition_bundle.Bundle,
) !proof_plan.CairoProofPlan {
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
    for (composition.components, parts, components, 0..) |
        component,
        *part,
        *planned,
        index,
    | {
        const rows = @as(u32, 1) << @intCast(component.trace_log_size);
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
    return proof_plan.CairoProofPlan.init(allocator, components);
}

fn claimedSum(
    allocator: std.mem.Allocator,
    ordinal: u32,
    planned: adapter.Instance,
    trace: relation_bundle.Trace,
    z: QM31,
    alpha_powers: []const QM31,
) !QM31 {
    if (trace.layout == .lookup_words) {
        const rows: usize = 2;
        const words = try allocator.alloc(u32, trace.layout_arg * rows);
        defer allocator.free(words);
        for (0..trace.layout_arg) |column| {
            @memset(
                words[column * rows ..][0..rows],
                sourceValue(ordinal, @intCast(column)),
            );
        }
        var reference = try interaction.Reference.init(
            allocator,
            trace.descriptors,
            try interaction.SourceView.lookupWords(
                try interaction.LookupColumns.init(words, rows),
                if (planned.geometry.real_rows == planned.geometry.rows)
                    rows
                else
                    1,
            ),
            z,
            alpha_powers,
        );
        defer reference.deinit();
        const cumulative = try allocator.alloc(QM31, trace.output_columns);
        defer allocator.free(cumulative);
        const active = try reference.evaluateRow(0, cumulative);
        const inactive = if (planned.geometry.real_rows == planned.geometry.rows)
            QM31.zero()
        else
            try reference.evaluateRow(1, cumulative);
        return active.mulM31(M31.fromCanonical(planned.geometry.real_rows))
            .add(inactive.mulM31(M31.fromCanonical(
            planned.geometry.rows - planned.geometry.real_rows,
        )));
    }

    const source_count: usize = planned.source_pointer_count;
    const rows: usize = planned.geometry.rows;
    const source_words = try allocator.alloc(u32, source_count * rows);
    defer allocator.free(source_words);
    const columns = try allocator.alloc([]const u32, source_count);
    defer allocator.free(columns);
    for (columns, 0..) |*column, index| {
        const values = source_words[index * rows ..][0..rows];
        @memset(values, sourceValue(ordinal, @intCast(index)));
        column.* = values;
    }
    const sparse = try interaction.SparseColumns.init(columns, rows);
    const source = switch (trace.layout) {
        .lookup_words => unreachable,
        .memory_address => try interaction.SourceView.memoryAddress(
            sparse,
            trace.layout_arg,
            planned.geometry.real_rows,
        ),
        .memory_big => try interaction.SourceView.memoryBig(
            sparse,
            trace.layout_arg,
            planned.geometry.real_rows,
            planned.geometry.source_offset_rows,
        ),
        .memory_small => try interaction.SourceView.memorySmall(
            sparse,
            trace.layout_arg,
            planned.geometry.real_rows,
            planned.geometry.source_offset_rows,
        ),
        .bitwise_xor_12 => try interaction.SourceView.bitwiseXor12(
            sparse,
            trace.layout_arg,
            planned.geometry.real_rows,
        ),
    };
    var reference = try interaction.Reference.init(
        allocator,
        trace.descriptors,
        source,
        z,
        alpha_powers,
    );
    defer reference.deinit();
    const cumulative = try allocator.alloc(QM31, trace.output_columns);
    defer allocator.free(cumulative);
    var result = QM31.zero();
    for (0..rows) |row| {
        result = result.add(try reference.evaluateRow(row, cumulative));
    }
    return result;
}

pub fn sourceByte(ordinal: u32, source_column: u32) u8 {
    return @intCast(1 + (ordinal * 17 + source_column * 13) % 126);
}

pub fn sourceValue(ordinal: u32, source_column: u32) u32 {
    return @as(u32, sourceByte(ordinal, source_column)) * 0x01010101;
}

fn localGeometry(geometry: relation_abi.Geometry) relation_abi.Geometry {
    var result = geometry;
    result.pair_first = 0;
    result.inverse_first = 0;
    result.row_first = 0;
    return result;
}

fn derivedRelationRows(component: []const u8) bool {
    return std.mem.eql(u8, component, "blake_round") or
        std.mem.eql(u8, component, "partial_ec_mul_window_bits_18") or
        std.mem.eql(u8, component, "cube_252");
}

fn qm31(words: [4]u32) QM31 {
    return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
}

fn coordinates(value: QM31) [4]u32 {
    const words = value.toM31Array();
    return .{ words[0].v, words[1].v, words[2].v, words[3].v };
}

fn writeWords(
    writer: anytype,
    name: []const u8,
    words: []const u32,
) !void {
    try writer.print(
        "inline constexpr std::uint32_t {s}[{}] = {{\n",
        .{ name, words.len },
    );
    for (words, 0..) |word, index| {
        if (index % 8 == 0) try writer.writeAll("    ");
        try writer.print("{}u", .{word});
        if (index + 1 != words.len) {
            try writer.writeByte(',');
            if (index % 8 != 7) try writer.writeByte(' ');
        }
        if (index % 8 == 7 or index + 1 == words.len)
            try writer.writeByte('\n');
    }
    try writer.writeAll("};\n\n");
}

fn writeQm31Words(
    writer: anytype,
    name: []const u8,
    words: []const [4]u32,
) !void {
    try writer.print(
        "inline constexpr std::uint32_t {s}[{}][4] = {{\n",
        .{ name, words.len },
    );
    for (words) |value| {
        try writer.print(
            "    {{{}u, {}u, {}u, {}u}},\n",
            .{ value[0], value[1], value[2], value[3] },
        );
    }
    try writer.writeAll("};\n\n");
}

fn writeBytes(
    writer: anytype,
    name: []const u8,
    bytes: []const u8,
) !void {
    try writer.print(
        "inline constexpr std::uint8_t {s}[{}] = {{\n    ",
        .{ name, bytes.len },
    );
    for (bytes, 0..) |byte, index| {
        try writer.print("0x{x:0>2}u", .{byte});
        if (index + 1 != bytes.len) {
            try writer.writeByte(',');
            if (index % 8 != 7) try writer.writeByte(' ');
        }
        if (index % 8 == 7 and index + 1 != bytes.len)
            try writer.writeAll("\n    ");
    }
    try writer.writeAll("\n};\n\n");
}
