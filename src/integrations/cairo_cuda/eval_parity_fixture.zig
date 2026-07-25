//! Bounded, exact-semantics fixture for the SN2 CUDA constraint differential.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const composition = @import("../../frontends/cairo/witness/composition_bundle.zig");
const geometry = @import("../../frontends/cairo/witness/resident_geometry.zig");
const eval_aot = @import("eval_aot.zig");
const oracle = @import("eval_simd_oracle.zig");

pub const palette_values = [_]u32{ 3, 5, 7, 11, 13, 17, 19, 23 };
pub const fixture_rows = oracle.lane_count;

pub const Component = struct {
    label: []const u8,
    instance: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    trace_offsets: u64,
    interaction_offsets: u64,
    base_params: u64,
    ext_params_offset: u64,
    denominator_inverses: u64,
    ext_params: []oracle.Qm31Words,
};

pub const Placement = struct {
    cache_key: u64,
    kernel_name: []const u8,
    component_index: u32,
    instance: u32,
    part_index: u32,
    global_rc_base: u32,
    domain_log_size: u32,
    expected: [fixture_rows]oracle.Qm31Words,
};

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    max_rows: u64,
    metadata_offset: u64,
    arena_words: u64,
    random_coefficients_offset: u64,
    coordinates_offset: u64,
    metadata_words: []u32,
    random_coefficients: []oracle.Qm31Words,
    components: []Component,
    placements: []Placement,
    zero_inversions: usize,

    pub fn deinit(self: *Fixture) void {
        for (self.components) |component| {
            self.allocator.free(component.ext_params);
        }
        self.allocator.free(self.metadata_words);
        self.allocator.free(self.random_coefficients);
        self.allocator.free(self.components);
        self.allocator.free(self.placements);
        self.* = undefined;
    }
};

const TraceContext = struct {
    component: *const composition.Component,
    base_span: geometry.Span,
    interaction_span: geometry.Span,
};

pub fn build(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
    product: eval_aot.Product,
) !Fixture {
    if (bundle.max_evaluation_log_size >= 32)
        return error.InvalidFixtureDomain;
    const max_rows = @as(u64, 1) <<
        @intCast(bundle.max_evaluation_log_size);
    const metadata_offset = std.math.mul(
        u64,
        palette_values.len,
        max_rows,
    ) catch return error.FixtureTooLarge;
    if (metadata_offset >= std.math.maxInt(u32))
        return error.FixtureTooLarge;

    var metadata = std.ArrayList(u32).empty;
    defer metadata.deinit(allocator);
    const components = try allocator.alloc(
        Component,
        bundle.components.len,
    );
    errdefer allocator.free(components);
    var components_initialized: usize = 0;
    errdefer for (components[0..components_initialized]) |component| {
        allocator.free(component.ext_params);
    };
    while (components_initialized < components.len) : (components_initialized += 1) {
        const captured = &bundle.components[components_initialized];
        const base_span = try geometry.componentSpan(captured.*, 1);
        const interaction_span = try geometry.componentSpan(
            captured.*,
            2,
        );
        const trace_offsets = try buildTraceOffsets(
            allocator,
            captured,
            base_span,
            interaction_span,
            max_rows,
        );
        defer allocator.free(trace_offsets);
        const trace_offsets_offset = try appendWords(
            &metadata,
            allocator,
            metadata_offset,
            trace_offsets,
        );
        const interaction_starts = [_]u32{
            0,
            @intCast(captured.preprocessed_indices.len),
            @intCast(
                captured.preprocessed_indices.len +
                    (base_span.end - base_span.start),
            ),
        };
        const interaction_offsets = try appendWords(
            &metadata,
            allocator,
            metadata_offset,
            &interaction_starts,
        );
        const ext_params = try buildExtParams(
            allocator,
            captured,
            @intCast(components_initialized),
        );
        errdefer allocator.free(ext_params);
        const flat_ext = std.mem.sliceAsBytes(ext_params);
        const ext_words = std.mem.bytesAsSlice(u32, flat_ext);
        const ext_params_offset = try appendWords(
            &metadata,
            allocator,
            metadata_offset,
            ext_words,
        );
        const denominator_inverses = try appendWords(
            &metadata,
            allocator,
            metadata_offset,
            captured.denominator_inverses,
        );
        components[components_initialized] = .{
            .label = captured.label,
            .instance = captured.instance,
            .trace_log_size = captured.trace_log_size,
            .evaluation_log_size = captured.evaluation_log_size,
            .trace_offsets = trace_offsets_offset,
            .interaction_offsets = interaction_offsets,
            .base_params = ext_params_offset,
            .ext_params_offset = ext_params_offset,
            .denominator_inverses = denominator_inverses,
            .ext_params = ext_params,
        };
    }

    const random_coefficients = try allocator.alloc(
        oracle.Qm31Words,
        bundle.total_constraints,
    );
    errdefer allocator.free(random_coefficients);
    for (random_coefficients, 0..) |*value, index| {
        value.* = randomCoefficient(@intCast(index));
    }
    const random_words = std.mem.bytesAsSlice(
        u32,
        std.mem.sliceAsBytes(random_coefficients),
    );
    const random_coefficients_offset = try appendWords(
        &metadata,
        allocator,
        metadata_offset,
        random_words,
    );
    const zero_coordinates =
        [_]u32{0} ** (4 * fixture_rows);
    const coordinates_offset = try appendWords(
        &metadata,
        allocator,
        metadata_offset,
        &zero_coordinates,
    );

    const placements = try allocator.alloc(
        Placement,
        product.occurrence_count,
    );
    errdefer allocator.free(placements);
    var placement_index: usize = 0;
    var cumulative = oracle.PackedQm31.zero();
    var zero_inversions: usize = 0;
    for (bundle.components, 0..) |captured, component_index| {
        const base_span = try geometry.componentSpan(captured, 1);
        const interaction_span = try geometry.componentSpan(captured, 2);
        const trace_context = TraceContext{
            .component = &bundle.components[component_index],
            .base_span = base_span,
            .interaction_span = interaction_span,
        };
        for (captured.parts, 0..) |part, part_index| {
            const body = findBody(
                product,
                @intCast(component_index),
                @intCast(part_index),
            ) orelse return error.MissingAotPlacement;
            const global_rc_base = std.math.add(
                u32,
                captured.random_coefficient_offset,
                part.rc_base,
            ) catch return error.InvalidRandomCoefficientRange;
            try oracle.evaluatePart(
                allocator,
                part.program,
                .{
                    .trace_context = &trace_context,
                    .trace_value = traceValue,
                    .ext_params = components[component_index].ext_params,
                    .random_coefficients = random_coefficients,
                    .global_rc_base = global_rc_base,
                    .denominator_inverse = captured.denominator_inverses[0],
                },
                &cumulative,
                &zero_inversions,
            );
            placements[placement_index] = .{
                .cache_key = body.cache_key,
                .kernel_name = body.kernel_name,
                .component_index = @intCast(component_index),
                .instance = captured.instance,
                .part_index = @intCast(part_index),
                .global_rc_base = global_rc_base,
                .domain_log_size = part.program.header.domain_log_size,
                .expected = cumulative.lanes(),
            };
            placement_index += 1;
        }
    }
    if (placement_index != placements.len)
        return error.InvalidPlacementCount;
    const arena_words = std.math.add(
        u64,
        metadata_offset,
        metadata.items.len,
    ) catch return error.FixtureTooLarge;
    return .{
        .allocator = allocator,
        .max_rows = max_rows,
        .metadata_offset = metadata_offset,
        .arena_words = arena_words,
        .random_coefficients_offset = random_coefficients_offset,
        .coordinates_offset = coordinates_offset,
        .metadata_words = try metadata.toOwnedSlice(allocator),
        .random_coefficients = random_coefficients,
        .components = components,
        .placements = placements,
        .zero_inversions = zero_inversions,
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
        \\#ifndef STWO_ZIG_CUDA_SN2_EVAL_PARITY_FIXTURE_H
        \\#define STWO_ZIG_CUDA_SN2_EVAL_PARITY_FIXTURE_H
        \\
        \\#include <cstddef>
        \\#include <cstdint>
        \\
        \\namespace stwo_sn2_eval_parity {
        \\
    );
    try writer.print(
        "constexpr std::uint32_t kFixtureRows = {}u;\n",
        .{fixture_rows},
    );
    try writer.print(
        "constexpr std::uint64_t kMaxRows = {}ull;\n",
        .{fixture.max_rows},
    );
    try writer.print(
        "constexpr std::uint64_t kMetadataOffset = {}ull;\n",
        .{fixture.metadata_offset},
    );
    try writer.print(
        "constexpr std::uint64_t kArenaWords = {}ull;\n",
        .{fixture.arena_words},
    );
    try writer.print(
        "constexpr std::uint64_t kRandomCoefficientsOffset = {}ull;\n",
        .{fixture.random_coefficients_offset},
    );
    try writer.print(
        "constexpr std::uint64_t kCoordinatesOffset = {}ull;\n",
        .{fixture.coordinates_offset},
    );
    try writer.writeAll(
        \\constexpr std::uint32_t kConstraintSchema = 22u;
        \\constexpr std::uint32_t kKernelArgumentCount = 3u;
        \\
        \\struct Component {
        \\    const char *label;
        \\    std::uint32_t instance;
        \\    std::uint32_t trace_log_size;
        \\    std::uint32_t evaluation_log_size;
        \\    std::uint64_t trace_offsets;
        \\    std::uint64_t interaction_offsets;
        \\    std::uint64_t base_params;
        \\    std::uint64_t ext_params;
        \\    std::uint64_t denominator_inverses;
        \\};
        \\
        \\struct Placement {
        \\    std::uint64_t cache_key;
        \\    const char *kernel_name;
        \\    std::uint32_t component_index;
        \\    std::uint32_t instance;
        \\    std::uint32_t part_index;
        \\    std::uint32_t global_rc_base;
        \\    std::uint32_t domain_log_size;
        \\    std::uint32_t expected[kFixtureRows][4];
        \\};
        \\
    );
    try writeU32Array(
        writer,
        "kPaletteValues",
        &palette_values,
    );
    try writeU32Array(
        writer,
        "kMetadataWords",
        fixture.metadata_words,
    );
    try writer.writeAll("constexpr Component kComponents[] = {\n");
    for (fixture.components) |component| {
        try writer.print(
            "    {{\"{s}\", {}u, {}u, {}u, {}ull, {}ull, {}ull, {}ull, {}ull}},\n",
            .{
                component.label,
                component.instance,
                component.trace_log_size,
                component.evaluation_log_size,
                component.trace_offsets,
                component.interaction_offsets,
                component.base_params,
                component.ext_params_offset,
                component.denominator_inverses,
            },
        );
    }
    try writer.writeAll("};\n\nconstexpr Placement kPlacements[] = {\n");
    for (fixture.placements) |placement| {
        try writer.print(
            "    {{0x{x:0>16}ull, \"{s}\", {}u, {}u, {}u, {}u, {}u, {{",
            .{
                placement.cache_key,
                placement.kernel_name,
                placement.component_index,
                placement.instance,
                placement.part_index,
                placement.global_rc_base,
                placement.domain_log_size,
            },
        );
        for (placement.expected, 0..) |row, row_index| {
            try writer.writeByte('{');
            for (row, 0..) |coordinate, coordinate_index| {
                try writer.print("{}u", .{coordinate});
                if (coordinate_index + 1 != row.len)
                    try writer.writeAll(", ");
            }
            try writer.writeByte('}');
            if (row_index + 1 != placement.expected.len)
                try writer.writeAll(", ");
        }
        try writer.writeAll("}},\n");
    }
    try writer.writeAll(
        \\};
        \\
        \\constexpr std::size_t kComponentCount =
        \\    sizeof(kComponents) / sizeof(kComponents[0]);
        \\constexpr std::size_t kPlacementCount =
        \\    sizeof(kPlacements) / sizeof(kPlacements[0]);
        \\constexpr std::size_t kMetadataWordCount =
        \\    sizeof(kMetadataWords) / sizeof(kMetadataWords[0]);
        \\constexpr std::size_t kPaletteCount =
        \\    sizeof(kPaletteValues) / sizeof(kPaletteValues[0]);
        \\
        \\}  // namespace stwo_sn2_eval_parity
        \\
        \\#endif
        \\
    );
    return output.toOwnedSlice(allocator);
}

fn buildTraceOffsets(
    allocator: std.mem.Allocator,
    component: *const composition.Component,
    base_span: geometry.Span,
    interaction_span: geometry.Span,
    max_rows: u64,
) ![]u32 {
    const base_columns = base_span.end - base_span.start;
    const interaction_columns =
        interaction_span.end - interaction_span.start;
    const offsets = try allocator.alloc(
        u32,
        component.preprocessed_indices.len +
            base_columns +
            interaction_columns,
    );
    var cursor: usize = 0;
    for (component.preprocessed_indices) |global| {
        offsets[cursor] = try paletteOffset(0, global, max_rows);
        cursor += 1;
    }
    for (0..base_columns) |local| {
        offsets[cursor] = try paletteOffset(
            1,
            @intCast(base_span.start + local),
            max_rows,
        );
        cursor += 1;
    }
    for (0..interaction_columns) |local| {
        offsets[cursor] = try paletteOffset(
            2,
            @intCast(interaction_span.start + local),
            max_rows,
        );
        cursor += 1;
    }
    return offsets;
}

fn buildExtParams(
    allocator: std.mem.Allocator,
    component: *const composition.Component,
    component_index: u32,
) ![]oracle.Qm31Words {
    const values = try allocator.alloc(
        oracle.Qm31Words,
        component.ext_sources.len,
    );
    const lookup_z = qm31.QM31.fromU32Unchecked(29, 31, 37, 41);
    const lookup_alpha =
        qm31.QM31.fromU32Unchecked(43, 47, 53, 59);
    const claimed_sum = qm31.QM31.fromU32Unchecked(
        101 + component_index * 17,
        103 + component_index * 19,
        107 + component_index * 23,
        109 + component_index * 29,
    );
    const row_scale = try m31.M31.fromCanonical(
        @as(u32, 1) << @intCast(component.trace_log_size),
    ).inv();
    for (component.ext_sources, values) |source, *words| {
        const value = switch (source) {
            .constant => |constant| qm31.QM31.fromU32Unchecked(
                constant[0],
                constant[1],
                constant[2],
                constant[3],
            ),
            .lookup_z => lookup_z,
            .lookup_alpha_power => |power| lookup_alpha.pow(power),
            .claimed_sum_scaled => claimed_sum.mulM31(row_scale),
            .lookup_alpha_power_scaled => |scaled| lookup_alpha.pow(scaled.power).mulM31(
                m31.M31.fromCanonical(scaled.scale),
            ),
        };
        const coordinates = value.toM31Array();
        inline for (0..4) |coordinate| {
            words[coordinate] = coordinates[coordinate].toU32();
        }
    }
    return values;
}

fn traceValue(
    raw_context: *const anyopaque,
    interaction: u8,
    column: u32,
    _: i32,
) oracle.PackedM31 {
    const context: *const TraceContext = @ptrCast(@alignCast(raw_context));
    const global: u32 = switch (interaction) {
        0 => context.component.preprocessed_indices[column],
        1 => @intCast(context.base_span.start + column),
        2 => @intCast(context.interaction_span.start + column),
        else => unreachable,
    };
    return @splat(palette_values[paletteIndex(interaction, global)]);
}

fn findBody(
    product: eval_aot.Product,
    component_index: u32,
    part_index: u32,
) ?*const eval_aot.Body {
    for (product.bodies) |*body| {
        for (body.occurrences) |occurrence| {
            if (occurrence.component_index == component_index and
                occurrence.part_index == part_index)
            {
                return body;
            }
        }
    }
    return null;
}

fn appendWords(
    metadata: *std.ArrayList(u32),
    allocator: std.mem.Allocator,
    metadata_offset: u64,
    words: []const u32,
) !u64 {
    const offset = std.math.add(
        u64,
        metadata_offset,
        metadata.items.len,
    ) catch return error.FixtureTooLarge;
    try metadata.appendSlice(allocator, words);
    return offset;
}

fn paletteOffset(
    tree: u8,
    global: u32,
    max_rows: u64,
) !u32 {
    return std.math.cast(
        u32,
        @as(u64, paletteIndex(tree, global)) * max_rows,
    ) orelse error.FixtureTooLarge;
}

fn paletteIndex(tree: u8, global: u32) usize {
    return @intCast(
        (@as(u64, tree) * 17 + @as(u64, global) * 13 + 5) %
            palette_values.len,
    );
}

fn randomCoefficient(index: u32) oracle.Qm31Words {
    return .{
        1009 + index * 17,
        1013 + index * 19,
        1019 + index * 23,
        1021 + index * 29,
    };
}

fn writeU32Array(
    writer: anytype,
    name: []const u8,
    values: []const u32,
) !void {
    try writer.print("constexpr std::uint32_t {s}[] = {{\n", .{name});
    for (values, 0..) |value, index| {
        if (index % 8 == 0) try writer.writeAll("    ");
        try writer.print("{}u", .{value});
        if (index + 1 != values.len) {
            try writer.writeByte(',');
            if (index % 8 != 7) try writer.writeByte(' ');
        }
        if (index % 8 == 7 or index + 1 == values.len)
            try writer.writeByte('\n');
    }
    try writer.writeAll("};\n\n");
}
