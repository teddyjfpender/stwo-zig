//! Authenticated heterogeneous-domain topology for Cairo constraint AOT.
//!
//! Each component evaluates all of its sources in one contiguous LDE tile at
//! its own evaluation height. Components with the same height accumulate into
//! one four-coordinate region; distinct heights remain separate until the
//! composition finalize transform.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const composition = @import(
    "../../../../frontends/cairo/witness/composition_bundle.zig",
);
const eval_abi = @import(
    "../../../../backends/cuda/abi/stages/cairo_eval.zig",
);
const eval_codegen = @import("../../eval_codegen.zig");

pub const expected_component_count = 58;
pub const expected_placement_count = 279;
pub const expected_constraint_count = 1325;

pub const SourceRole = enum(u8) {
    preprocessed,
    main,
    interaction,
};

pub const Source = struct {
    role: SourceRole,
    column: u32,
    log_rows: u32,
    tile_offset: u64,
};

pub const Component = struct {
    component_index: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    first_source: u32,
    source_count: u32,
    preprocessed_count: u32,
    main_count: u32,
    interaction_count: u32,
    first_trace_offset: u32,
    first_interaction_offset: u32,
    first_denominator: u32,
    denominator_count: u32,
    first_extended_parameter: u32,
    extended_parameter_count: u32,
    accumulator_offset: u64,
    first_placement: u32,
    placement_count: u32,
};

pub const Placement = struct {
    component_index: u32,
    part_index: u32,
    global_rc_base: u32,
    rc_count: u32,
    domain_log_size: u32,
    semantic_hash: u64,
    program_identity: proof_ir.Digest,
};

pub const Accumulator = struct {
    evaluation_log_size: u32,
    offset_words: u64,
    words: u64,
};

pub const Summary = struct {
    component_count: u32,
    placement_count: u32,
    constraint_count: u64,
    source_count: u32,
    trace_offset_words: u64,
    interaction_offset_words: u64,
    lde_descriptor_words: u64,
    denominator_words: u64,
    extended_parameter_descriptor_words: u64,
    extended_parameter_words: u64,
    argument_words: u64,
    lde_tile_words: u64,
    accumulator_words: u64,
};

pub const Topology = struct {
    allocator: std.mem.Allocator,
    components: []Component,
    sources: []Source,
    placements: []Placement,
    accumulators: []Accumulator,
    extended_parameter_descriptors: []eval_abi.ExtSourceDescriptor,
    summary: Summary,
    identity: proof_ir.Digest,

    pub fn derive(
        allocator: std.mem.Allocator,
        bundle: composition.Bundle,
        preprocessed_logs: []const u32,
    ) !Topology {
        if (bundle.plan_hash == 0 or
            bundle.components.len == 0 or
            preprocessed_logs.len == 0)
        {
            return error.InvalidCairoEvalTopology;
        }
        const counts = try count(bundle);
        const components = try allocator.alloc(
            Component,
            bundle.components.len,
        );
        errdefer allocator.free(components);
        const sources = try allocator.alloc(Source, counts.sources);
        errdefer allocator.free(sources);
        const placements = try allocator.alloc(
            Placement,
            counts.placements,
        );
        errdefer allocator.free(placements);
        const extended_parameter_descriptors = try allocator.alloc(
            eval_abi.ExtSourceDescriptor,
            counts.extended_parameters,
        );
        errdefer allocator.free(extended_parameter_descriptors);
        const accumulators = try buildAccumulators(allocator, bundle);
        errdefer allocator.free(accumulators);

        var source_cursor: usize = 0;
        var placement_cursor: usize = 0;
        var trace_offset_cursor: u64 = 0;
        var interaction_offset_cursor: u64 = 0;
        var denominator_cursor: u64 = 0;
        var extended_cursor: u64 = 0;
        var extended_descriptor_cursor: usize = 0;
        var maximum_tile_words: u64 = 0;
        for (bundle.components, components, 0..) |
            captured,
            *component,
            component_index,
        | {
            const main = try uniqueSpan(captured, 1);
            const interaction = try uniqueSpan(captured, 2);
            const main_count = try spanLength(main);
            const interaction_count = try spanLength(interaction);
            const source_count = try add(
                captured.preprocessed_indices.len,
                try add(main_count, interaction_count),
            );
            const row_count = try pow2(captured.evaluation_log_size);
            const tile_words = try mul(source_count, row_count);
            maximum_tile_words = @max(maximum_tile_words, tile_words);
            const first_source = source_cursor;
            var local_source: u64 = 0;
            for (captured.preprocessed_indices) |column| {
                if (column >= preprocessed_logs.len)
                    return error.InvalidCairoEvalTopology;
                sources[source_cursor] = .{
                    .role = .preprocessed,
                    .column = column,
                    .log_rows = preprocessed_logs[column],
                    .tile_offset = try mul(local_source, row_count),
                };
                source_cursor += 1;
                local_source += 1;
            }
            for (main.start..main.end) |column| {
                sources[source_cursor] = .{
                    .role = .main,
                    .column = @intCast(column),
                    .log_rows = captured.trace_log_size,
                    .tile_offset = try mul(local_source, row_count),
                };
                source_cursor += 1;
                local_source += 1;
            }
            for (interaction.start..interaction.end) |column| {
                sources[source_cursor] = .{
                    .role = .interaction,
                    .column = @intCast(column),
                    .log_rows = captured.trace_log_size,
                    .tile_offset = try mul(local_source, row_count),
                };
                source_cursor += 1;
                local_source += 1;
            }
            if (local_source != source_count)
                return error.InvalidCairoEvalTopology;

            const first_placement = placement_cursor;
            for (captured.parts, 0..) |part, part_index| {
                if (part.program.header.domain_log_size !=
                    captured.trace_log_size)
                {
                    return error.InvalidCairoEvalTopology;
                }
                placements[placement_cursor] = .{
                    .component_index = @intCast(component_index),
                    .part_index = @intCast(part_index),
                    .global_rc_base = try addU32(
                        captured.random_coefficient_offset,
                        part.rc_base,
                    ),
                    .rc_count = part.program.header.n_constraints,
                    .domain_log_size = part.program.header.domain_log_size,
                    .semantic_hash = part.semantic_hash,
                    .program_identity = eval_codegen.programIdentity(part.program),
                };
                placement_cursor += 1;
            }
            for (captured.ext_sources) |source| {
                extended_parameter_descriptors[
                    extended_descriptor_cursor
                ] = try extSourceDescriptor(
                    source,
                    @intCast(component_index),
                    captured.trace_log_size,
                );
                extended_descriptor_cursor += 1;
            }
            component.* = .{
                .component_index = @intCast(component_index),
                .trace_log_size = captured.trace_log_size,
                .evaluation_log_size = captured.evaluation_log_size,
                .first_source = @intCast(first_source),
                .source_count = @intCast(source_count),
                .preprocessed_count = @intCast(captured.preprocessed_indices.len),
                .main_count = @intCast(main_count),
                .interaction_count = @intCast(interaction_count),
                .first_trace_offset = @intCast(trace_offset_cursor),
                .first_interaction_offset = @intCast(interaction_offset_cursor),
                .first_denominator = @intCast(denominator_cursor),
                .denominator_count = @intCast(captured.denominator_inverses.len),
                .first_extended_parameter = @intCast(extended_cursor),
                .extended_parameter_count = @intCast(captured.ext_sources.len),
                .accumulator_offset = try accumulatorOffset(
                    accumulators,
                    captured.evaluation_log_size,
                ),
                .first_placement = @intCast(first_placement),
                .placement_count = @intCast(captured.parts.len),
            };
            trace_offset_cursor = try add(
                trace_offset_cursor,
                source_count,
            );
            interaction_offset_cursor = try add(
                interaction_offset_cursor,
                3,
            );
            denominator_cursor = try add(
                denominator_cursor,
                captured.denominator_inverses.len,
            );
            extended_cursor = try add(
                extended_cursor,
                try mul(captured.ext_sources.len, 4),
            );
        }
        if (source_cursor != sources.len or
            placement_cursor != placements.len or
            extended_descriptor_cursor !=
                extended_parameter_descriptors.len)
        {
            return error.InvalidCairoEvalTopology;
        }
        try validatePlacementOrder(placements, bundle.total_constraints);
        const accumulator_words = if (accumulators.len == 0)
            0
        else
            try add(
                accumulators[accumulators.len - 1].offset_words,
                accumulators[accumulators.len - 1].words,
            );
        const summary = Summary{
            .component_count = @intCast(components.len),
            .placement_count = @intCast(placements.len),
            .constraint_count = bundle.total_constraints,
            .source_count = @intCast(sources.len),
            .trace_offset_words = trace_offset_cursor,
            .interaction_offset_words = interaction_offset_cursor,
            .lde_descriptor_words = try mul(sources.len, 6),
            .denominator_words = denominator_cursor,
            .extended_parameter_descriptor_words = try mul(extended_parameter_descriptors.len, 8),
            .extended_parameter_words = extended_cursor,
            .argument_words = try mul(placements.len, 24),
            .lde_tile_words = maximum_tile_words,
            .accumulator_words = accumulator_words,
        };
        const identity = topologyIdentity(
            bundle,
            preprocessed_logs,
            components,
            sources,
            placements,
            accumulators,
            extended_parameter_descriptors,
            summary,
        );
        return .{
            .allocator = allocator,
            .components = components,
            .sources = sources,
            .placements = placements,
            .accumulators = accumulators,
            .extended_parameter_descriptors = extended_parameter_descriptors,
            .summary = summary,
            .identity = identity,
        };
    }

    pub fn deinit(self: *Topology) void {
        self.allocator.free(self.accumulators);
        self.allocator.free(self.extended_parameter_descriptors);
        self.allocator.free(self.placements);
        self.allocator.free(self.sources);
        self.allocator.free(self.components);
        self.* = undefined;
    }
};

const Counts = struct {
    sources: usize,
    placements: usize,
    extended_parameters: usize,
};

fn count(bundle: composition.Bundle) !Counts {
    var sources: u64 = 0;
    var placements: u64 = 0;
    var extended_parameters: u64 = 0;
    for (bundle.components) |component| {
        const main = try uniqueSpan(component, 1);
        const interaction = try uniqueSpan(component, 2);
        sources = try add(
            sources,
            try add(
                component.preprocessed_indices.len,
                try add(
                    try spanLength(main),
                    try spanLength(interaction),
                ),
            ),
        );
        placements = try add(placements, component.parts.len);
        extended_parameters = try add(
            extended_parameters,
            component.ext_sources.len,
        );
    }
    return .{
        .sources = std.math.cast(usize, sources) orelse
            return error.CairoEvalTopologyOverflow,
        .placements = std.math.cast(usize, placements) orelse
            return error.CairoEvalTopologyOverflow,
        .extended_parameters = std.math.cast(usize, extended_parameters) orelse
            return error.CairoEvalTopologyOverflow,
    };
}

fn buildAccumulators(
    allocator: std.mem.Allocator,
    bundle: composition.Bundle,
) ![]Accumulator {
    var present = [_]bool{false} ** 32;
    for (bundle.components) |component| {
        if (component.evaluation_log_size >= present.len)
            return error.InvalidCairoEvalTopology;
        present[component.evaluation_log_size] = true;
    }
    var count_present: usize = 0;
    for (present) |value| count_present += @intFromBool(value);
    const output = try allocator.alloc(Accumulator, count_present);
    var cursor: usize = 0;
    var offset: u64 = 0;
    for (present, 0..) |value, log_size| {
        if (!value) continue;
        const words = try mul(try pow2(@intCast(log_size)), 4);
        output[cursor] = .{
            .evaluation_log_size = @intCast(log_size),
            .offset_words = offset,
            .words = words,
        };
        offset = try add(offset, words);
        cursor += 1;
    }
    return output;
}

fn uniqueSpan(
    component: composition.Component,
    tree: u32,
) !composition.TraceSpan {
    var result: ?composition.TraceSpan = null;
    for (component.trace_spans) |span| {
        if (span.tree != tree) continue;
        if (result != null or span.end <= span.start)
            return error.InvalidCairoEvalTopology;
        result = span;
    }
    return result orelse error.InvalidCairoEvalTopology;
}

fn spanLength(span: composition.TraceSpan) !u64 {
    return std.math.sub(u32, span.end, span.start) catch
        error.InvalidCairoEvalTopology;
}

fn accumulatorOffset(
    accumulators: []const Accumulator,
    log_size: u32,
) !u64 {
    for (accumulators) |accumulator| {
        if (accumulator.evaluation_log_size == log_size)
            return accumulator.offset_words;
    }
    return error.InvalidCairoEvalTopology;
}

fn validatePlacementOrder(
    placements: []const Placement,
    constraint_count: u64,
) !void {
    var next: u64 = 0;
    for (placements) |placement| {
        if (placement.global_rc_base != next or
            placement.rc_count == 0 or
            placement.semantic_hash == 0 or
            std.mem.allEqual(u8, &placement.program_identity, 0))
        {
            return error.InvalidCairoEvalTopology;
        }
        next = try add(next, placement.rc_count);
    }
    if (next != constraint_count)
        return error.InvalidCairoEvalTopology;
}

fn topologyIdentity(
    bundle: composition.Bundle,
    preprocessed_logs: []const u32,
    components: []const Component,
    sources: []const Source,
    placements: []const Placement,
    accumulators: []const Accumulator,
    extended_parameter_descriptors: []const eval_abi.ExtSourceDescriptor,
    summary: Summary,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/eval-topology/v1\x00");
    hashInt(&hash, u64, bundle.plan_hash);
    for (preprocessed_logs) |value| hashInt(&hash, u32, value);
    hash.update(std.mem.sliceAsBytes(components));
    hash.update(std.mem.sliceAsBytes(sources));
    for (placements) |placement| {
        hashInt(&hash, u32, placement.component_index);
        hashInt(&hash, u32, placement.part_index);
        hashInt(&hash, u32, placement.global_rc_base);
        hashInt(&hash, u32, placement.rc_count);
        hashInt(&hash, u32, placement.domain_log_size);
        hashInt(&hash, u64, placement.semantic_hash);
        hash.update(&placement.program_identity);
    }
    hash.update(std.mem.sliceAsBytes(accumulators));
    hash.update(std.mem.sliceAsBytes(extended_parameter_descriptors));
    hash.update(std.mem.asBytes(&summary));
    return hash.finalResult();
}

fn extSourceDescriptor(
    source: composition.ExtSource,
    component_index: u32,
    trace_log_size: u32,
) !eval_abi.ExtSourceDescriptor {
    return switch (source) {
        .constant => |value| .{
            .kind = .constant,
            .source_index = 0,
            .scale = 1,
            .constant = value,
        },
        .lookup_z => .{
            .kind = .lookup_z,
            .source_index = 0,
            .scale = 1,
        },
        .lookup_alpha_power => |power| .{
            .kind = .lookup_alpha_power,
            .source_index = power,
            .scale = 1,
        },
        .claimed_sum_scaled => .{
            .kind = .claimed_sum_scaled,
            .source_index = component_index,
            .scale = try inversePowerOfTwo(trace_log_size),
        },
        .lookup_alpha_power_scaled => |value| .{
            .kind = .lookup_alpha_power_scaled,
            .source_index = value.power,
            .scale = value.scale,
        },
    };
}

fn inversePowerOfTwo(log_size: u32) !u32 {
    if (log_size == 0 or log_size > 30)
        return error.InvalidCairoEvalTopology;
    return @as(u32, 1) << @intCast(31 - log_size);
}

fn pow2(log_size: u32) !u64 {
    if (log_size >= 63) return error.CairoEvalTopologyOverflow;
    return @as(u64, 1) << @intCast(log_size);
}

fn add(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse
        return error.CairoEvalTopologyOverflow;
    const rhs = std.math.cast(u64, right) orelse
        return error.CairoEvalTopologyOverflow;
    return std.math.add(u64, lhs, rhs) catch
        error.CairoEvalTopologyOverflow;
}

fn mul(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse
        return error.CairoEvalTopologyOverflow;
    const rhs = std.math.cast(u64, right) orelse
        return error.CairoEvalTopologyOverflow;
    return std.math.mul(u64, lhs, rhs) catch
        error.CairoEvalTopologyOverflow;
}

fn addU32(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.CairoEvalTopologyOverflow;
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime F: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(F)]u8 = undefined;
    std.mem.writeInt(F, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
