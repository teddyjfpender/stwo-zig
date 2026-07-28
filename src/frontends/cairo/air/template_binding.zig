//! Instantiates authenticated Cairo AIR templates for one live claim schedule.

const std = @import("std");
const core = @import("stwo_core");
const adapter = @import("../adapter/mod.zig");
const claim_generator = @import("../claim_generator.zig");
const preprocessed = @import("../preprocessed/trace.zig");
const composition = @import("../witness/composition_bundle.zig");
const eval_program = @import("../witness/eval_program.zig");
const template_library = @import("template_library.zig");

const M31 = core.fields.m31.M31;

pub fn instantiate(
    allocator: std.mem.Allocator,
    library: template_library.Library,
    geometry: *const claim_generator.OwnedClaimGeometry,
    target_variant: preprocessed.Variant,
    segments: adapter.BuiltinSegments,
) !composition.Bundle {
    var target_spec = try preprocessed.Spec.init(allocator, target_variant);
    defer target_spec.deinit();
    var canonical_spec = try preprocessed.Spec.init(allocator, .canonical);
    defer canonical_spec.deinit();
    var small_spec = try preprocessed.Spec.init(allocator, .canonical_small);
    defer small_spec.deinit();

    const components = try allocator.alloc(
        composition.Component,
        geometry.components.len,
    );
    errdefer allocator.free(components);
    var initialized: usize = 0;
    errdefer for (components[0..initialized]) |*component|
        deinitComponent(allocator, component);
    var tree_cursors = [3]u32{ 0, 0, 0 };
    var constraint_cursor: u32 = 0;
    var maximum_evaluation_log: u32 = 0;
    for (geometry.components, components) |live, *component| {
        const trace_log = switch (live.log_size) {
            .known => |value| value,
            .deferred => return error.IncompleteClaimGeometry,
        };
        const source = try library.sourceFor(
            live.name,
            trace_log,
            target_variant,
        );
        const template = source.find(live.name) orelse
            return error.MissingAirTemplate;
        const source_spec = switch (source.variant) {
            .canonical => canonical_spec,
            .canonical_small => small_spec,
            .canonical_without_pedersen => return error.InvalidTemplateVariant,
        };
        component.* = try instantiateComponent(
            allocator,
            template,
            source.*,
            live,
            source_spec,
            target_spec,
            segments,
            &tree_cursors,
            constraint_cursor,
        );
        initialized += 1;
        constraint_cursor = std.math.add(
            u32,
            constraint_cursor,
            component.n_constraints,
        ) catch return error.InvalidConstraintCount;
        maximum_evaluation_log = @max(
            maximum_evaluation_log,
            component.evaluation_log_size,
        );
    }
    if (constraint_cursor == 0 or maximum_evaluation_log == 0)
        return error.EmptyAirSchedule;
    return .{
        .allocator = allocator,
        .format_version = composition.version,
        .max_kernel_instructions = 1_000_000,
        .total_constraints = constraint_cursor,
        .max_evaluation_log_size = maximum_evaluation_log,
        .plan_hash = scheduleHash(components),
        .components = components,
    };
}

fn instantiateComponent(
    allocator: std.mem.Allocator,
    template: *const composition.Component,
    source: template_library.Source,
    live: claim_generator.ComponentGeometry,
    source_spec: preprocessed.Spec,
    target_spec: preprocessed.Spec,
    segments: adapter.BuiltinSegments,
    tree_cursors: *[3]u32,
    random_coefficient_offset: u32,
) !composition.Component {
    const trace_log = switch (live.log_size) {
        .known => |value| value,
        .deferred => return error.IncompleteClaimGeometry,
    };
    const evaluation_delta = std.math.sub(
        u32,
        template.evaluation_log_size,
        template.trace_log_size,
    ) catch return error.InvalidTemplateGeometry;
    const evaluation_log = std.math.add(
        u32,
        trace_log,
        evaluation_delta,
    ) catch return error.InvalidTemplateGeometry;
    if (evaluation_log > 31) return error.InvalidTemplateGeometry;

    const label = if (std.mem.eql(u8, live.name, "memory_id_to_big"))
        try std.fmt.allocPrint(allocator, "memory_id_to_big[{}]", .{live.instance})
    else
        try allocator.dupe(u8, live.name);
    errdefer allocator.free(label);
    const spans = try allocator.alloc(composition.TraceSpan, template.trace_spans.len);
    errdefer allocator.free(spans);
    for (template.trace_spans, spans) |template_span, *span| {
        const width = std.math.sub(
            u32,
            template_span.end,
            template_span.start,
        ) catch return error.InvalidTemplateGeometry;
        if (template_span.tree == 0) {
            if (width != 0) return error.InvalidTemplateGeometry;
            span.* = .{ .tree = 0, .start = 0, .end = 0 };
        } else if (template_span.tree < tree_cursors.len) {
            const start = tree_cursors[template_span.tree];
            const end = std.math.add(u32, start, width) catch
                return error.InvalidTemplateGeometry;
            span.* = .{ .tree = template_span.tree, .start = start, .end = end };
            tree_cursors[template_span.tree] = end;
        } else {
            return error.InvalidTemplateGeometry;
        }
    }
    const projected = try source_spec.projectIndices(
        allocator,
        target_spec,
        template.preprocessed_indices,
    );
    errdefer allocator.free(projected);
    try rebindSequenceColumn(
        projected,
        template.preprocessed_indices,
        source_spec,
        target_spec,
        template.trace_log_size,
        trace_log,
    );
    const denominators = try denominatorInverses(
        allocator,
        trace_log,
        evaluation_log,
    );
    errdefer allocator.free(denominators);
    const extension_sources = try allocator.dupe(
        composition.ExtSource,
        template.ext_sources,
    );
    errdefer allocator.free(extension_sources);
    const parts = try allocator.alloc(composition.Part, template.parts.len);
    errdefer allocator.free(parts);
    var parts_initialized: usize = 0;
    errdefer for (parts[0..parts_initialized]) |*part| part.program.deinit();
    for (template.parts, parts) |template_part, *part| {
        var program = try template_part.program.clone(allocator);
        errdefer program.deinit();
        try program.setDomainLogSize(trace_log);
        try rebindDomainConstants(
            &program,
            live.name,
            template.trace_log_size,
            trace_log,
        );
        try rebindSegmentConstant(
            &program,
            live.name,
            source.segment_starts,
            segments,
        );
        part.* = .{
            .rc_base = template_part.rc_base,
            .semantic_hash = program.header.semantic_hash,
            .program = program,
        };
        parts_initialized += 1;
    }
    return .{
        .label = label,
        .instance = live.instance,
        .trace_log_size = trace_log,
        .evaluation_log_size = evaluation_log,
        .n_constraints = template.n_constraints,
        .random_coefficient_offset = random_coefficient_offset,
        .trace_spans = spans,
        .preprocessed_indices = projected,
        .denominator_inverses = denominators,
        .ext_sources = extension_sources,
        .parts = parts,
    };
}

fn denominatorInverses(
    allocator: std.mem.Allocator,
    trace_log: u32,
    evaluation_log: u32,
) ![]u32 {
    const delta = std.math.sub(
        u32,
        evaluation_log,
        trace_log,
    ) catch return error.InvalidTemplateGeometry;
    if (delta >= @bitSizeOf(usize)) return error.InvalidTemplateGeometry;

    const values = try allocator.alloc(u32, @as(usize, 1) << @intCast(delta));
    errdefer allocator.free(values);
    const trace_coset = core.poly.circle.canonic.CanonicCoset.new(trace_log).coset();
    const evaluation_domain =
        core.poly.circle.canonic.CanonicCoset.new(evaluation_log).circleDomain();
    for (values, 0..) |*value, index| {
        value.* = (try core.constraints.cosetVanishing(
            M31,
            trace_coset,
            evaluation_domain.at(index),
        ).inv()).toU32();
    }
    core.utils.bitReverse(u32, values);
    return values;
}

fn rebindDomainConstants(
    program: *eval_program.Program,
    label: []const u8,
    source_log: u32,
    target_log: u32,
) !void {
    if (!std.mem.eql(u8, label, "memory_address_to_id") or
        source_log == target_log)
        return;
    const source_stride = @as(u64, 1) << @intCast(source_log);
    const target_stride = @as(u64, 1) << @intCast(target_log);
    for (1..claim_generator.memory_address_to_id_split) |chunk| {
        const source = std.math.cast(u32, chunk * source_stride) orelse
            return error.InvalidTemplateGeometry;
        const target = std.math.cast(u32, chunk * target_stride) orelse
            return error.InvalidTemplateGeometry;
        if (try program.replaceBaseConstant(source, target) == 0)
            return error.MissingDomainConstant;
    }
}

fn rebindSequenceColumn(
    projected: []u32,
    source_indices: []const u32,
    source_spec: preprocessed.Spec,
    target_spec: preprocessed.Spec,
    source_log: u32,
    target_log: u32,
) !void {
    if (source_log == target_log) return;
    var source_buffer: [16]u8 = undefined;
    const source_name = try std.fmt.bufPrint(&source_buffer, "seq_{}", .{source_log});
    const source_sequence = source_spec.indexOf(source_name) orelse
        return error.MissingSourceSequenceColumn;
    if (std.mem.indexOfScalar(u32, source_indices, source_sequence) == null) return;
    var target_buffer: [16]u8 = undefined;
    const target_name = try std.fmt.bufPrint(&target_buffer, "seq_{}", .{target_log});
    const target_sequence = target_spec.indexOf(target_name) orelse
        return error.MissingTargetSequenceColumn;
    for (source_indices, projected) |source_index, *target_index| {
        if (source_index == source_sequence) target_index.* = target_sequence;
    }
}

fn rebindSegmentConstant(
    program: *eval_program.Program,
    label: []const u8,
    source_starts: template_library.SegmentStarts,
    target_segments: adapter.BuiltinSegments,
) !void {
    const source = source_starts.get(label) orelse return;
    const target = segmentStart(target_segments, label) orelse
        return error.MissingBuiltinSegment;
    if (source == target) return;
    if (try program.replaceBaseConstant(source, target) == 0)
        return error.MissingSegmentConstant;
}

fn segmentStart(segments: adapter.BuiltinSegments, label: []const u8) ?u32 {
    if (std.mem.eql(u8, label, "pedersen_builtin_narrow_windows")) {
        const segment = segments.pedersen_builtin orelse return null;
        return std.math.cast(u32, segment.begin_addr);
    }
    inline for (std.meta.fields(adapter.BuiltinSegments)) |field| {
        if (std.mem.eql(u8, label, field.name)) {
            const segment = @field(segments, field.name) orelse return null;
            return std.math.cast(u32, segment.begin_addr);
        }
    }
    return null;
}

fn deinitComponent(
    allocator: std.mem.Allocator,
    component: *composition.Component,
) void {
    allocator.free(component.label);
    allocator.free(component.trace_spans);
    allocator.free(component.preprocessed_indices);
    allocator.free(component.denominator_inverses);
    allocator.free(component.ext_sources);
    for (component.parts) |*part| part.program.deinit();
    allocator.free(component.parts);
}

fn scheduleHash(components: []const composition.Component) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    for (components) |component| {
        hashBytes(&hash, component.label);
        hashInt(&hash, component.instance);
        hashInt(&hash, component.trace_log_size);
        hashInt(&hash, component.evaluation_log_size);
        hashInt(&hash, component.n_constraints);
        hashInt(&hash, component.random_coefficient_offset);
        for (component.trace_spans) |span| {
            hashInt(&hash, span.tree);
            hashInt(&hash, span.start);
            hashInt(&hash, span.end);
        }
        for (component.preprocessed_indices) |index| hashInt(&hash, index);
        for (component.parts) |part| hashInt(&hash, part.semantic_hash);
    }
    return if (hash == 0) 1 else hash;
}

fn hashInt(hash: *u64, value: anytype) void {
    const T = @TypeOf(value);
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hashBytes(hash, &encoded);
}

fn hashBytes(hash: *u64, bytes: []const u8) void {
    for (bytes) |byte| {
        hash.* ^= byte;
        hash.* *%= 0x100000001b3;
    }
}

test "official Cairo AIR templates instantiate live logs and segment starts" {
    const allocator = std.testing.allocator;
    var library = try template_library.Library.readFile(
        allocator,
        "vectors/cairo/official/air_template_library_v1.json",
    );
    defer library.deinit();
    const live_components = try allocator.dupe(
        claim_generator.ComponentGeometry,
        &.{
            .{ .name = "add_mod_builtin", .log_size = .{ .known = 7 } },
            .{ .name = "memory_address_to_id", .log_size = .{ .known = 9 } },
            .{ .name = "memory_id_to_big", .log_size = .{ .known = 6 } },
        },
    );
    var geometry = claim_generator.OwnedClaimGeometry{
        .allocator = allocator,
        .components = live_components,
    };
    defer geometry.deinit();
    var segments = adapter.BuiltinSegments{};
    segments.add_mod_builtin = .{ .begin_addr = 9001, .stop_ptr = 9002 };
    var bundle = try instantiate(
        allocator,
        library,
        &geometry,
        .canonical,
        segments,
    );
    defer bundle.deinit();
    try std.testing.expectEqual(@as(usize, 3), bundle.components.len);
    try std.testing.expectEqual(@as(u32, 7), bundle.components[0].trace_log_size);
    try std.testing.expectEqual(@as(u32, 9), bundle.components[1].trace_log_size);
    var canonical = try preprocessed.Spec.init(allocator, .canonical);
    defer canonical.deinit();
    const live_sequence = canonical.indexOf("seq_9").?;
    try std.testing.expect(std.mem.indexOfScalar(
        u32,
        bundle.components[1].preprocessed_indices,
        live_sequence,
    ) != null);
    try std.testing.expectEqualStrings(
        "memory_id_to_big[0]",
        bundle.components[2].label,
    );
    try std.testing.expectEqual(
        bundle.components[0].n_constraints,
        bundle.components[1].random_coefficient_offset,
    );
}

test "official Cairo AIR templates derive vanishing inverses from live geometry" {
    const allocator = std.testing.allocator;
    const source = try denominatorInverses(allocator, 8, 9);
    defer allocator.free(source);
    const rebound = try denominatorInverses(allocator, 9, 10);
    defer allocator.free(rebound);

    try std.testing.expectEqual(@as(usize, 2), source.len);
    try std.testing.expectEqual(@as(usize, 2), rebound.len);
    try std.testing.expect(!std.mem.eql(u32, source, rebound));
    for (source, 0..) |inverse, index| {
        const trace_coset =
            core.poly.circle.canonic.CanonicCoset.new(8).coset();
        const evaluation_domain =
            core.poly.circle.canonic.CanonicCoset.new(9).circleDomain();
        const point_index = core.utils.bitReverseIndex(index, 1);
        const vanishing = core.constraints.cosetVanishing(
            M31,
            trace_coset,
            evaluation_domain.at(point_index),
        );
        try std.testing.expect(vanishing.mul(M31.fromCanonical(inverse)).eql(M31.one()));
    }
}

test "sequence rebinding permits larger components without sequence inputs" {
    const allocator = std.testing.allocator;
    var canonical = try preprocessed.Spec.init(allocator, .canonical);
    defer canonical.deinit();
    var small = try preprocessed.Spec.init(allocator, .canonical_small);
    defer small.deinit();

    const source_indices = [_]u32{canonical.indexOf("blake_sigma_0").?};
    var projected = [_]u32{small.indexOf("blake_sigma_0").?};
    try rebindSequenceColumn(
        &projected,
        &source_indices,
        canonical,
        small,
        20,
        21,
    );
    try std.testing.expectEqual(
        small.indexOf("blake_sigma_0").?,
        projected[0],
    );
}
