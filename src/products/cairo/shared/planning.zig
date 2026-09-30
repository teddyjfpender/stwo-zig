//! Read-only Cairo coverage and geometry inspection before a large proof.

const std = @import("std");
const cairo = @import("stwo_cairo").frontends.cairo;
const profile = @import("profile.zig");
const cli = @import("cli.zig");

const Component = struct {
    name: []const u8,
    instance: u32,
    log_size: ?u32,
    sizing_source: []const u8,
    base_columns: u64,
    interaction_columns: u64,
    base_bytes: ?u64,
    interaction_bytes: ?u64,
};

pub fn inspect(allocator: std.mem.Allocator, request: cli.Inspect) !void {
    const started = try std.time.Instant.now();
    const default_manifest = if (request.params == null) try profile.defaultManifestPath(allocator) else null;
    defer if (default_manifest) |path| allocator.free(path);
    var paths = try profile.load(allocator, request.params orelse default_manifest.?);
    defer paths.deinit();
    var input = try cairo.adapter.input.readFile(allocator, request.prover_input);
    defer input.deinit(allocator);
    var library = try cairo.air.template_library.Library.readFile(allocator, paths.air_template_library);
    defer library.deinit();
    try profile.admitInput(&paths, &input, library, request.params == null);
    var topology = try cairo.witness.feed_topology.readOfficial(allocator, paths.witness_topology);
    defer topology.deinit();
    const variant: cairo.claim_generator.PreprocessedVariant = paths.variant;
    var geometry = try cairo.claim_generator.deriveFromProverInput(allocator, &input, .{ .preprocessed_variant = variant });
    defer geometry.deinit();
    const was_deferred = try allocator.alloc(bool, geometry.components.len);
    defer allocator.free(was_deferred);
    for (geometry.components, was_deferred) |component, *deferred| deferred.* = component.log_size == .deferred;
    const resources = cairo.claim_generator.ExecutionResources.fromProverInput(&input);
    var prediction_error: ?[]const u8 = null;
    _ = cairo.proving.feed_geometry_oracle.resolveInPlace(allocator, &geometry, resources, topology) catch |err| blk: {
        switch (err) {
            error.UnresolvableFeedGeometry, error.FeedRowCountOverflow => prediction_error = @errorName(err),
            else => return err,
        }
        break :blk cairo.proving.feed_geometry_oracle.Outcome{ .resolved = 0, .deferred = geometry.deferredCount() };
    };
    const components = try allocator.alloc(Component, geometry.components.len);
    defer allocator.free(components);
    var base_bytes: u64 = 0;
    var interaction_bytes: u64 = 0;
    for (geometry.components, components, was_deferred) |live, *component, deferred| {
        const log: ?u32 = switch (live.log_size) {
            .known => |value| value,
            .deferred => null,
        };
        const source = try library.sourceFor(live.name, log orelse 4, paths.variant);
        const template = source.find(live.name) orelse return error.MissingAirTemplate;
        var widths = [_]u64{0} ** 3;
        for (template.trace_spans) |span| {
            if (span.tree >= widths.len or span.end < span.start) return error.InvalidTraceSpan;
            widths[span.tree] += span.end - span.start;
        }
        const rows: ?u64 = if (log) |value| @as(u64, 1) << @intCast(value) else null;
        component.* = .{
            .name = live.name,
            .instance = live.instance,
            .log_size = log,
            .sizing_source = if (!deferred) "execution_resources" else if (log != null) "feed_prediction" else "witness_feed_cardinality",
            .base_columns = widths[1],
            .interaction_columns = widths[2],
            .base_bytes = if (rows) |count| try bytes(count, widths[1]) else null,
            .interaction_bytes = if (rows) |count| try bytes(count, widths[2]) else null,
        };
        base_bytes = try std.math.add(u64, base_bytes, component.base_bytes orelse 0);
        interaction_bytes = try std.math.add(u64, interaction_bytes, component.interaction_bytes orelse 0);
    }
    var storage: [64 * 1024]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&storage);
    try std.json.Stringify.value(.{
        .schema = "stwo-zig-cairo-input-plan-v1",
        .input = request.prover_input,
        .profile = paths.profile,
        .source_revision = cairo.claim_registry.source_revision,
        .proof_qualified = false,
        .execution_steps = input.state_transitions.casm_states_by_opcode.totalCount(),
        .resources = resources,
        .prediction_error = prediction_error,
        .unresolved_components = geometry.deferredCount(),
        .components = components,
        // Lower bound if feed geometry is unresolved. Excludes preprocessed
        // tables, LDEs, coefficients, commitments, scratch and retained input.
        .trace_storage = .{
            .base_bytes = base_bytes,
            .interaction_bytes = interaction_bytes,
            .complete = geometry.deferredCount() == 0,
            .is_peak_memory_estimate = false,
        },
        .inspection_ns = (try std.time.Instant.now()).since(started),
    }, .{}, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}

fn bytes(rows: u64, columns: u64) !u64 {
    return std.math.mul(u64, try std.math.mul(u64, rows, columns), @sizeOf(u32));
}
