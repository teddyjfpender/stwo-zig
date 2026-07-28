//! Pre-execution feed-geometry parity tests.
//!
//! These live in the frontend test root rather than beside the resolver because
//! `zig build addTest` only collects tests from its root module's own files;
//! tests inside the `cairo_frontend` dependency module compile but never run.
//!
//! The parity claim under test is the one the arena activation depends on: the
//! log sizes `feed_geometry_oracle` computes from the adapted prover input alone
//! are *bit-identical* to the ones the witness-to-statement handoff
//! (`OwnedClaimGeometry.resolveFeedGeometry`) produces after execution. The
//! reference here is not this repository's own measurement but the pinned
//! official claim summary vector, so a drift in either the resolver or the
//! topology fails the test.

const std = @import("std");
const cairo = @import("cairo_frontend");

const oracle = cairo.proving.feed_geometry_oracle;

const claim_summary_path = "vectors/cairo/official/all_opcodes.claim_summary.json";
const input_path = "vectors/cairo/official/all_opcodes.prover_input.json";
const topology_path = "vectors/cairo/official/witness_feed_topology_v1.json";

fn jsonU32(value: std.json.Value) !u32 {
    return switch (value) {
        .integer => |raw| std.math.cast(u32, raw) orelse error.InvalidOracleVector,
        else => error.InvalidOracleVector,
    };
}

fn findField(name: []const u8) ?cairo.claim_registry.ClaimField {
    for (cairo.claim_registry.claim_fields) |field| {
        if (std.mem.eql(u8, name, field.name)) return field;
    }
    return null;
}

test "pre-execution feed geometry reproduces the official resolved claim exactly" {
    const allocator = std.testing.allocator;

    const encoded = try std.fs.cwd().readFileAlloc(allocator, claim_summary_path, 64 * 1024);
    defer allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    const flat_json = parsed.value.object.get("flat_claim").?.object;
    const expected_bits = flat_json.get("component_enable_bits").?.array.items;
    const expected_logs = flat_json.get("component_log_sizes").?.array.items;

    var slot_logs = [_]?u32{null} ** cairo.claim_registry.enable_slot_count;
    var log_index: usize = 0;
    for (expected_bits, 0..) |enabled, slot| {
        if (!enabled.bool) continue;
        slot_logs[slot] = try jsonU32(expected_logs[log_index]);
        log_index += 1;
    }

    var input = try cairo.adapter.official_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var topology = try cairo.witness.feed_topology.readOfficial(allocator, topology_path);
    defer topology.deinit();

    var geometry = try cairo.claim_generator.deriveFromProverInput(
        allocator,
        &input,
        .{ .preprocessed_variant = .canonical },
    );
    defer geometry.deinit();

    // The premise of the increment: this workload really does arrive with
    // unresolved feed geometry, so the resolver is being exercised.
    const deferred_before = geometry.deferredCount();
    try std.testing.expect(deferred_before > 0);

    // Record which entries were deferred, so the assertion below is specifically
    // about the resolver's output and not about entries the claim already knew.
    const was_deferred = try allocator.alloc(bool, geometry.components.len);
    defer allocator.free(was_deferred);
    for (geometry.components, was_deferred) |component, *flag|
        flag.* = component.log_size == .deferred;

    const outcome = try oracle.resolveInPlace(
        allocator,
        &geometry,
        cairo.claim_generator.ExecutionResources.fromProverInput(&input),
        topology,
    );
    try std.testing.expectEqual(deferred_before, outcome.resolved);
    try std.testing.expectEqual(@as(usize, 0), geometry.deferredCount());

    var checked: usize = 0;
    for (geometry.components, was_deferred) |component, deferred| {
        if (!deferred) continue;
        const field = findField(component.name) orelse return error.UnknownClaimComponent;
        const slot = @as(usize, field.first_enable_slot) + component.instance;
        const expected = slot_logs[slot] orelse return error.InvalidOracleVector;
        try std.testing.expectEqual(expected, component.log_size.known);
        checked += 1;
    }
    try std.testing.expectEqual(deferred_before, checked);

    // `flatten` refuses a deferred entry, so a successful flatten is the same
    // completeness the AIR template binder demands before execution.
    var flat = try geometry.flatten();
    defer flat.deinit();
    for (expected_logs, flat.component_log_sizes) |expected, actual|
        try std.testing.expectEqual(try jsonU32(expected), actual);
}

test "pre-execution feed geometry is a no-op on an already-complete claim" {
    const allocator = std.testing.allocator;
    var input = try cairo.adapter.official_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var topology = try cairo.witness.feed_topology.readOfficial(allocator, topology_path);
    defer topology.deinit();
    var geometry = try cairo.claim_generator.deriveFromProverInput(
        allocator,
        &input,
        .{ .preprocessed_variant = .canonical },
    );
    defer geometry.deinit();
    const resources = cairo.claim_generator.ExecutionResources.fromProverInput(&input);
    _ = try oracle.resolveInPlace(allocator, &geometry, resources, topology);

    // Second application must change nothing and must report nothing resolved:
    // the resolver is idempotent, which is what makes it safe to run before the
    // arena plan without perturbing the claim the statement is built from.
    const again = try oracle.resolveInPlace(allocator, &geometry, resources, topology);
    try std.testing.expectEqual(@as(usize, 0), again.resolved);
    try std.testing.expectEqual(@as(usize, 0), again.deferred);
}

test "pre-execution feed geometry refuses a claim whose producers are absent" {
    const allocator = std.testing.allocator;
    var topology = try cairo.witness.feed_topology.readOfficial(allocator, topology_path);
    defer topology.deinit();

    // A deferred component with no active producer in the claim is a
    // topology/claim disagreement, and the resolver must refuse rather than
    // invent a row count.
    const components = try allocator.alloc(cairo.claim_generator.ComponentGeometry, 1);
    components[0] = .{ .name = "blake_round", .instance = 0, .log_size = .{ .deferred = .witness_feed_cardinality } };
    var geometry = cairo.claim_generator.OwnedClaimGeometry{
        .allocator = allocator,
        .components = components,
    };
    defer geometry.deinit();

    var resources = std.mem.zeroes(cairo.claim_generator.ExecutionResources);
    resources.builtin_segments = std.mem.zeroes(cairo.adapter.BuiltinSegments);
    try std.testing.expectError(
        oracle.Error.UnresolvableFeedGeometry,
        oracle.resolveInPlace(allocator, &geometry, resources, topology),
    );
    try std.testing.expectEqual(@as(usize, 1), geometry.deferredCount());
}
