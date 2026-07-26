const std = @import("std");
const claim_generator = @import("../../frontends/cairo/claim_generator.zig");
const claim_registry = @import("../../frontends/cairo/air/official_claim_registry.zig");
const adapter = @import("../../frontends/cairo/adapter/mod.zig");
const opcodes = @import("../../frontends/cairo/adapter/opcodes.zig");

const OracleComponent = struct {
    name: []const u8,
    instance: u32 = 0,
    log_size: u32,
};

const OracleOpcodeCount = struct {
    name: []const u8,
    count: usize,
};

const OracleVector = struct {
    schema_version: u32,
    case: []const u8,
    oracle: struct {
        kind: []const u8,
        artifact_stwo_cairo_revision: []const u8,
        claim_registry_stwo_cairo_revision: []const u8,
        adapted_input_sha256: []const u8,
        reference_proof_sha256: []const u8,
    },
    preprocessed_variant: []const u8,
    resources: struct {
        pc_count: usize,
        memory_address_count: usize,
        memory_big_value_count: usize,
        memory_small_value_count: usize,
        opcode_counts: []const OracleOpcodeCount,
    },
    components: []const OracleComponent,
};

test "Cairo claim generator: legacy Fib25k remains diagnostic geometry" {
    const vector_bytes = try std.fs.cwd().readFileAlloc(
        std.testing.allocator,
        "vectors/cairo/cairo_fib25k_claim_geometry.json",
        64 * 1024,
    );
    defer std.testing.allocator.free(vector_bytes);
    var parsed = try std.json.parseFromSlice(
        OracleVector,
        std.testing.allocator,
        vector_bytes,
        .{},
    );
    defer parsed.deinit();
    const oracle = parsed.value;

    try std.testing.expectEqual(@as(u32, 1), oracle.schema_version);
    try std.testing.expectEqualStrings("pinned_rust_stwo_cairo_test_only", oracle.oracle.kind);
    try std.testing.expect(!std.mem.eql(
        u8,
        claim_registry.source_revision.stwo_cairo,
        oracle.oracle.claim_registry_stwo_cairo_revision,
    ));

    var resources = claim_generator.ExecutionResources{
        .opcode_counts = [_]usize{0} ** opcodes.N_OPCODES,
        .pc_count = oracle.resources.pc_count,
        .memory_address_count = oracle.resources.memory_address_count,
        .memory_big_value_count = oracle.resources.memory_big_value_count,
        .memory_small_value_count = oracle.resources.memory_small_value_count,
        .builtin_segments = .{},
    };
    for (oracle.resources.opcode_counts) |entry| {
        const tag = std.meta.stringToEnum(opcodes.OpcodeTag, entry.name) orelse
            return error.UnknownOracleOpcode;
        resources.opcode_counts[@intFromEnum(tag)] = entry.count;
    }

    var geometry = try claim_generator.deriveFromResources(std.testing.allocator, resources, .{
        .preprocessed_variant = .canonical_without_pedersen,
    });
    defer geometry.deinit();

    try std.testing.expectEqual(@as(usize, 0), geometry.deferredCount());
    try std.testing.expectEqual(oracle.components.len, geometry.components.len);
    for (geometry.components, oracle.components) |actual, expected| {
        try std.testing.expectEqualStrings(expected.name, actual.name);
        try std.testing.expectEqual(expected.instance, actual.instance);
        try std.testing.expectEqual(expected.log_size, switch (actual.log_size) {
            .known => |log_size| log_size,
            .deferred => return error.UnexpectedDeferredGeometry,
        });
    }

    var flat = try geometry.flatten();
    defer flat.deinit();
    try std.testing.expectEqual(@as(usize, claim_registry.enable_slot_count), flat.component_enable_bits.len);
    try std.testing.expectEqual(oracle.components.len, std.mem.count(bool, flat.component_enable_bits, &.{true}));
    for (flat.component_log_sizes, oracle.components) |actual, expected| {
        try std.testing.expectEqual(expected.log_size, actual);
    }
}

test "Cairo claim generator: witness-fed Poseidon logs remain unresolved" {
    var opcode_counts = [_]usize{0} ** opcodes.N_OPCODES;
    opcode_counts[@intFromEnum(opcodes.OpcodeTag.ret_opcode)] = 1;
    const resources = claim_generator.ExecutionResources{
        .opcode_counts = opcode_counts,
        .pc_count = 1,
        .memory_address_count = 17,
        .memory_big_value_count = 16,
        .memory_small_value_count = 16,
        .builtin_segments = .{
            .poseidon_builtin = adapter.MemorySegmentAddresses{ .begin_addr = 100, .stop_ptr = 196 },
        },
    };
    var geometry = try claim_generator.deriveFromResources(std.testing.allocator, resources, .{
        .preprocessed_variant = .canonical_without_pedersen,
    });
    defer geometry.deinit();

    try std.testing.expectEqual(@as(usize, 5), geometry.deferredCount());
    try std.testing.expectError(claim_generator.Error.IncompleteClaimGeometry, geometry.flatten());

    const incomplete = [_]claim_generator.FeedGeometry{
        .{ .name = "poseidon_aggregator", .log_size = 4 },
    };
    try std.testing.expectError(
        claim_generator.Error.MissingFeedGeometry,
        geometry.resolveFeedGeometry(std.testing.allocator, &incomplete),
    );
    try std.testing.expectEqual(@as(usize, 5), geometry.deferredCount());

    const feeds = [_]claim_generator.FeedGeometry{
        .{ .name = "poseidon_aggregator", .log_size = 4 },
        .{ .name = "poseidon_3_partial_rounds_chain", .log_size = 4 },
        .{ .name = "poseidon_full_round_chain", .log_size = 4 },
        .{ .name = "cube_252", .log_size = 4 },
        .{ .name = "range_check_252_width_27", .log_size = 4 },
    };
    try geometry.resolveFeedGeometry(std.testing.allocator, &feeds);
    try std.testing.expectEqual(@as(usize, 0), geometry.deferredCount());
    var flat = try geometry.flatten();
    defer flat.deinit();
}
