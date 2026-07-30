const std = @import("std");
pub const stwo = @import("stwo");
const metal_runtime = stwo.backends.metal.runtime;
const composition_bundle_mod = stwo.frontends.cairo.witness.composition_bundle;
const canonical_protocol_support = @import("canonical_protocol.zig");

pub const CanonicalProtocol = canonical_protocol_support.CanonicalProtocol;
pub const canonical_protocol = canonical_protocol_support.canonical_protocol;

pub const protocolObjectIsCanonical = canonical_protocol_support.objectIsCanonical;

const runOne = @import("runner.zig").runOne;

const host_geometry_mod = @import("host_geometry.zig");
const prepared_state_mod = @import("prepared_state_cache.zig");
const timing_mod = @import("timing.zig");

pub const PreparedStateKey = host_geometry_mod.PreparedStateKey;
pub const PreparedHostGeometry = host_geometry_mod.PreparedHostGeometry;
pub const PreparedStateTelemetry = timing_mod.PreparedStateTelemetry;
pub const PreparedStateCache = prepared_state_mod.PreparedStateCache;

const runtimeVerifierGeometry = host_geometry_mod.runtimeVerifierGeometry;

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    var output_buffer: [4096]u8 = undefined;
    var output = std.fs.File.stdout().writer(&output_buffer);
    try runOne(allocator, args, null, null, null, &output.interface);
    try output.interface.flush();
}

/// Executes one invocation while borrowing a process-owned Metal runtime.
/// Request isolation and the report destination remain caller-owned.
pub fn proveOne(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    runtime: *metal_runtime.Runtime,
    report_writer: *std.Io.Writer,
) !void {
    try runOne(allocator, args, runtime, null, null, report_writer);
}

pub fn proveOnePrepared(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    runtime: *metal_runtime.Runtime,
    prepared_state: *PreparedStateCache,
    prepared_state_key: PreparedStateKey,
    report_writer: *std.Io.Writer,
) !void {
    try runOne(
        allocator,
        args,
        runtime,
        .{ .cache = prepared_state, .key = prepared_state_key },
        null,
        report_writer,
    );
}

pub fn proveOnePreparedGeometry(
    allocator: std.mem.Allocator,
    args: []const []const u8,
    runtime: *metal_runtime.Runtime,
    prepared_state: *PreparedStateCache,
    prepared_state_key: PreparedStateKey,
    prepared_geometry: *const PreparedHostGeometry,
    report_writer: *std.Io.Writer,
) !void {
    try runOne(
        allocator,
        args,
        runtime,
        .{ .cache = prepared_state, .key = prepared_state_key },
        prepared_geometry,
        report_writer,
    );
}

fn requireResidentPreprocessedCoefficients(composition_requested: bool, populated: bool) !void {
    if (composition_requested and !populated) return error.MissingPreprocessedCoefficients;
}

test "resident composition requires preprocessed coefficients" {
    try requireResidentPreprocessedCoefficients(false, false);
    try requireResidentPreprocessedCoefficients(true, true);
    try std.testing.expectError(
        error.MissingPreprocessedCoefficients,
        requireResidentPreprocessedCoefficients(true, false),
    );
}

test "runtime verifier geometry follows projected composition degree" {
    const config_words = [_]u32{ 26, 1, 70, 0, 3, 0, 0, 0 };
    var composition = composition_bundle_mod.Bundle{
        .allocator = undefined,
        .format_version = composition_bundle_mod.projected_version,
        .max_kernel_instructions = 1,
        .total_constraints = 1,
        .max_evaluation_log_size = 21,
        .plan_hash = 1,
        .components = &.{},
    };
    const fib = try runtimeVerifierGeometry(&config_words, composition);
    try std.testing.expectEqual(@as(usize, 4), fib.trace_tree_count);
    try std.testing.expectEqual(@as(usize, 7), fib.fri_layer_count);
    try std.testing.expectEqual(@as(u32, 20), fib.max_log_degree_bound);
    try std.testing.expect(fib.matchesTranscript(&config_words));

    composition.format_version = composition_bundle_mod.version;
    composition.max_evaluation_log_size = 24;
    const sn2 = try runtimeVerifierGeometry(&config_words, composition);
    try std.testing.expectEqual(@as(usize, 8), sn2.fri_layer_count);
    try std.testing.expectEqual(@as(u32, 24), sn2.max_log_degree_bound);
    try std.testing.expectError(
        error.InvalidProtocolGeometry,
        runtimeVerifierGeometry(&config_words, .{
            .allocator = undefined,
            .max_kernel_instructions = 1,
            .total_constraints = 1,
            .max_evaluation_log_size = 0,
            .plan_hash = 1,
            .components = &.{},
        }),
    );
}

test "canonical proof protocol uses the exact report contract" {
    const encoded =
        \\{"channel":"blake2s","channel_salt":0,"log_blowup_factor":1,"n_queries":70,"interaction_pow_bits":24,"query_pow_bits":26,"fri_fold_step":3,"fri_lifting":null,"fri_log_last_layer_degree_bound":0}
    ;
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    try std.testing.expect(protocolObjectIsCanonical(parsed.value));

    const invalid = [_][]const u8{
        // Extra and missing fields are rejected, not ignored.
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0,\"extra\":0}",
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null}",
        // JSON booleans and floats never coerce into protocol integers.
        "{\"channel\":\"blake2s\",\"channel_salt\":false,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}",
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70.0,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}",
        // Null lifting and every fixed value are part of the proof identity.
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":71,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":null,\"fri_log_last_layer_degree_bound\":0}",
        "{\"channel\":\"blake2s\",\"channel_salt\":0,\"log_blowup_factor\":1,\"n_queries\":70,\"interaction_pow_bits\":24,\"query_pow_bits\":26,\"fri_fold_step\":3,\"fri_lifting\":0,\"fri_log_last_layer_degree_bound\":0}",
    };
    for (invalid) |document| {
        var candidate = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, document, .{});
        defer candidate.deinit();
        try std.testing.expect(!protocolObjectIsCanonical(candidate.value));
    }
}

test {
    _ = @import("prepared_cache_tests.zig");
}
