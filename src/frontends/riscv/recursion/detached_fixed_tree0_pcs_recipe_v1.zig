//! Proof-free reconstruction of the detached leaf's PCS-DEEP Tree0 row.
//! The only variable facts are admitted native descriptors and PCS parameters.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const PcsConfig = @import("stwo_core").pcs.PcsConfig;
const authority = @import("detached_segment_authority_boundary_v1.zig");
const geometry_mod = @import("detached_native_column_geometry_v1.zig");
const ids = @import("detached_pcs_circuit_ids_v1.zig");
const pcs_circuit = @import("air/pcs_deep_circuit.zig");
const pcs_air = @import("air/pcs_deep_input.zig");
const pcs_witness = @import("air/pcs_deep_input_witness.zig");
const KeyV1 = @import("detached_segment_protocol_v1.zig").KeyV1;

/// The caller retains independent key-identity custody. This function reads
/// only the admitted key and canonical program constants; no proof is an input.
pub fn fillFromKey(
    allocator: std.mem.Allocator,
    key: *const KeyV1,
    columns: *[pcs_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    try key.validate();
    const placement = key.manifest.placements[24] orelse return error.InvalidFixedPcsGeometry;
    if (placement.geometry.preprocessed_columns != pcs_witness.PREPROCESSED_COLUMN_COUNT)
        return error.InvalidFixedPcsGeometry;
    return fill(allocator, key.native_descriptors, key.profile.nativePcsConfig(), placement.geometry.log_size, columns);
}

fn fill(
    allocator: std.mem.Allocator,
    descriptors: authority.DescriptorsV1,
    native_pcs_config: PcsConfig,
    log_size: u32,
    columns: *[pcs_witness.PREPROCESSED_COLUMN_COUNT][]M31,
) !void {
    var geometry = try geometry_mod.init(
        allocator,
        descriptors,
        native_pcs_config.fri_config.log_blowup_factor,
    );
    defer geometry.deinit();
    const profile = try geometry.pcsProfile(
        std.math.cast(u32, native_pcs_config.fri_config.n_queries) orelse
            return error.InvalidFixedPcsGeometry,
    );
    var circuit = try pcs_circuit.Prepared.init(allocator, profile);
    defer circuit.deinit();
    const lane_profile = try circuit.laneProfile();
    const lanes = [3]pcs_witness.Lane{
        .{ .verifier_id = pcs_witness.SEGMENT_VERIFIER_ID, .circuit_id = ids.SEGMENT, .profile = lane_profile, .graph = circuit.graph(), .bindings = circuit.view().bindings },
        .{ .verifier_id = pcs_witness.LEFT_RECURSION_VERIFIER_ID, .circuit_id = ids.LEFT_RECURSION, .profile = lane_profile, .graph = circuit.graph(), .bindings = circuit.view().bindings },
        .{ .verifier_id = pcs_witness.RIGHT_RECURSION_VERIFIER_ID, .circuit_id = ids.RIGHT_RECURSION, .profile = lane_profile, .graph = circuit.graph(), .bindings = circuit.view().bindings },
    };
    const reference = try pcs_witness.Reference.authenticate(lanes, pcs_witness.computeReferenceDigest(lanes));
    var preprocessing = try pcs_witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
    if (preprocessing.log_size != log_size or log_size >= @bitSizeOf(usize))
        return error.InvalidFixedPcsGeometry;
    const size = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.len != size)
        return error.InvalidFixedPcsGeometry;

    var definition = try pcs_air.build(allocator);
    defer definition.deinit();
    const binding = try pcs_witness.Binding.canonical(&definition);
    const executor = try pcs_witness.Executor.init(&definition, &binding);
    try executor.generatePreprocessedInto(&preprocessing, reference, columns);
}

fn censusDigest(columns: []const []const M31) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for (columns) |column| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, column.len, .little);
        hash.update(&bytes);
        for (column) |word| {
            var field: [4]u8 = undefined;
            std.mem.writeInt(u32, &field, word.toU32(), .little);
            hash.update(&field);
        }
    }
    return hash.finalResult();
}

test "q193 PCS fixed row 24 regenerates from native descriptors without proof input" {
    const allocator = std.testing.allocator;
    const descriptors = @import("tests/q193_native_census_fixture.zig").DESCRIPTORS;
    const size: usize = 1 << 19;
    const words = try allocator.alloc(M31, size * pcs_witness.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(words);
    var columns: [pcs_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    var view: [pcs_witness.PREPROCESSED_COLUMN_COUNT][]const M31 = undefined;
    for (&columns, &view, 0..) |*column, *source, index| {
        column.* = words[index * size ..][0..size];
        source.* = column.*;
    }
    try fill(allocator, descriptors, @import("protocol.zig").PCS_CONFIG, 19, &columns);
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "ccd6ec59d7ddf4439da2cc4ebaa1ee190025f3d5c5104f8908f2435fa0dded7d");
    try std.testing.expectEqual(expected, censusDigest(&view));
}
