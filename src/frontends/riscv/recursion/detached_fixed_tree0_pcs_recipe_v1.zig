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
    const descriptors = authority.DescriptorsV1{
        .components = &.{
            .{ .family = .base_alu_imm, .log_size = 4, .n_rows = 12, .n_columns = 35 },
            .{ .family = .load_store, .log_size = 5, .n_rows = 22, .n_columns = 50 },
            .{ .family = .lui, .log_size = 4, .n_rows = 1, .n_columns = 18 },
        },
        .infrastructure = &.{
            .{ .kind = .program, .log_size = 6, .n_rows = 36, .n_columns = 10 },
            .{ .kind = .merkle, .log_size = 9, .n_rows = 466, .n_columns = 10 },
            .{ .kind = .poseidon2, .log_size = 9, .n_rows = 466, .n_columns = 445 },
            .{ .kind = .clock_update, .log_size = 4, .n_rows = 0, .n_columns = 10 },
            .{ .kind = .bitwise, .log_size = 18, .n_rows = 262144, .n_columns = 1 },
            .{ .kind = .range_check_20, .log_size = 20, .n_rows = 1048576, .n_columns = 1 },
            .{ .kind = .range_check_8_11, .log_size = 19, .n_rows = 524288, .n_columns = 1 },
            .{ .kind = .range_check_8_8_4, .log_size = 20, .n_rows = 1048576, .n_columns = 1 },
            .{ .kind = .range_check_8_8, .log_size = 16, .n_rows = 65536, .n_columns = 1 },
            .{ .kind = .range_check_m31, .log_size = 15, .n_rows = 32768, .n_columns = 1 },
        },
    };
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
