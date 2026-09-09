//! Variable-width PCS input custody for heterogeneous recursive children.
//!
//! V1's row-20--29 owner stores three equal-width PCS input slices. Native
//! transparent-STARK children compile different column inventories, so their
//! PCS graphs legitimately have different binding counts. This append-only
//! arena derives canonical prefix offsets from the authenticated graphs,
//! copies every value once, and publishes only after the existing PCS witness
//! validator accepts the complete three-lane view.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const pcs = @import("pcs_deep_input_witness.zig");
const pcs_contract = @import("pcs_deep_input_witness_reference.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const LANE_COUNT: usize = 3;
const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursion-pcs-input-arena/v2\x00";

pub const Error = pcs.Error || error{
    InvalidHeterogeneousPcsArena,
};

pub const Arena = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    proof_kind: pcs.ProofKind,
    /// Canonical prefix offsets. Lane `i` is `storage[offsets[i]..offsets[i+1]]`.
    offsets: [LANE_COUNT + 1]usize,
    storage: []M31,
    reference_digest: [32]u8,
    witness: pcs.InputWitness,
    authority_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        reference: pcs.Reference,
        proof_kind: pcs.ProofKind,
        lane_values: [LANE_COUNT][]const M31,
    ) Error!Arena {
        try reference.validate();
        const offsets = try canonicalOffsets(reference);
        const storage = try allocator.alloc(M31, offsets[LANE_COUNT]);
        errdefer allocator.free(storage);
        for (lane_values, reference.lanes, 0..) |values, lane, lane_index| {
            if (values.len != lane.bindings.len)
                return error.InvalidHeterogeneousPcsArena;
            @memcpy(storage[offsets[lane_index]..offsets[lane_index + 1]], values);
        }
        var result = Arena{
            .allocator = allocator,
            .proof_kind = proof_kind,
            .offsets = offsets,
            .storage = storage,
            .reference_digest = reference.authority_digest,
            .witness = undefined,
            .authority_sha256 = undefined,
        };
        result.witness = result.witnessFor(reference);
        try pcs_contract.validateWitness(reference, result.witness, proof_kind);
        result.authority_sha256 = identity(&result);
        try result.validateAgainst(reference);
        return result;
    }

    pub fn deinit(self: *Arena) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn laneValues(self: *const Arena, lane: usize) []const M31 {
        std.debug.assert(lane < LANE_COUNT);
        return self.storage[self.offsets[lane]..self.offsets[lane + 1]];
    }

    pub fn validateAgainst(
        self: *const Arena,
        reference: pcs.Reference,
    ) Error!void {
        try reference.validate();
        const expected_offsets = try canonicalOffsets(reference);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.offsets, expected_offsets) or
            self.storage.len != expected_offsets[LANE_COUNT] or
            !std.mem.eql(u8, &self.reference_digest, &reference.authority_digest))
        {
            return error.InvalidHeterogeneousPcsArena;
        }
        const expected_witness = self.witnessFor(reference);
        for (self.witness.lanes, expected_witness.lanes) |retained, expected| {
            if (retained.verifier_id != expected.verifier_id or
                retained.circuit_id != expected.circuit_id or
                !std.mem.eql(u8, &retained.graph_digest, &expected.graph_digest) or
                retained.input_values.ptr != expected.input_values.ptr or
                retained.input_values.len != expected.input_values.len)
            {
                return error.InvalidHeterogeneousPcsArena;
            }
        }
        try pcs_contract.validateWitness(reference, self.witness, self.proof_kind);
        if (!std.mem.eql(u8, &self.authority_sha256, &identity(self)))
            return error.InvalidHeterogeneousPcsArena;
    }

    fn witnessFor(self: *const Arena, reference: pcs.Reference) pcs.InputWitness {
        var lanes: [LANE_COUNT]pcs.LaneWitness = undefined;
        for (&lanes, reference.lanes, 0..) |*target, lane, lane_index| target.* = .{
            .verifier_id = lane.verifier_id,
            .circuit_id = lane.circuit_id,
            .graph_digest = lane.graph.identity_digest,
            .input_values = self.laneValues(lane_index),
        };
        return .{ .lanes = lanes };
    }
};

fn canonicalOffsets(reference: pcs.Reference) Error![LANE_COUNT + 1]usize {
    var offsets = [_]usize{0} ** (LANE_COUNT + 1);
    for (reference.lanes, 0..) |lane, lane_index| {
        offsets[lane_index + 1] = std.math.add(
            usize,
            offsets[lane_index],
            lane.bindings.len,
        ) catch return error.ArithmeticOverflow;
    }
    return offsets;
}

fn identity(value: *const Arena) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.proof_kind));
    hash.update(&value.reference_digest);
    for (value.offsets) |offset| hashInt(&hash, u64, @as(u64, @intCast(offset)));
    for (value.storage) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or LANE_COUNT != 3)
        @compileError("heterogeneous PCS input arena contract drifted");
}
