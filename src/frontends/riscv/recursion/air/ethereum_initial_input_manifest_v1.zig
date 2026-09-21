//! Explicit initial-input extension of the Ethereum statement-routing roster.
//! The ordinary 36-row manifest is preserved, followed by the authenticated
//! input lane and packet bridge. Equations and widths come from their typed AIRs.
//! This contract admits geometry; it does not establish a complete proof.
const std = @import("std");
const base = @import("universal_adapter_manifest.zig");
const universal = @import("universal_manifest.zig");
const profile = @import("../incremental_ethereum_composition_profile_v4.zig");
const typed = @import("universal_typed_geometry.zig");
const relation = @import("../../air/lang/relation.zig");
pub const LaneAir = @import("ethereum_initial_input_lane_v1.zig");
pub const PacketAir = @import("ethereum_initial_input_packet_v1.zig");
pub const COMPONENT_COUNT = base.COMPONENT_COUNT + 2;
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const LogSizesV4 = [COMPONENT_COUNT]u32;
pub const StatementRootProfile = profile;
pub const TRANSCRIPT_FORMAT_VERSION: u32 = 1;
pub const TRANSCRIPT_DOMAIN: u32 = 0x4549_4c31; // EIL1
pub const CLAIM_DOMAIN = "stwo-zig/ethereum-initial-input-claims/v1\x00";
pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;
pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = base.AdapterBinding;
pub const Error = base.Error || universal.Error || error{InvalidEthereumInitialManifest};

// Retain every prior name/index from the canonical enum, rather than maintain
// a second transcription of the shared roster.
pub const ComponentKey = blk: {
    var info = @typeInfo(base.ComponentKey).@"enum";
    var fields: [COMPONENT_COUNT]std.builtin.Type.EnumField = undefined;
    @memcpy(fields[0..base.COMPONENT_COUNT], info.fields);
    fields[base.COMPONENT_COUNT] = .{ .name = "ethereum_initial_input_lane", .value = base.COMPONENT_COUNT };
    fields[base.COMPONENT_COUNT + 1] = .{ .name = "ethereum_initial_input_packet", .value = base.COMPONENT_COUNT + 1 };
    info.fields = &fields;
    break :blk @Type(.{ .@"enum" = info });
};
pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}

const ProofProtocol = @import("manifest_proof_protocol.zig").Types(@This());
pub const ClaimVector = ProofProtocol.ClaimVector;
pub const ProofGate = ProofProtocol.ProofGate;

pub const Manifest = struct {
    format_version: u16 = FORMAT_VERSION,
    ordinary: base.Manifest,
    input_capacity: u32,
    roster_count: u8 = COMPONENT_COUNT,
    roster_rows: [COMPONENT_COUNT]u8,
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    seal: [32]u8,

    pub fn validate(self: *const Manifest) Error!void {
        const expected = try build(&self.ordinary, self.input_capacity);
        if (!std.meta.eql(self.*, expected)) return error.ManifestSealMismatch;
    }
    pub fn placement(self: *const Manifest, row: ComponentKey) Error!Placement {
        try self.validate();
        return self.placements[keyIndex(row)] orelse error.ComponentNotAdmitted;
    }
    pub fn transcriptHeader(self: *const Manifest) [7]u32 {
        return .{ TRANSCRIPT_DOMAIN, TRANSCRIPT_FORMAT_VERSION, self.roster_count, self.total_preprocessed_columns, self.total_main_columns, self.total_interaction_columns, self.total_constraints };
    }
    pub fn mixStatementPrefix(self: *const Manifest, channel: anytype) Error!void {
        try self.validate();
        channel.mixU32s(&self.transcriptHeader());
        channel.mixU32s(&digestWords(self.seal));
        channel.mixU32s(&digestWords(relation.registryOrderDigest()));
    }
};

/// Only fixed circuit structure enters this manifest. Job and input values
/// remain independently admitted sources and authenticated AIR statements.
pub fn build(ordinary: *const base.Manifest, input_capacity: u32) Error!Manifest {
    try ordinary.validate();
    if (ordinary.roster_count != base.COMPONENT_COUNT) return error.InvalidEthereumInitialManifest;
    var logs: universal.LogSizes = undefined;
    for (&logs, 0..) |*log, index| log.* = (ordinary.placements[index] orelse return error.InvalidEthereumInitialManifest).geometry.log_size;
    const expected = try universal.buildForCatalog(profile.StatementRoutingOuterCatalog, logs);
    if (!std.meta.eql(ordinary.*, expected)) return error.InvalidEthereumInitialManifest;
    const shape = LaneAir.Shape.init(input_capacity) catch return error.InvalidEthereumInitialManifest;
    const lane_log: u32 = std.math.log2_int(u32, shape.role_capacity);
    const packet_log: u32 = std.math.log2_int(usize, PacketAir.ROW_COUNT);
    const additions = [_]Geometry{
        typed.manifestGeometryForAir(LaneAir, @This(), .ethereum_initial_input_lane, lane_log),
        typed.manifestGeometryForAir(PacketAir, @This(), .ethereum_initial_input_packet, packet_log),
    };
    var result = Manifest{
        .ordinary = ordinary.*,
        .input_capacity = input_capacity,
        .roster_rows = undefined,
        .placements = undefined,
        .total_preprocessed_columns = ordinary.total_preprocessed_columns,
        .total_main_columns = ordinary.total_main_columns,
        .total_interaction_columns = ordinary.total_interaction_columns,
        .total_constraints = ordinary.total_constraints,
        .seal = undefined,
    };
    @memcpy(result.roster_rows[0..base.COMPONENT_COUNT], &ordinary.roster_rows);
    @memcpy(result.placements[0..base.COMPONENT_COUNT], &ordinary.placements);
    for (additions) |geometry| {
        try geometry.validateForComponentCount(COMPONENT_COUNT);
        const row = geometry.roster_row;
        result.roster_rows[row] = row;
        result.placements[row] = .{ .geometry = geometry, .preprocessed_offset = result.total_preprocessed_columns, .main_offset = result.total_main_columns, .interaction_offset = result.total_interaction_columns, .constraint_offset = result.total_constraints, .claimed_sum_index = row };
        result.total_preprocessed_columns = try add(result.total_preprocessed_columns, geometry.preprocessed_columns);
        result.total_main_columns = try add(result.total_main_columns, geometry.main_columns);
        result.total_interaction_columns = try add(result.total_interaction_columns, geometry.interaction_columns);
        result.total_constraints = try add(result.total_constraints, @as(u32, geometry.direct_constraints) + geometry.interaction_batches);
    }
    // Everything outside these independent identities is derived above from
    // typed AIR definitions and canonical ordering, then checked by validate.
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/ethereum-initial-input-manifest/v1\x00");
    hash.update(&ordinary.seal);
    hash.update(&LaneAir.SEMANTIC_DIGEST);
    hash.update(&PacketAir.SEMANTIC_DIGEST);
    for ([_]u32{ FORMAT_VERSION, COMPONENT_COUNT, input_capacity, lane_log, packet_log }) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        hash.update(&bytes);
    }
    result.seal = hash.finalResult();
    return result;
}

fn add(left: u32, right: anytype) Error!u32 {
    return std.math.add(u32, left, @intCast(right)) catch error.ArithmeticOverflow;
}

pub fn validateExact(value: *const Manifest, logs: LogSizesV4) Error!void {
    try value.validate();
    for (value.placements, logs) |item, log| {
        if ((item orelse return error.InvalidEthereumInitialManifest).geometry.log_size != log) return error.LogSizeMismatch;
    }
}
fn digestWords(value: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    return words;
}
