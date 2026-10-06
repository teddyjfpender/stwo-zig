//! Versioned 49-row V3 roster for the corrected row-39/40 program.
//!
//! Geometry is reconstructed directly from ProgramV2. The seal binds every
//! placement and the pinned schedule ID, so the same log sizes cannot alias
//! the earlier unclosed provider-digest schedule or its protocol key.

const std = @import("std");
const roster = @import("segment_leaf_wrapper_roster_v3.zig");
const child_manifest = @import("segment_outer_adapter_manifest_v2.zig");
const program_mod = @import("../ethereum_leaf_link_program_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const DOMAIN = "stwo-zig/riscv-v3-leaf-wrapper-roster/v2\x00";
pub const COMPONENT_COUNT = roster.COMPONENT_COUNT;
pub const TREE_COUNT = roster.TREE_COUNT;
pub const PRODUCTION_PROOF_ACTIVATION = false;

pub const PlanV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    program_schedule_id: [32]u8,
    geometry: roster.Plan,
    seal: [32]u8,

    pub fn build(
        allocator: std.mem.Allocator,
        base_manifest: *const child_manifest.Manifest,
        program: *const program_mod.ProgramV2,
        shape: roster.Shape,
    ) !PlanV2 {
        try program.validate();
        const geometry = try roster.Plan.build(allocator, base_manifest, program, shape);
        var result = PlanV2{
            .program_schedule_id = program.schedule_id,
            .geometry = geometry,
            .seal = undefined,
        };
        result.seal = digest(&result);
        try result.validateAgainst(allocator, base_manifest, program, shape);
        return result;
    }

    pub fn validate(self: *const PlanV2) !void {
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.program_schedule_id, program_mod.SCHEDULE_ID))
            return error.InvalidV3LeafWrapperRosterV2;
        try self.geometry.validate();
        if (!std.meta.eql(self.seal, digest(self)))
            return error.InvalidV3LeafWrapperRosterV2;
    }

    pub fn validateAgainst(
        self: *const PlanV2,
        allocator: std.mem.Allocator,
        base_manifest: *const child_manifest.Manifest,
        program: *const program_mod.ProgramV2,
        shape: roster.Shape,
    ) !void {
        try self.validate();
        try program.validate();
        try self.geometry.validateAgainst(allocator, base_manifest, program, shape);
        if (!std.meta.eql(self.program_schedule_id, program.schedule_id))
            return error.InvalidV3LeafWrapperRosterV2;
    }

    pub fn requireCompleteWrapperProof(_: *const PlanV2) error{V3WrapperProofUnavailable}!void {
        return error.V3WrapperProofUnavailable;
    }
};

fn digest(value: *const PlanV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.program_schedule_id);
    hash.update(&value.geometry.base_manifest_seal);
    for (value.geometry.placements) |maybe_item| {
        const item = maybe_item orelse return @splat(0);
        const g = item.geometry;
        hashInt(&hash, u8, g.roster_row);
        hashInt(&hash, u32, g.log_size);
        inline for (.{ g.preprocessed_columns, g.main_columns, g.interaction_columns, g.direct_constraints, g.interaction_batches }) |n|
            hashInt(&hash, u16, n);
        hashInt(&hash, u8, g.protocol_constraint_degree);
        hashInt(&hash, u8, g.profiled_constraint_degree);
        hash.update(&g.semantic_digest);
        inline for (.{ item.preprocessed_offset, item.main_offset, item.interaction_offset, item.constraint_offset }) |n|
            hashInt(&hash, u32, n);
        hashInt(&hash, u8, item.claimed_sum_index);
    }
    inline for (.{ value.geometry.total_preprocessed_columns, value.geometry.total_main_columns, value.geometry.total_interaction_columns, value.geometry.total_constraints }) |n|
        hashInt(&hash, u32, n);
    inline for (.{ value.geometry.shape.program_words, value.geometry.shape.provider_words, value.geometry.shape.base_poseidon_calls, value.geometry.poseidon_calls.total }) |n|
        hashInt(&hash, u64, @intCast(n));
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

test "corrected wrapper roster rejects a changed schedule identity" {
    // The key boundary may be checked without constructing an expensive
    // native cohort; full geometry is reconstructed in `validateAgainst`.
    var invalid: PlanV2 = undefined;
    invalid.format_version = FORMAT_VERSION;
    invalid.program_schedule_id = program_mod.SCHEDULE_ID;
    invalid.program_schedule_id[0] ^= 1;
    try std.testing.expectError(error.InvalidV3LeafWrapperRosterV2, invalid.validate());
}
