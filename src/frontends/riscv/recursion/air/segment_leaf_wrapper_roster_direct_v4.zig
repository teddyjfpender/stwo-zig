//! Direct native-verifier V3 wrapper geometry.
//!
//! The first 39 rows prove verification of the native SegmentV2 proof in this
//! same transaction. The global V3 link adds eight rows. A separate 39-row
//! outer proof and its post-challenge PFD1 digest are not inputs. This module
//! fixes geometry only; it grants no proof-publication capability.

const std = @import("std");
const core = @import("stwo_core");
const base = @import("universal_manifest_contract.zig");
const v2 = @import("segment_outer_adapter_manifest_v2.zig");
const link = @import("segment_leaf_wrapper_link_manifest_v3.zig");
const word_air = @import("transcript_program_v2_field_source_v1.zig");
const hash_air = @import("vm_public_claim_hash.zig");
const tree0_air = @import("segment_v2_tree0_field_link_direct_v4.zig");
const frame_air = @import("transcript_word_direct_v4.zig");
const link_program = @import("../ethereum_leaf_link_program_v3.zig");
const hash_witness = @import("vm_public_claim_hash_witness.zig");
const typed = @import("universal_typed_component.zig");
const binding = @import("universal_relation_binding.zig");
const link_source_air = @import("ethereum_leaf_link_source_v1.zig");
const link_projection_air = @import("ethereum_leaf_link_projection_v1.zig");
const link_arithmetic_air = @import("ethereum_leaf_link_arithmetic_v1.zig");
const hash_relation = @import("vm_public_claim_hash_relation.zig");
const relation = @import("../../air/lang/relation.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const BASE_COUNT: usize = v2.COMPONENT_COUNT;
pub const COMPONENT_COUNT: usize = 47;
pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;
pub const TRANSCRIPT_DOMAIN: u32 = 0x5256_3457; // RV4W
pub const DOMAIN = "stwo-zig/riscv-direct-leaf-wrapper-roster/v4\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_WRAPPER_PROOF_AVAILABLE = false;

pub const ComponentKey = enum(u8) {
    link_source = 39,
    link_projection = 40,
    link_arithmetic = 41,
    program_words = 42,
    program_hash = 43,
    tree0_field = 44,
    metadata_hash = 45,
    link_hash = 46,
};
pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}
pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const AdapterBinding = @import("universal_adapter_manifest.zig").AdapterBinding;
pub const Manifest = Plan;
pub const LinkSourceAdapter = typed.ComponentForManifest(link_source_air, binding.Binding(link_source_air), @This());
pub const LinkProjectionAdapter = typed.ComponentForManifest(link_projection_air, binding.Binding(link_projection_air), @This());
pub const LinkArithmeticAdapter = typed.ComponentForManifest(link_arithmetic_air, binding.Binding(link_arithmetic_air), @This());
pub const FieldWordsAdapter = typed.ComponentForManifest(word_air, binding.Binding(word_air), @This());
pub const FieldHashAdapter = typed.ComponentForManifest(hash_air, hash_relation, @This());
pub const Tree0Adapter = typed.ComponentForManifest(tree0_air, binding.Binding(tree0_air), @This());

comptime {
    if (BASE_COUNT != 39 or link.COMPONENT_COUNT != 42 or COMPONENT_COUNT > 64 or
        link_program.METADATA_HASH_ROW_COUNT != 77 or
        link_program.LINK_HASH_ROW_COUNT != 7)
        @compileError("V3 wrapper roster or Poseidon caller schedule drifted");
}

/// Shape evidence only. `base_poseidon_calls` must eventually come from the
/// newly constructed wrapper provider, not from a caller's assertion. The
/// constructor below uses it only to reserve the correct committed geometry;
/// no function here turns this plan into a proof or verified publication.
pub const Shape = struct {
    program_words: usize,
    base_poseidon_calls: usize,
};

pub const PoseidonCalls = struct {
    base: usize,
    metadata: usize,
    link: usize,
    program: usize,
    total: usize,

    pub fn validate(self: PoseidonCalls) !void {
        const sum = try std.math.add(usize, self.base, self.metadata);
        const with_link = try std.math.add(usize, sum, self.link);
        const with_program = try std.math.add(usize, with_link, self.program);
        if (self.total != with_program)
            return error.V3PoseidonCallCountMismatch;
    }
};

pub const Plan = struct {
    format_version: u16 = FORMAT_VERSION,
    roster_rows: [COMPONENT_COUNT]u8,
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    base_manifest_seal: [32]u8,
    program_schedule_id: [32]u8,
    poseidon_calls: PoseidonCalls,
    shape: Shape,
    seal: [32]u8,

    /// The V2 manifest contributes authenticated *geometry* and its seal.
    /// It is not imported as a proof prefix. `program` is reconstructed from
    /// the pinned compiler, and each new row's geometry comes from typed AIR.
    pub fn build(
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        program: *const link_program.ProgramV3,
        shape: Shape,
    ) !Plan {
        const result = try buildRaw(allocator, base_manifest, program, shape);
        try result.validate();
        return result;
    }

    fn buildRaw(
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        program: *const link_program.ProgramV3,
        shape: Shape,
    ) !Plan {
        try base_manifest.validate();
        if (shape.program_words == 0 or
            shape.program_words >= core.fields.m31.Modulus or
            shape.base_poseidon_calls == 0)
            return error.InvalidV3WrapperShape;

        const base_provider_log = base_manifest.placements[34].?.geometry.log_size;
        if (shape.base_poseidon_calls > (@as(usize, 1) << @intCast(base_provider_log)))
            return error.V3PoseidonCallCountMismatch;

        const hash_rate = hash_witness.RATE;
        const program_hash_calls = try std.math.divCeil(usize, shape.program_words + 1, hash_rate);
        const calls = PoseidonCalls{
            .base = shape.base_poseidon_calls,
            .metadata = link_program.METADATA_HASH_ROW_COUNT,
            .link = link_program.LINK_HASH_ROW_COUNT,
            .program = program_hash_calls,
            .total = try checkedSum(&.{
                shape.base_poseidon_calls,
                link_program.METADATA_HASH_ROW_COUNT,
                link_program.LINK_HASH_ROW_COUNT,
                program_hash_calls,
            }),
        };
        try calls.validate();
        const provider_log = try hash_witness.traceLogSize(calls.total);

        const link_manifest = try link.Manifest.build(allocator, program);
        var rows: [COMPONENT_COUNT]u8 = undefined;
        var placements: [COMPONENT_COUNT]?Placement = @splat(null);
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (0..COMPONENT_COUNT) |index| {
            const row: u8 = @intCast(index);
            var item: Geometry = if (index < BASE_COUNT)
                base_manifest.placements[index].?.geometry
            else if (index < link.COMPONENT_COUNT)
                link_manifest.placements[index].?.geometry
            else
                try extraGeometry(row, shape, program);
            if (index == 4) item = frameGeometry(item.log_size);
            if (index == 34) item.log_size = provider_log;
            try item.validateForComponentCount(COMPONENT_COUNT);
            if (item.roster_row != row) return error.InvalidV3WrapperRoster;
            rows[index] = row;
            placements[index] = .{
                .geometry = item,
                .preprocessed_offset = pp,
                .main_offset = main,
                .interaction_offset = interaction,
                .constraint_offset = constraints,
                .claimed_sum_index = row,
            };
            pp = try std.math.add(u32, pp, item.preprocessed_columns);
            main = try std.math.add(u32, main, item.main_columns);
            interaction = try std.math.add(u32, interaction, item.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, item.direct_constraints) + item.interaction_batches);
        }
        var result = Plan{
            .roster_rows = rows,
            .placements = placements,
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .base_manifest_seal = base_manifest.seal,
            .program_schedule_id = program.schedule_id,
            .poseidon_calls = calls,
            .shape = shape,
            .seal = undefined,
        };
        result.seal = planSeal(&result);
        return result;
    }

    pub fn validate(self: *const Plan) !void {
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.program_schedule_id, link_program.SCHEDULE_ID) or
            !std.mem.eql(u8, &self.seal, &planSeal(self)))
            return error.InvalidV3WrapperRoster;
        if (self.shape.program_words == 0 or
            self.shape.program_words >= core.fields.m31.Modulus or
            self.shape.base_poseidon_calls == 0)
            return error.InvalidV3WrapperShape;
        try self.poseidon_calls.validate();
        if (self.shape.base_poseidon_calls != self.poseidon_calls.base or
            self.poseidon_calls.metadata != link_program.METADATA_HASH_ROW_COUNT or
            self.poseidon_calls.link != link_program.LINK_HASH_ROW_COUNT or
            self.poseidon_calls.program != try std.math.divCeil(usize, self.shape.program_words + 1, hash_witness.RATE))
            return error.V3PoseidonCallCountMismatch;
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (self.roster_rows, self.placements, 0..) |row, maybe_item, index| {
            const item = maybe_item orelse return error.InvalidV3WrapperRoster;
            if (row != index or item.geometry.roster_row != row or
                item.claimed_sum_index != row or
                item.preprocessed_offset != pp or item.main_offset != main or
                item.interaction_offset != interaction or
                item.constraint_offset != constraints)
                return error.InvalidV3WrapperRoster;
            try item.geometry.validateForComponentCount(COMPONENT_COUNT);
            if (index == 4) {
                if (!std.meta.eql(item.geometry, frameGeometry(item.geometry.log_size)))
                    return error.InvalidV3WrapperRoster;
            } else if (index >= link.V2_COMPONENT_COUNT and index < link.COMPONENT_COUNT) {
                const expected = switch (index) {
                    39 => LinkSourceAdapter.manifestGeometry(.link_source, try hash_witness.traceLogSize(link_program.SOURCE_ROW_COUNT)),
                    40 => LinkProjectionAdapter.manifestGeometry(.link_projection, try hash_witness.traceLogSize(link_program.PROJECTION_ROW_COUNT)),
                    41 => LinkArithmeticAdapter.manifestGeometry(.link_arithmetic, 4),
                    else => unreachable,
                };
                if (!std.meta.eql(item.geometry, expected))
                    return error.InvalidV3WrapperRoster;
            } else if (index >= link.COMPONENT_COUNT) {
                const expected = try extraGeometryStatic(row, self.shape);
                if (!std.meta.eql(item.geometry, expected))
                    return error.InvalidV3WrapperRoster;
            }
            pp = try std.math.add(u32, pp, item.geometry.preprocessed_columns);
            main = try std.math.add(u32, main, item.geometry.main_columns);
            interaction = try std.math.add(u32, interaction, item.geometry.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, item.geometry.direct_constraints) + item.geometry.interaction_batches);
        }
        if (pp != self.total_preprocessed_columns or
            main != self.total_main_columns or
            interaction != self.total_interaction_columns or
            constraints != self.total_constraints or
            self.placements[34].?.geometry.log_size != try hash_witness.traceLogSize(self.poseidon_calls.total))
            return error.InvalidV3WrapperRoster;
    }

    /// A resealed attacker-controlled geometry still fails this independent
    /// reconstruction against the admitted V2 manifest and fixed typed AIR.
    pub fn validateAgainst(
        self: *const Plan,
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        program: *const link_program.ProgramV3,
        shape: Shape,
    ) !void {
        try self.validate();
        if (!std.meta.eql(self.shape, shape) or
            !std.meta.eql(self.program_schedule_id, program.schedule_id) or
            !std.mem.eql(u8, &self.base_manifest_seal, &base_manifest.seal))
            return error.InvalidV3WrapperRoster;
        // Rebuild without recursing into this public validator.
        const expected = try buildRaw(allocator, base_manifest, program, shape);
        if (!std.meta.eql(self.*, expected)) return error.InvalidV3WrapperRoster;
    }

    /// Only geometry and registry identity. A future transaction must mix the
    /// verifier-owned V3 statement, child proof/key identity and field
    /// authorities separately before drawing any relation challenges.
    pub fn mixGeometryPrefix(self: *const Plan, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{
            TRANSCRIPT_DOMAIN,
            FORMAT_VERSION,
            COMPONENT_COUNT,
            self.total_preprocessed_columns,
            self.total_main_columns,
            self.total_interaction_columns,
            self.total_constraints,
        });
        channel.mixU32s(&digestWords(self.seal));
        channel.mixU32s(&digestWords(self.base_manifest_seal));
        channel.mixU32s(&digestWords(relation.registryOrderDigest()));
    }

    pub fn placement(self: *const Plan, key: ComponentKey) !Placement {
        try self.validate();
        return self.placements[keyIndex(key)] orelse error.InvalidV3WrapperRoster;
    }

    pub fn requireCompleteWrapperProof(_: *const Plan) error{V3WrapperProofUnavailable}!void {
        return error.V3WrapperProofUnavailable;
    }
};

fn frameGeometry(log_size: u32) Geometry {
    return .{
        .roster_row = 4,
        .log_size = log_size,
        .preprocessed_columns = frame_air.PREPROCESSED_COLUMN_COUNT,
        .main_columns = frame_air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = frame_air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = frame_air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = frame_air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(frame_air)),
        .profiled_constraint_degree = frame_air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = frame_air.SEMANTIC_DIGEST,
    };
}

fn extraGeometry(row: u8, shape: Shape, program: *const link_program.ProgramV3) !Geometry {
    const key: ComponentKey = @enumFromInt(row);
    return switch (key) {
        .program_words => FieldWordsAdapter.manifestGeometry(.program_words, try hash_witness.traceLogSize(shape.program_words)),
        .program_hash => FieldHashAdapter.manifestGeometry(.program_hash, try hash_witness.traceLogSize(try std.math.divCeil(usize, shape.program_words + 1, hash_witness.RATE))),
        .tree0_field => Tree0Adapter.manifestGeometry(.tree0_field, 4),
        .metadata_hash => FieldHashAdapter.manifestGeometry(.metadata_hash, program.metadata_hash.log_size),
        .link_hash => FieldHashAdapter.manifestGeometry(.link_hash, program.link_hash.log_size),
        else => error.InvalidV3WrapperRoster,
    };
}

fn extraGeometryStatic(row: u8, shape: Shape) !Geometry {
    const key: ComponentKey = @enumFromInt(row);
    return switch (key) {
        .program_words => FieldWordsAdapter.manifestGeometry(.program_words, try hash_witness.traceLogSize(shape.program_words)),
        .program_hash => FieldHashAdapter.manifestGeometry(.program_hash, try hash_witness.traceLogSize(try std.math.divCeil(usize, shape.program_words + 1, hash_witness.RATE))),
        .tree0_field => Tree0Adapter.manifestGeometry(.tree0_field, 4),
        .metadata_hash => FieldHashAdapter.manifestGeometry(.metadata_hash, try hash_witness.traceLogSize(link_program.METADATA_HASH_ROW_COUNT)),
        .link_hash => FieldHashAdapter.manifestGeometry(.link_hash, try hash_witness.traceLogSize(link_program.LINK_HASH_ROW_COUNT)),
        else => error.InvalidV3WrapperRoster,
    };
}

fn checkedSum(values: []const usize) !usize {
    var result: usize = 0;
    for (values) |value| result = try std.math.add(usize, result, value);
    return result;
}

fn planSeal(value: *const Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.roster_rows);
    hash.update(&value.base_manifest_seal);
    hash.update(&value.program_schedule_id);
    for (value.placements) |maybe_item| {
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
    inline for (.{ value.total_preprocessed_columns, value.total_main_columns, value.total_interaction_columns, value.total_constraints }) |n|
        hashInt(&hash, u32, n);
    inline for (.{ value.shape.program_words, value.shape.base_poseidon_calls, value.poseidon_calls.base, value.poseidon_calls.metadata, value.poseidon_calls.link, value.poseidon_calls.program, value.poseidon_calls.total }) |n|
        hashInt(&hash, u64, @intCast(n));
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
    return result;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
