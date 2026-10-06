//! Versioned 50-row direct native leaf geometry and six ordered Poseidon ranges.
//! V4 supplies the base geometry. V5 replaces rows 36 and 42 with versioned
//! typed AIR, then appends the local identity router and two hash components.
//! No proof is admitted.

const std = @import("std");
const core = @import("stwo_core");
const base = @import("universal_manifest_contract.zig");
const v2 = @import("segment_outer_adapter_manifest_v2.zig");
const v4 = @import("segment_leaf_wrapper_roster_direct_v4.zig");
const typed = @import("universal_typed_component.zig");
const binding = @import("universal_relation_binding.zig");
const router_air = @import("ethereum_leaf_child_field_router_v1.zig");
const hash_air = @import("vm_public_claim_hash.zig");
const hash_relation = @import("vm_public_claim_hash_relation.zig");
const hash_witness = @import("vm_public_claim_hash_witness.zig");
const statement_air = @import("segment_leaf_statement_source_direct_v5.zig");
const program_bridge_air = @import("transcript_program_v2_field_bridge_v5.zig");
const local = @import("../segment_leaf_wrapper_local_identity_v5.zig");
const local_program = @import("../ethereum_leaf_child_field_program_v1.zig");
const link_program = @import("../ethereum_leaf_link_program_v3.zig");
const relation = @import("../../air/lang/relation.zig");
const statement_v1 = @import("../../air/statement.zig");

pub const FORMAT_VERSION: u16 = 5;
pub const COMPONENT_COUNT: usize = 50;
pub const PREFIX_COUNT: usize = v4.COMPONENT_COUNT;
pub const TREE_COUNT = base.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = base.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = base.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = base.INTERACTION_TREE_INDEX;
pub const TRANSCRIPT_DOMAIN: u32 = 0x5256_3557; // RV5W
pub const DOMAIN = "stwo-zig/riscv-direct-leaf-wrapper-roster/v5\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const COMPLETE_WRAPPER_PROOF_AVAILABLE = false;

pub const Geometry = base.Geometry;
pub const Placement = base.Placement;
pub const Manifest = Plan;
pub const ComponentKey = enum(u8) {
    local_router = 47,
    local_authority_hash = 48,
    local_receipt_hash = 49,
};
pub fn keyIndex(key: ComponentKey) u8 {
    return @intFromEnum(key);
}
pub const RouterAdapter = typed.ComponentForManifest(router_air, binding.Binding(router_air), @This());
pub const HashAdapter = typed.ComponentForManifest(hash_air, hash_relation, @This());

comptime {
    if (PREFIX_COUNT != 47 or COMPONENT_COUNT > 64 or local.ROW_COUNT != 3)
        @compileError("direct local identity roster drifted");
}

pub const Range = struct { start: usize, count: usize };
pub const PoseidonCalls = struct {
    base: Range,
    metadata: Range,
    link: Range,
    program: Range,
    authority: Range,
    receipt: Range,
    total: usize,

    pub fn init(prefix: v4.PoseidonCalls, authority: usize, receipt: usize) !PoseidonCalls {
        try prefix.validate();
        if (authority == 0 or receipt == 0) return error.InvalidLocalIdentityShape;
        const ranges = PoseidonCalls{
            .base = .{ .start = 0, .count = prefix.base },
            .metadata = .{ .start = prefix.base, .count = prefix.metadata },
            .link = .{ .start = try std.math.add(usize, prefix.base, prefix.metadata), .count = prefix.link },
            .program = .{ .start = try std.math.add(usize, prefix.base + prefix.metadata, prefix.link), .count = prefix.program },
            .authority = .{ .start = prefix.total, .count = authority },
            .receipt = .{ .start = try std.math.add(usize, prefix.total, authority), .count = receipt },
            .total = try std.math.add(usize, try std.math.add(usize, prefix.total, authority), receipt),
        };
        try ranges.validate();
        return ranges;
    }

    pub fn ordered(self: PoseidonCalls) [6]Range {
        return .{ self.base, self.metadata, self.link, self.program, self.authority, self.receipt };
    }

    pub fn validate(self: PoseidonCalls) !void {
        var cursor: usize = 0;
        for (self.ordered()) |range| {
            if (range.count == 0 or range.start != cursor)
                return error.InvalidV5PoseidonCallRanges;
            cursor = try std.math.add(usize, cursor, range.count);
        }
        if (cursor != self.total) return error.InvalidV5PoseidonCallRanges;
    }
};

pub const Plan = struct {
    format_version: u16 = FORMAT_VERSION,
    base_plan: v4.Plan,
    roster_rows: [COMPONENT_COUNT]u8,
    placements: [COMPONENT_COUNT]?Placement,
    total_preprocessed_columns: u32,
    total_main_columns: u32,
    total_interaction_columns: u32,
    total_constraints: u32,
    local_schedule_id: [32]u8,
    poseidon_calls: PoseidonCalls,
    seal: [32]u8,

    pub fn build(
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        link: *const link_program.ProgramV3,
        shape: v4.Shape,
        local_source: *const local_program.ProgramV1,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) !Plan {
        const result = try buildRaw(allocator, base_manifest, link, shape, local_source, component_descs, infra_descs);
        try result.validate();
        return result;
    }

    fn buildRaw(
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        link: *const link_program.ProgramV3,
        shape: v4.Shape,
        local_source: *const local_program.ProgramV1,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) !Plan {
        try local_source.validateAgainst(component_descs, infra_descs);
        const prefix = try v4.Plan.build(allocator, base_manifest, link, shape);
        const schedule_id = try local.directScheduleId(local_source);
        const layout = try local.Layout.init(local_source);
        const calls = try PoseidonCalls.init(prefix.poseidon_calls, local_source.authority_hash.rows.len, local_source.receipt_hash.rows.len);
        const provider_log = try hash_witness.traceLogSize(calls.total);
        var rows: [COMPONENT_COUNT]u8 = undefined;
        var placements: [COMPONENT_COUNT]?Placement = @splat(null);
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (0..COMPONENT_COUNT) |index| {
            const row: u8 = @intCast(index);
            var geometry = if (index < PREFIX_COUNT)
                prefix.placements[index].?.geometry
            else switch (index) {
                47 => RouterAdapter.manifestGeometry(.local_router, layout.placements[0].log_size),
                48 => HashAdapter.manifestGeometry(.local_authority_hash, layout.placements[1].log_size),
                49 => HashAdapter.manifestGeometry(.local_receipt_hash, layout.placements[2].log_size),
                else => unreachable,
            };
            if (index == 34) geometry.log_size = provider_log;
            if (index == 36) geometry = statementGeometry(geometry.log_size);
            if (index == 42) geometry = programBridgeGeometry(geometry.log_size);
            try geometry.validateForComponentCount(COMPONENT_COUNT);
            if (geometry.roster_row != row) return error.InvalidV5WrapperRoster;
            rows[index] = row;
            placements[index] = .{
                .geometry = geometry,
                .preprocessed_offset = pp,
                .main_offset = main,
                .interaction_offset = interaction,
                .constraint_offset = constraints,
                .claimed_sum_index = row,
            };
            pp = try std.math.add(u32, pp, geometry.preprocessed_columns);
            main = try std.math.add(u32, main, geometry.main_columns);
            interaction = try std.math.add(u32, interaction, geometry.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, geometry.direct_constraints) + geometry.interaction_batches);
        }
        var result = Plan{
            .base_plan = prefix,
            .roster_rows = rows,
            .placements = placements,
            .total_preprocessed_columns = pp,
            .total_main_columns = main,
            .total_interaction_columns = interaction,
            .total_constraints = constraints,
            .local_schedule_id = schedule_id,
            .poseidon_calls = calls,
            .seal = undefined,
        };
        result.seal = planSeal(&result);
        return result;
    }

    pub fn validate(self: *const Plan) !void {
        try self.base_plan.validate();
        try self.poseidon_calls.validate();
        if (self.format_version != FORMAT_VERSION or
            !std.mem.eql(u8, &self.seal, &planSeal(self)))
            return error.InvalidV5WrapperRoster;
        const prefix = self.base_plan.poseidon_calls;
        if (self.poseidon_calls.base.count != prefix.base or
            self.poseidon_calls.metadata.count != prefix.metadata or
            self.poseidon_calls.link.count != prefix.link or
            self.poseidon_calls.program.count != prefix.program or
            self.poseidon_calls.authority.start != prefix.total)
            return error.InvalidV5PoseidonCallRanges;
        const provider_log = try hash_witness.traceLogSize(self.poseidon_calls.total);
        var pp: u32 = 0;
        var main: u32 = 0;
        var interaction: u32 = 0;
        var constraints: u32 = 0;
        for (self.roster_rows, self.placements, 0..) |row, maybe_placement, index| {
            const item = maybe_placement orelse return error.InvalidV5WrapperRoster;
            if (row != index or item.geometry.roster_row != row or
                item.claimed_sum_index != row or item.preprocessed_offset != pp or
                item.main_offset != main or item.interaction_offset != interaction or
                item.constraint_offset != constraints)
                return error.InvalidV5WrapperRoster;
            try item.geometry.validateForComponentCount(COMPONENT_COUNT);
            const expected = if (index < PREFIX_COUNT) blk: {
                var value = self.base_plan.placements[index].?.geometry;
                if (index == 34) value.log_size = provider_log;
                if (index == 36) value = statementGeometry(value.log_size);
                if (index == 42) value = programBridgeGeometry(value.log_size);
                break :blk value;
            } else switch (index) {
                47 => RouterAdapter.manifestGeometry(.local_router, item.geometry.log_size),
                48 => HashAdapter.manifestGeometry(.local_authority_hash, item.geometry.log_size),
                49 => HashAdapter.manifestGeometry(.local_receipt_hash, item.geometry.log_size),
                else => unreachable,
            };
            if (!std.meta.eql(item.geometry, expected)) return error.InvalidV5WrapperRoster;
            pp = try std.math.add(u32, pp, item.geometry.preprocessed_columns);
            main = try std.math.add(u32, main, item.geometry.main_columns);
            interaction = try std.math.add(u32, interaction, item.geometry.interaction_columns);
            constraints = try std.math.add(u32, constraints, @as(u32, item.geometry.direct_constraints) + item.geometry.interaction_batches);
        }
        if (pp != self.total_preprocessed_columns or main != self.total_main_columns or
            interaction != self.total_interaction_columns or constraints != self.total_constraints)
            return error.InvalidV5WrapperRoster;
    }

    /// Rejects a resealed attacker-selected schedule or hash-call count by
    /// reconstructing both versioned programs from verifier-owned inputs.
    pub fn validateAgainst(
        self: *const Plan,
        allocator: std.mem.Allocator,
        base_manifest: *const v2.Manifest,
        link: *const link_program.ProgramV3,
        shape: v4.Shape,
        local_source: *const local_program.ProgramV1,
        component_descs: []const statement_v1.FamilyComponentDesc,
        infra_descs: []const statement_v1.InfraComponentDesc,
    ) !void {
        try self.validate();
        const expected = try buildRaw(allocator, base_manifest, link, shape, local_source, component_descs, infra_descs);
        if (!std.meta.eql(self.*, expected)) return error.InvalidV5WrapperRoster;
    }

    pub fn mixGeometryPrefix(self: *const Plan, channel: anytype) !void {
        try self.validate();
        channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, COMPONENT_COUNT, self.total_preprocessed_columns, self.total_main_columns, self.total_interaction_columns, self.total_constraints });
        channel.mixU32s(&digestWords(self.seal));
        channel.mixU32s(&digestWords(self.local_schedule_id));
        channel.mixU32s(&digestWords(relation.registryOrderDigest()));
    }

    pub fn placement(self: *const Plan, key: ComponentKey) !Placement {
        try self.validate();
        return self.placements[keyIndex(key)] orelse error.InvalidV5WrapperRoster;
    }

    pub fn requireCompleteWrapperProof(_: *const Plan) error{V5WrapperProofUnavailable}!void {
        return error.V5WrapperProofUnavailable;
    }
};

fn statementGeometry(log_size: u32) Geometry {
    return .{
        .roster_row = 36,
        .log_size = log_size,
        .preprocessed_columns = statement_air.PREPROCESSED_COLUMN_COUNT,
        .main_columns = statement_air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = statement_air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = statement_air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = statement_air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(statement_air)),
        .profiled_constraint_degree = statement_air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = statement_air.SEMANTIC_DIGEST,
    };
}

fn programBridgeGeometry(log_size: u32) Geometry {
    return .{
        .roster_row = 42,
        .log_size = log_size,
        .preprocessed_columns = program_bridge_air.PREPROCESSED_COLUMN_COUNT,
        .main_columns = program_bridge_air.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = program_bridge_air.INTERACTION_COLUMN_COUNT,
        .direct_constraints = program_bridge_air.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = program_bridge_air.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = @intCast(typed.protocolMaximumConstraintDegree(program_bridge_air)),
        .profiled_constraint_degree = program_bridge_air.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = program_bridge_air.SEMANTIC_DIGEST,
    };
}

fn planSeal(value: *const Plan) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hash.update(&value.base_plan.seal);
    hash.update(&value.local_schedule_id);
    hash.update(&value.roster_rows);
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
    for (value.poseidon_calls.ordered()) |range| {
        hashInt(&hash, u64, @intCast(range.start));
        hashInt(&hash, u64, @intCast(range.count));
    }
    hashInt(&hash, u64, @intCast(value.poseidon_calls.total));
    return hash.finalResult();
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

test "direct V5 roster pins 50 typed rows and six ordered call ranges" {
    const allocator = std.testing.allocator;
    const fixture = @import("../../wrapper_roster_v3_test_root.zig");
    const catalog = @import("segment_outer_typed_catalog_v2.zig");
    const child_fixture = @import("../tests/ethereum_leaf_child_field_test.zig");
    const source_catalog = try catalog.build(fixture.fixtureLogSizes(), fixture.boundaryComponents());
    const base_manifest = try v2.assemble(&source_catalog, fixture.authorityIds());
    var link = try link_program.ProgramV3.init(allocator);
    defer link.deinit();
    var child = try local_program.ProgramV1.init(allocator, &child_fixture.components, &child_fixture.infra);
    defer child.deinit();
    const shape = v4.Shape{ .program_words = 100, .base_poseidon_calls = 1193 };
    var plan = try Plan.build(allocator, &base_manifest, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    try plan.validateAgainst(allocator, &base_manifest, &link, shape, &child, &child_fixture.components, &child_fixture.infra);
    try std.testing.expectEqual(@as(usize, 50), plan.placements.len);
    try std.testing.expectEqual(@as(usize, 6), plan.poseidon_calls.ordered().len);
    try std.testing.expectEqual(plan.poseidon_calls.total, plan.poseidon_calls.receipt.start + plan.poseidon_calls.receipt.count);
    try std.testing.expectEqual(try hash_witness.traceLogSize(plan.poseidon_calls.total), plan.placements[34].?.geometry.log_size);
    try std.testing.expectEqualDeep(statement_air.SEMANTIC_DIGEST, plan.placements[36].?.geometry.semantic_digest);
    try std.testing.expectEqualDeep(program_bridge_air.SEMANTIC_DIGEST, plan.placements[42].?.geometry.semantic_digest);
    try std.testing.expectEqualDeep(router_air.SEMANTIC_DIGEST, plan.placements[47].?.geometry.semantic_digest);
    try std.testing.expectEqualDeep(hash_air.SEMANTIC_DIGEST, plan.placements[48].?.geometry.semantic_digest);

    plan.poseidon_calls.receipt.start += 1;
    try std.testing.expectError(error.InvalidV5PoseidonCallRanges, plan.validate());
    plan.poseidon_calls.receipt.start -= 1;
    plan.placements[36].?.geometry.semantic_digest[0] ^= 1;
    plan.seal = planSeal(&plan);
    try std.testing.expectError(error.InvalidV5WrapperRoster, plan.validate());
    plan.placements[36].?.geometry.semantic_digest[0] ^= 1;
    plan.local_schedule_id[0] ^= 1;
    plan.seal = planSeal(&plan);
    try std.testing.expectError(error.InvalidV5WrapperRoster, plan.validateAgainst(allocator, &base_manifest, &link, shape, &child, &child_fixture.components, &child_fixture.infra));
    child.component_count += 1;
    try std.testing.expectError(error.InvalidEthereumChildFieldProgram, Plan.build(allocator, &base_manifest, &link, shape, &child, &child_fixture.components, &child_fixture.infra));
}
