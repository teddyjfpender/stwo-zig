//! Owned witness rows for the explicit initial-input lane and packet bridge.
//! Fixed packet routes come from the native core's immutable admitted graph;
//! packet witnesses are copied from that graph's actual evaluated inputs.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const table = frontend.air.lookups.tables.schema;
const packet_words = @import("recursive_common_ethereum_initial_input_packet_v1.zig");
const role = @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const Lane = air.ethereum_initial_input_lane_v1;
pub const Packet = air.ethereum_initial_input_packet_v1;
pub const LANE_COMPONENT: u8 = 36;
pub const PACKET_COMPONENT: u8 = 37;
pub const RANGE_TABLE_SIZE: usize = table.size(.range_check_8_8);

pub const OwnedV1 = opaque {
    const Self = @This();
    pub fn init(allocator: std.mem.Allocator, materialized: anytype, native: anytype) !*Self {
        try materialized.validate();
        const admission = materialized.initial_input_admission orelse return error.InvalidEthereumInitialInputAdmission;
        try admission.validateInput(&materialized.base.input);
        const shape = try Lane.Shape.init(admission.claimShape().max_input_words);
        const public = &materialized.base.input.stage101.role_aware_public.value;
        const words = try native.initialPacketWords();
        const preprocessing = try native.initialPacketPreprocessing();
        const owned = try allocator.create(Storage);
        errdefer allocator.destroy(owned);
        var definition = try Lane.build(allocator);
        errdefer definition.deinit();
        var packet_definition = try Packet.build(allocator);
        errdefer packet_definition.deinit();
        const lane_rows = try allocator.alloc(Lane.Row, shape.role_capacity);
        errdefer allocator.free(lane_rows);
        const histogram = try allocator.alloc(u32, RANGE_TABLE_SIZE);
        errdefer allocator.free(histogram);
        var packet_rows: [Packet.ROW_COUNT]Packet.Row = undefined;
        try generate(shape, public.io_entries.input_words, words, preprocessing, lane_rows, &packet_rows, histogram);
        // These are same-value checks against existing authenticated witnesses,
        // never replacement constants or a host-only proof acceptance path.
        const header = [4]M31{ field(public.io_entries.input_start & 65535), field(public.io_entries.input_start >> 16), field(shape.max_input_words & 65535), field(shape.max_input_words >> 16) };
        const first = role.HEADER_WORD_COUNT + @as(usize, shape.max_input_words) * role.TUPLE_WORD_COUNT;
        var program: [18]M31 = undefined;
        for (&program, materialized.role_aware_io.canonical_words[first..][0..18]) |*word, value| word.* = field(value);
        const memory = materialized.base.input.stage101.relations.base.memory_access;
        const expected = packet_words.witnessWords(memory.z, memory.alpha, header, materialized.role_aware_io.claims.memory_access, program);
        if (!std.meta.eql(words, expected)) return error.EthereumInitialPacketWitnessMismatch;
        owned.* = .{ .allocator = allocator, .shape = shape, .definition = definition, .packet_definition = packet_definition, .lane_plan = try Lane.Relation.authenticate(&definition), .packet_plan = try Packet.Relation.authenticate(&packet_definition), .lane_rows = lane_rows, .packet_rows = packet_rows, .range_histogram = histogram, .materialized_identity = materialized.identity_sha256, .program_identity = native.publicSumsProgramIdentity() };
        return @ptrCast(owned);
    }
    pub fn deinit(self: *Self) void {
        const owned: *Storage = @ptrCast(@alignCast(self));
        const allocator = owned.allocator;
        allocator.free(owned.range_histogram);
        allocator.free(owned.lane_rows);
        owned.packet_definition.deinit();
        owned.definition.deinit();
        allocator.destroy(owned);
    }
    pub fn laneRows(self: *const Self) []const Lane.Row {
        return self.storage().lane_rows;
    }
    pub fn packetRows(self: *const Self) []const Packet.Row {
        return &self.storage().packet_rows;
    }
    pub fn lanePlan(self: *const Self) *const Lane.Relation.Plan {
        return &self.storage().lane_plan;
    }
    pub fn packetPlan(self: *const Self) *const Packet.Relation.Plan {
        return &self.storage().packet_plan;
    }
    pub fn laneShape(self: *const Self) Lane.Shape {
        return self.storage().shape;
    }
    pub fn rangeHistogram(self: *const Self) []const u32 {
        return self.storage().range_histogram;
    }
    pub fn rangeContributionCount(self: *const Self) usize {
        return self.laneRows().len * Lane.RANGE_REQUEST_COUNT;
    }
    pub fn contributionBound(self: *const Self) usize {
        return self.laneRows().len * Lane.RELATION_EVENT_COUNT + self.packetRows().len * Packet.RELATION_EVENT_COUNT;
    }
    pub fn validateAgainst(self: *const Self, materialized: anytype, native: anytype) !void {
        const owned = self.storage();
        if (!std.meta.eql(owned.materialized_identity, materialized.identity_sha256) or !std.meta.eql(owned.program_identity, native.publicSumsProgramIdentity()) or materialized.initial_input_admission == null or owned.shape.max_input_words != materialized.initial_input_admission.?.claimShape().max_input_words) return error.InvalidEthereumInitialInputRows;
    }
    /// Prefix columns belong to their existing owners. The selected manifest
    /// authenticates these two appended placements before any write.
    pub fn validateDestination(self: *const Self, destination: []const []M31) !void {
        const support = @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");
        const protected = .{ try support.sliceRange(self.laneRows()), try support.sliceRange(self.packetRows()), try support.sliceRange(self.rangeHistogram()) };
        for (destination) |column| {
            const target = try support.sliceRange(column);
            inline for (protected) |source| if (target.overlaps(source)) return error.DestinationAlias;
        }
    }
    pub fn fillBaseInto(self: *const Self, manifest: *const air.ethereum_initial_input_manifest_v1.Manifest, tree: usize, destination: []const []M31) !void {
        try manifest.validate();
        try self.validateDestination(destination);
        if (manifest.input_capacity != self.laneShape().max_input_words) return error.InvalidEthereumInitialInputRows;
        try fillBase(Lane, self.laneRows(), manifest, LANE_COMPONENT, tree, destination);
        try fillBase(Packet, self.packetRows(), manifest, PACKET_COMPONENT, tree, destination);
    }
    pub fn fillInteractionInto(self: *const Self, manifest: *const air.ethereum_initial_input_manifest_v1.Manifest, relations: *const air.universal_challenges.UniversalRelations, destination: []const []M31) ![2]QM31 {
        try manifest.validate();
        try self.validateDestination(destination);
        if (manifest.input_capacity != self.laneShape().max_input_words) return error.InvalidEthereumInitialInputRows;
        return .{
            try fillInteraction(Lane, self.storage().allocator, self.lanePlan(), self.laneRows(), manifest, LANE_COMPONENT, relations, destination),
            try fillInteraction(Packet, self.storage().allocator, self.packetPlan(), self.packetRows(), manifest, PACKET_COMPONENT, relations, destination),
        };
    }
    pub fn auditClaims(self: *const Self, relations: *const air.universal_challenges.UniversalRelations, claims: [2]QM31) ![2]air.relation_interaction.DomainAudit {
        return .{
            try self.lanePlan().auditPreparedDomainSums(self.storage().allocator, self.laneRows(), relations, claims[0]),
            try self.packetPlan().auditPreparedDomainSums(self.storage().allocator, self.packetRows(), relations, claims[1]),
        };
    }
    pub fn appendTupleContributions(self: *const Self, ledger: *air.relation_interaction.TupleLedger, domain_mask: u64) !void {
        try self.lanePlan().appendPreparedTupleContributions(ledger, LANE_COMPONENT, self.laneRows(), domain_mask);
        try self.packetPlan().appendPreparedTupleContributions(ledger, PACKET_COMPONENT, self.packetRows(), domain_mask);
    }
    fn storage(self: *const Self) *const Storage {
        return @ptrCast(@alignCast(self));
    }
};
const Storage = struct {
    allocator: std.mem.Allocator,
    shape: Lane.Shape,
    definition: Lane.Definition,
    packet_definition: Packet.Definition,
    lane_plan: Lane.Relation.Plan,
    packet_plan: Packet.Relation.Plan,
    lane_rows: []Lane.Row,
    packet_rows: [Packet.ROW_COUNT]Packet.Row,
    range_histogram: []u32,
    materialized_identity: [32]u8,
    program_identity: [32]u8,
};

/// Pure witness generation, not an admission constructor. Exposed so the
/// genuine small fixture exercises exactly the production row writer.
pub fn generate(shape: Lane.Shape, input: []const u32, words: [Packet.INPUT_COUNT]M31, preprocessing: [Packet.ROW_COUNT]Packet.Preprocessing, rows: []Lane.Row, packets: *[Packet.ROW_COUNT]Packet.Row, histogram: []u32) !void {
    if (!std.meta.eql(shape, try Lane.Shape.init(shape.max_input_words)) or input.len != shape.max_input_words or rows.len != shape.role_capacity or histogram.len != RANGE_TABLE_SIZE) return error.InvalidEthereumInitialInputRows;
    @memset(histogram, 0);
    var coefficients: [6]QM31 = undefined;
    for (&coefficients, 0..) |*value, index| value.* = QM31.fromM31Array(words[index * 4 ..][0..4].*);
    const header = words[Lane.HEADER_SLOT * 4 ..][0..4].*;
    for (header) |limb| if (limb.toU32() > 65535) return error.InvalidEthereumInitialInputHeader;
    if (header[2].toU32() + 65536 * header[3].toU32() != shape.max_input_words) return error.InvalidEthereumInitialInputRows;
    var sum = QM31.zero();
    for (rows, 0..) |*row, index| {
        row.* = try Lane.row(shape, @intCast(index), .{ .header = header, .coefficients = coefficients, .word = if (index < input.len) input[index] else 0, .present = index < input.len, .previous_present = index <= input.len, .previous_sum = sum, .program_words = if (index == input.len) words[Lane.PROGRAM_FIRST_SLOT * 4 ..][0..18].* else null });
        sum = sum.add(QM31.fromM31Array(row[40..44].*));
        for (Lane.rangePairs(row.*)) |pair| {
            const index_in_table = try table.indexBase(.range_check_8_8, &pair);
            histogram[index_in_table] = try std.math.add(u32, histogram[index_in_table], 1);
        }
    }
    if (!sum.eql(QM31.fromM31Array(words[Lane.SUM_SLOT * 4 ..][0..4].*))) return error.EthereumInitialInputSubtotalMismatch;
    for (packets, preprocessing, 0..) |*row, pp, index| row.* = Packet.row(pp, if (index < Packet.PACKET_COUNT) words[index * 4 ..][0..4].* else [_]M31{M31.zero()} ** 4);
}
fn field(value: u32) M31 {
    return M31.fromCanonical(value);
}

/// Initial public sums retain only the six role-header publishers. Every
/// canonical tuple word belongs to the linear lane, including padding. Do
/// not mask duplicate publishers after the fact: reject a mismatched program.
pub fn validateOrdinaryRolePublishers(rows: []const air.ethereum_public_logup_input_v1.Relation.Row) !void {
    const legacy = air.vm_public_logup_input;
    const at = legacy.PHYSICAL_MAIN_COLUMN_COUNT + legacy.PREPROCESSED_COLUMN_COUNT;
    var seen = [_]bool{false} ** role.HEADER_WORD_COUNT;
    for (rows) |row| {
        if (row[at].isZero() or row[at + 1].toU32() != Lane.ROLE_HASH_SCOPE) continue;
        const index = row[at + 2].toU32();
        if (!row[at].eql(M31.one()) or index >= seen.len or seen[index]) return error.DuplicateEthereumInitialRolePublisher;
        seen[index] = true;
    }
    for (seen) |present| if (!present) return error.MissingEthereumInitialRoleHeader;
}

fn fillBase(comptime Air: type, rows: []const Air.Row, manifest: *const air.ethereum_initial_input_manifest_v1.Manifest, component: u8, tree: usize, destination: []const []M31) !void {
    const placement = manifest.placements[component] orelse return error.InvalidEthereumInitialInputRows;
    const width: usize = switch (tree) {
        0 => Air.PREPROCESSED_COLUMN_COUNT,
        1 => Air.PHYSICAL_MAIN_COLUMN_COUNT,
        else => return error.InvalidTreeIndex,
    };
    const offset: usize = if (tree == 0) placement.preprocessed_offset else placement.main_offset;
    const source: usize = if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
    if (offset + width > destination.len) return error.DestinationColumnCountMismatch;
    for (destination[offset..][0..width]) |column| if (column.len != rows.len) return error.DestinationLogSizeMismatch;
    for (rows, 0..) |row, index| for (0..width) |column| {
        destination[offset + column][index] = row[source + column];
    };
}
fn fillInteraction(comptime Air: type, allocator: std.mem.Allocator, plan: *const Air.Relation.Plan, rows: []const Air.Row, manifest: *const air.ethereum_initial_input_manifest_v1.Manifest, component: u8, relations: *const air.universal_challenges.UniversalRelations, destination: []const []M31) !QM31 {
    const placement = manifest.placements[component] orelse return error.InvalidEthereumInitialInputRows;
    const offset: usize = placement.interaction_offset;
    if (offset + Air.INTERACTION_COLUMN_COUNT > destination.len) return error.DestinationColumnCountMismatch;
    var columns = destination[offset..][0..Air.INTERACTION_COLUMN_COUNT].*;
    const Framework = air.framework_interaction.Runtime(Air.Relation.Runtime);
    var workspace = try Framework.Workspace.init(allocator, placement.geometry.log_size);
    defer workspace.deinit();
    return Framework.generatePreparedInto(&workspace, plan, rows, placement.geometry.log_size, relations, &columns);
}

test "Ethereum initial complete writers commit genuine lane and packet rows at appended offsets" {
    const allocator = std.testing.allocator;
    const fixture = try @import("recursive_common_ethereum_initial_input_lane_v1_test.zig").Fixture.init();
    var graph = try @import("recursive_common_ethereum_initial_input_packet_v1_test.zig").TestGraph.init(&fixture);
    defer graph.circuit.deinit();
    const ordinary_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
    var logs: ordinary_mod.LogSizesV4 = @splat(4);
    logs[34] = ordinary_mod.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = ordinary_mod.RANGE_LOG_SIZE;
    const ordinary = try ordinary_mod.buildForDerivedLogSizes(logs);
    const manifest = try air.ethereum_initial_input_manifest_v1.build(&ordinary, 40);
    const packet_rows = graph.rows();
    const relations = air.universal_challenges.UniversalRelations.dummy();
    inline for (.{ Lane, Packet }, .{ LANE_COMPONENT, PACKET_COMPONENT }) |Air, component| {
        const source: []const Air.Row = if (Air == Lane) &fixture.rows else &packet_rows;
        var definition = try Air.build(allocator);
        defer definition.deinit();
        const plan = try Air.Relation.authenticate(&definition);
        inline for (0..3) |tree| {
            const placement = manifest.placements[component].?;
            const offset: usize = switch (tree) {
                0 => placement.preprocessed_offset,
                1 => placement.main_offset,
                2 => placement.interaction_offset,
                else => unreachable,
            };
            const width = switch (tree) {
                0 => Air.PREPROCESSED_COLUMN_COUNT,
                1 => Air.PHYSICAL_MAIN_COLUMN_COUNT,
                2 => Air.INTERACTION_COLUMN_COUNT,
                else => unreachable,
            };
            const columns = try allocator.alloc([]M31, offset + width);
            defer allocator.free(columns);
            const storage = try allocator.alloc(M31, width * source.len);
            defer allocator.free(storage);
            @memset(storage, M31.zero());
            @memset(columns, &.{});
            for (columns[offset..], 0..) |*column, index| column.* = storage[index * source.len ..][0..source.len];
            if (tree == 2) {
                const claim = try fillInteraction(Air, allocator, &plan, source, &manifest, component, &relations, columns);
                _ = try plan.auditPreparedDomainSums(allocator, source, &relations, claim);
            } else {
                try fillBase(Air, source, &manifest, component, tree, columns);
                for (source, 0..) |row, index| for (0..width) |column| try std.testing.expect(row[(if (tree == 0) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0) + column].eql(columns[offset + column][index]));
                try std.testing.expectError(error.DestinationColumnCountMismatch, fillBase(Air, source, &manifest, component, tree, columns[0 .. columns.len - 1]));
            }
        }
    }
}
