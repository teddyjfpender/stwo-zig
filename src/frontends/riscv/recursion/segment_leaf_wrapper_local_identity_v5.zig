//! Three proof-visible local identity components for a future direct leaf roster.
//!
//! This is a V5 roster extension, not a wrapper proof. It binds the exact
//! S2WR/S2CX source uses and LAI1/LWI1/LRI1 sink multiplicities before any
//! component can be placed in a proof. The existing V4 roster stays frozen.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const router_air = @import("air/ethereum_leaf_child_field_router_v1.zig");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_relation = @import("air/vm_public_claim_hash_relation.zig");
const hash_witness = @import("air/vm_public_claim_hash_witness.zig");
const program_mod = @import("ethereum_leaf_child_field_program_v1.zig");
const witness_mod = @import("ethereum_leaf_child_field_witness_v1.zig");
const leaf_source = @import("air/ethereum_leaf_link_source_v1.zig");
const leaf_v2 = @import("segment_leaf_authority_v2.zig");
const merkle_root = @import("air/merkle_root_witness.zig");
const universal = @import("air/universal_challenges.zig");
const relation_interaction = @import("air/relation_interaction.zig");
const framework = @import("air/framework_interaction.zig");
const relation = @import("../air/lang/relation.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW_COUNT: usize = 3;
pub const REMOVED_TREE0_FORWARD_ROWS: usize = 8;
pub const SCHEDULE_DOMAIN = "stwo-zig/riscv-leaf-local-identity/v5-direct\x00";
pub const FIXTURE_SCHEDULE_ID_HEX = "b82f7555963906fbd76232bb0b015b7b6e743b0259fb19af3730d0534d008f52";
pub const Component = enum(u2) { router, authority_hash, receipt_hash };
pub const DomainAudit = relation_interaction.DomainAudit;
pub const Call = hash_witness.PoseidonCall;

pub const Placement = struct {
    log_size: u32,
    preprocessed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
};

pub const Layout = struct {
    placements: [ROW_COUNT]Placement,
    preprocessed_columns: usize,
    main_columns: usize,
    interaction_columns: usize,

    pub fn init(program: *const program_mod.ProgramV1) !Layout {
        const logs = [_]u32{
            program.router_log_size,
            program.authority_hash.log_size,
            program.receipt_hash.log_size,
        };
        const pp = [_]usize{
            router_air.PREPROCESSED_COLUMN_COUNT,
            hash_air.PREPROCESSED_COLUMN_COUNT,
            hash_air.PREPROCESSED_COLUMN_COUNT,
        };
        const main = [_]usize{
            router_air.PHYSICAL_MAIN_COLUMN_COUNT,
            hash_air.PHYSICAL_MAIN_COLUMN_COUNT,
            hash_air.PHYSICAL_MAIN_COLUMN_COUNT,
        };
        const interaction = [_]usize{
            router_air.INTERACTION_COLUMN_COUNT,
            hash_air.INTERACTION_COLUMN_COUNT,
            hash_air.INTERACTION_COLUMN_COUNT,
        };
        var result = Layout{
            .placements = undefined,
            .preprocessed_columns = 0,
            .main_columns = 0,
            .interaction_columns = 0,
        };
        for (&result.placements, logs, pp, main, interaction) |*item, log, p, m, i| {
            item.* = .{
                .log_size = log,
                .preprocessed_offset = result.preprocessed_columns,
                .main_offset = result.main_columns,
                .interaction_offset = result.interaction_columns,
            };
            result.preprocessed_columns = try std.math.add(usize, result.preprocessed_columns, p);
            result.main_columns = try std.math.add(usize, result.main_columns, m);
            result.interaction_columns = try std.math.add(usize, result.interaction_columns, i);
        }
        return result;
    }
};

pub const SourceUse = struct { scope: u32, index: u32, count: u32 };

/// The row-36 S2WR/S2CX source must emit one additional copy of each tuple
/// consumed here. A tuple already consumed by V4 keeps its old use as well.
pub fn sourceUses(allocator: std.mem.Allocator, program: *const program_mod.ProgramV1) ![]SourceUse {
    const uses = try allocator.alloc(SourceUse, program.router_rows.len);
    errdefer allocator.free(uses);
    var len: usize = 0;
    for (program.router_rows) |row| {
        if (row.statement_source_mask == 0) continue;
        if (row.statement_source_mask != 1 or
            (row.statement_scope != leaf_v2.WIRE_SCOPE and row.statement_scope != leaf_v2.CONTEXT_SCOPE))
            return error.InvalidLocalIdentitySource;
        var found = false;
        for (uses[0..len]) |*item| {
            if (item.scope == row.statement_scope and item.index == row.statement_index) {
                item.count = try std.math.add(u32, item.count, 1);
                found = true;
                break;
            }
        }
        if (!found) {
            uses[len] = .{ .scope = row.statement_scope, .index = row.statement_index, .count = 1 };
            len += 1;
        }
    }
    return allocator.realloc(uses, len);
}

/// Verifies the *schedule* of the 24 digest tuples consumed by direct row40.
/// The row writers below make the tuple values proof-visible; the full V5
/// cohort must still close these against row40 and the native statement rows.
pub fn validateSinkSchedule(program: *const program_mod.ProgramV1) !void {
    var seen: [3][8]bool = @splat(@splat(false));
    for (program.router_rows) |row| {
        if (row.verifier_sink_mask == 0) continue;
        const group: usize = switch (row.sink_verifier_kind) {
            leaf_source.LOCAL_AUTHORITY_DIGEST_KIND => 0,
            leaf_source.LOCAL_WIRE_DIGEST_KIND => 1,
            leaf_source.LOCAL_RECEIPT_DIGEST_KIND => 2,
            else => continue,
        };
        if (row.sink_index_0 != 0 or row.sink_index_1 >= 8 or
            seen[group][row.sink_index_1] or
            row.sink_use_count != (if (group == 1) @as(u32, 1) else 2))
            return error.InvalidLocalIdentitySink;
        seen[group][row.sink_index_1] = true;
    }
    for (seen) |group| for (group) |present| {
        if (!present) return error.InvalidLocalIdentitySink;
    };
}

/// The old diagnostic router forwarded Tree0 to PPR1. Direct V4 already does
/// this through row39/44. V5 removes those exact eight active rows so it
/// cannot create an extra unbound PPR1 producer.
pub fn validateDirectSchedule(program: *const program_mod.ProgramV1) !void {
    try validateSinkSchedule(program);
    if (program.router_rows.len < REMOVED_TREE0_FORWARD_ROWS)
        return error.InvalidLocalIdentityRouter;
    const trailing = program.router_rows[program.router_rows.len - REMOVED_TREE0_FORWARD_ROWS ..];
    for (trailing, 0..) |row, limb| {
        if (row.statement_source_mask != 0 or row.verifier_source_mask != 1 or
            row.raw_a_sink_mask != 0 or row.raw_b_sink_mask != 0 or
            row.verifier_sink_mask != 1 or row.source_verifier_kind != merkle_root.COMMITMENT_INPUT_KIND or
            row.source_index_0 != 0 or row.source_index_1 != limb or
            row.sink_verifier_kind != leaf_source.PREPROCESSED_ROOT_KIND or
            row.sink_index_0 != 0 or row.sink_index_1 != limb or row.sink_use_count != 1)
            return error.InvalidLocalIdentityRouter;
    }
}

pub fn directScheduleId(program: *const program_mod.ProgramV1) ![32]u8 {
    try validateDirectSchedule(program);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SCHEDULE_DOMAIN);
    hash.update(&router_air.SEMANTIC_DIGEST);
    hash.update(&hash_air.SEMANTIC_DIGEST);
    for (program.router_rows[0 .. program.router_rows.len - REMOVED_TREE0_FORWARD_ROWS]) |row|
        for (row.preprocessed()) |word| hashWord(&hash, word);
    for (program.authority_hash.rows) |row|
        for (row.values()) |value| hashWord(&hash, value.toU32());
    for (program.receipt_hash.rows) |row|
        for (row.values()) |value| hashWord(&hash, value.toU32());
    return hash.finalResult();
}

fn hashWord(hash: *std.crypto.hash.sha2.Sha256, word: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    hash.update(&bytes);
}

fn requireNoPpr1RouterEmitter(rows: []const router_air.Row) !void {
    for (rows) |row| {
        // AIR logical row = one main value followed by the 22 preprocessed
        // values in RouterScheduleRowV1.preprocessed() order.
        if (row[1 + 7].toU32() == 1 and
            row[1 + 18].toU32() == leaf_source.PREPROCESSED_ROOT_KIND)
            return error.DuplicateDirectTree0Emitter;
    }
}

pub const Claims = struct {
    values: [ROW_COUNT]QM31,
    audits: [ROW_COUNT]DomainAudit,
};

const PhysicalTree = enum { main, preprocessed };

/// Append these two ranges after the direct V4 base/metadata/link/program
/// calls. The final V5 row34 must prove the complete ordered buffer.
pub const CallRanges = struct {
    authority: []const Call,
    receipt: []const Call,

    pub fn fromWitness(program: *const program_mod.ProgramV1, witness: *const witness_mod.WitnessV1) !CallRanges {
        const result = CallRanges{
            .authority = witness.authority_hash.poseidon_calls,
            .receipt = witness.receipt_hash.poseidon_calls,
        };
        try result.validateExact(program, witness);
        return result;
    }

    pub fn validateExact(self: CallRanges, program: *const program_mod.ProgramV1, witness: *const witness_mod.WitnessV1) !void {
        if (self.authority.len != program.authority_hash.rows.len or
            self.receipt.len != program.receipt_hash.rows.len or
            witness.authority_hash.main_rows.len != self.authority.len or
            witness.receipt_hash.main_rows.len != self.receipt.len)
            return error.InvalidLocalIdentityCallRanges;
        for (self.authority, witness.authority_hash.main_rows) |call, row|
            if (!std.meta.eql(call, hash_witness.callFor(row))) return error.InvalidLocalIdentityCallRanges;
        for (self.receipt, witness.receipt_hash.main_rows) |call, row|
            if (!std.meta.eql(call, hash_witness.callFor(row))) return error.InvalidLocalIdentityCallRanges;
    }

    pub fn copyAfter(self: CallRanges, prefix: []const Call, destination: []Call) !void {
        const after_authority = try std.math.add(usize, prefix.len, self.authority.len);
        if (destination.len != try std.math.add(usize, after_authority, self.receipt.len))
            return error.InvalidLocalIdentityCallRanges;
        @memcpy(destination[0..prefix.len], prefix);
        @memcpy(destination[prefix.len..after_authority], self.authority);
        @memcpy(destination[after_authority..], self.receipt);
    }
};

pub const Rows = struct {
    allocator: std.mem.Allocator,
    layout: Layout,
    program: *const program_mod.ProgramV1,
    witness: *const witness_mod.WitnessV1,
    schedule_id: [32]u8,

    pub fn init(allocator: std.mem.Allocator, program: *const program_mod.ProgramV1, witness: *const witness_mod.WitnessV1, inputs: witness_mod.InputsV1) !Rows {
        try program.validateAgainst(inputs.component_descs, inputs.infra_descs);
        try validateDirectSchedule(program);
        try witness.validateAgainst(program, inputs);
        return .{ .allocator = allocator, .layout = try Layout.init(program), .program = program, .witness = witness, .schedule_id = try directScheduleId(program) };
    }

    pub fn writePreprocessed(self: *const Rows, columns: [][]M31) !void {
        try self.writePhysical(columns, .preprocessed);
    }

    pub fn writeMain(self: *const Rows, columns: [][]M31) !void {
        try self.writePhysical(columns, .main);
    }

    pub fn writeInteraction(self: *const Rows, relations: *const universal.UniversalRelations, columns: [][]M31) !Claims {
        try relations.validate();
        var router_definition = try router_air.build(self.allocator);
        defer router_definition.deinit();
        const router_plan = try router_air.authenticate(&router_definition);
        const router_rows = try self.routerRows();
        defer self.allocator.free(router_rows);
        try requireNoPpr1RouterEmitter(router_rows);
        var router_generated = try router_plan.generateInteraction(self.allocator, &router_definition.arena, router_air.SEMANTIC_DIGEST, router_definition.events, router_rows, self.layout.placements[0].log_size, relations);
        defer router_generated.deinit(self.allocator);
        var result: Claims = undefined;
        result.values[0] = router_generated.claims.total();
        result.audits[0] = try router_plan.auditPreparedDomainSums(self.allocator, router_rows, relations, result.values[0]);
        try writeGenerated(self.layout, .router, &router_generated, columns);

        var hash_definition = try hash_air.build(self.allocator);
        defer hash_definition.deinit();
        const hash_plan = try hash_relation.authenticate(&hash_definition);
        inline for ([_]Component{ .authority_hash, .receipt_hash }) |kind| {
            const index = @intFromEnum(kind);
            const rows = try self.hashRows(kind);
            defer self.allocator.free(rows);
            var generated = try hash_plan.generateInteraction(self.allocator, &hash_definition.arena, hash_air.SEMANTIC_DIGEST, hash_definition.events, rows, self.layout.placements[index].log_size, relations);
            defer generated.deinit(self.allocator);
            result.values[index] = generated.claims.total();
            result.audits[index] = try hash_plan.auditPreparedDomainSums(self.allocator, rows, relations, result.values[index]);
            try writeGenerated(self.layout, kind, &generated, columns);
        }
        return result;
    }

    fn writePhysical(self: *const Rows, columns: [][]M31, comptime tree: PhysicalTree) !void {
        const count = if (tree == .main) self.layout.main_columns else self.layout.preprocessed_columns;
        if (columns.len != count) return error.LocalIdentityTreeGeometryMismatch;
        const router_rows = try self.routerRows();
        defer self.allocator.free(router_rows);
        try requireNoPpr1RouterEmitter(router_rows);
        try writeRows(router_air, self.layout.placements[0], router_rows, columns, tree);
        inline for ([_]Component{ .authority_hash, .receipt_hash }) |kind| {
            const rows = try self.hashRows(kind);
            defer self.allocator.free(rows);
            try writeRows(hash_air, self.layout.placements[@intFromEnum(kind)], rows, columns, tree);
        }
    }

    fn routerRows(self: *const Rows) ![]router_air.Row {
        const size = @as(usize, 1) << @intCast(self.layout.placements[0].log_size);
        const rows = try self.allocator.alloc(router_air.Row, size);
        @memset(rows, [_]M31{M31.zero()} ** router_air.LOGICAL_INPUT_COUNT);
        const active = self.witness.router_rows.len - REMOVED_TREE0_FORWARD_ROWS;
        @memcpy(rows[0..active], self.witness.router_rows[0..active]);
        return rows;
    }

    fn hashRows(self: *const Rows, kind: Component) ![]hash_relation.Row {
        const index = @intFromEnum(kind);
        const size = @as(usize, 1) << @intCast(self.layout.placements[index].log_size);
        const rows = try self.allocator.alloc(hash_relation.Row, size);
        errdefer self.allocator.free(rows);
        @memset(rows, [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT);
        const active = if (kind == .authority_hash) self.witness.authority_hash.main_rows.len else self.witness.receipt_hash.main_rows.len;
        for (rows[0..active], 0..) |*row, at|
            row.* = if (kind == .authority_hash) try self.witness.authorityHashLogicalRow(self.program, at) else try self.witness.receiptHashLogicalRow(self.program, at);
        return rows;
    }
};

fn writeRows(comptime Air: type, placement: Placement, rows: anytype, destination: [][]M31, comptime tree: PhysicalTree) !void {
    const begin: usize = if (tree == .main) 0 else Air.PHYSICAL_MAIN_COLUMN_COUNT;
    const count: usize = if (tree == .main) Air.PHYSICAL_MAIN_COLUMN_COUNT else Air.PREPROCESSED_COLUMN_COUNT;
    const offset = if (tree == .main) placement.main_offset else placement.preprocessed_offset;
    if (rows.len != @as(usize, 1) << @intCast(placement.log_size) or offset > destination.len or count > destination.len - offset)
        return error.LocalIdentityTreeGeometryMismatch;
    for (destination[offset..][0..count]) |column| {
        if (column.len != rows.len) return error.LocalIdentityTreeGeometryMismatch;
        for (column) |value| if (!value.isZero()) return error.LocalIdentityTreeNotFresh;
    }
    for (rows, 0..) |row, logical| {
        const committed = framework.committedRow(logical, placement.log_size);
        for (row[begin..][0..count], 0..) |value, column|
            destination[offset + column][committed] = value;
    }
}

fn writeGenerated(layout: Layout, kind: Component, generated: anytype, destination: [][]M31) !void {
    const placement = layout.placements[@intFromEnum(kind)];
    const count: usize = switch (kind) {
        .router => router_air.INTERACTION_COLUMN_COUNT,
        .authority_hash, .receipt_hash => hash_air.INTERACTION_COLUMN_COUNT,
    };
    if (destination.len != layout.interaction_columns or generated.columns.len != count or
        placement.interaction_offset > destination.len or count > destination.len - placement.interaction_offset)
        return error.LocalIdentityTreeGeometryMismatch;
    const size = @as(usize, 1) << @intCast(placement.log_size);
    for (generated.columns, destination[placement.interaction_offset..][0..count]) |source, target| {
        if (source.len != size or target.len != size) return error.LocalIdentityTreeGeometryMismatch;
        for (target) |value| if (!value.isZero()) return error.LocalIdentityTreeNotFresh;
    }
    for (generated.columns, destination[placement.interaction_offset..][0..count]) |source, target|
        @memcpy(target, source);
}

test "V5 local identity schedule pins all 24 verifier tuples and source uses" {
    const fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    var program = try program_mod.ProgramV1.init(std.testing.allocator, &fixture.components, &fixture.infra);
    defer program.deinit();
    try validateSinkSchedule(&program);
    try validateDirectSchedule(&program);
    const schedule_id = try directScheduleId(&program);
    try std.testing.expectEqualStrings(FIXTURE_SCHEDULE_ID_HEX, &std.fmt.bytesToHex(schedule_id, .lower));
    const uses = try sourceUses(std.testing.allocator, &program);
    defer std.testing.allocator.free(uses);
    try std.testing.expectEqual(@as(usize, 56), uses.len);
    for (uses) |item| try std.testing.expectEqual(@as(u32, 1), item.count);
    try std.testing.expectEqual(@as(u32, 1), program.router_rows[program.router_rows.len - 1].verifier_sink_mask);
    const layout = try Layout.init(&program);
    try std.testing.expectEqual(@as(u32, 7), layout.placements[0].log_size);
    try std.testing.expectEqual(@as(u32, 4), layout.placements[1].log_size);
    try std.testing.expectEqual(@as(u32, 4), layout.placements[2].log_size);
    for (program.router_rows) |*row| {
        if (row.sink_verifier_kind == leaf_source.LOCAL_AUTHORITY_DIGEST_KIND) {
            row.sink_use_count = 1;
            break;
        }
    }
    try std.testing.expectError(error.InvalidLocalIdentitySink, validateSinkSchedule(&program));
}

test "V5 local identity rows write three typed components with exact claims" {
    const fixture_mod = @import("tests/ethereum_leaf_child_field_test.zig");
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init(allocator);
    defer fixture.deinit();
    var program = try program_mod.ProgramV1.init(allocator, &fixture_mod.components, &fixture_mod.infra);
    defer program.deinit();
    const inputs = fixture.input();
    var witness = try witness_mod.WitnessV1.init(allocator, &program, inputs);
    defer witness.deinit();
    const ranges = try CallRanges.fromWitness(&program, &witness);
    const prefix = [_]Call{.{ .input = @splat(17), .io = true }};
    const calls = try allocator.alloc(Call, prefix.len + ranges.authority.len + ranges.receipt.len);
    defer allocator.free(calls);
    try ranges.copyAfter(&prefix, calls);
    try std.testing.expectEqualDeep(prefix[0], calls[0]);
    try std.testing.expectEqualDeep(ranges.authority[0], calls[1]);
    try std.testing.expectEqualDeep(ranges.receipt[0], calls[1 + ranges.authority.len]);
    try std.testing.expectError(error.InvalidLocalIdentityCallRanges, ranges.copyAfter(&prefix, calls[0 .. calls.len - 1]));
    calls[1].input[0] +%= 1;
    const changed = CallRanges{ .authority = calls[1..][0..ranges.authority.len], .receipt = calls[1 + ranges.authority.len ..] };
    try std.testing.expectError(error.InvalidLocalIdentityCallRanges, changed.validateExact(&program, &witness));
    const rows = try Rows.init(allocator, &program, &witness, inputs);
    const pruned = try rows.routerRows();
    defer allocator.free(pruned);
    try requireNoPpr1RouterEmitter(pruned);
    pruned[witness.router_rows.len - REMOVED_TREE0_FORWARD_ROWS] = witness.router_rows[witness.router_rows.len - REMOVED_TREE0_FORWARD_ROWS];
    try std.testing.expectError(error.DuplicateDirectTree0Emitter, requireNoPpr1RouterEmitter(pruned));
    const pp = try allocateTree(allocator, rows.layout, .preprocessed);
    defer freeTree(allocator, pp);
    const main = try allocateTree(allocator, rows.layout, .main);
    defer freeTree(allocator, main);
    const interaction = try allocateTree(allocator, rows.layout, .interaction);
    defer freeTree(allocator, interaction);
    try rows.writePreprocessed(pp);
    try rows.writeMain(main);
    const relations = universal.UniversalRelations.dummy();
    const claims = try rows.writeInteraction(&relations, interaction);
    for (claims.values, claims.audits) |claim, audit|
        try std.testing.expect(claim.eql(audit.total));
    try std.testing.expectError(error.LocalIdentityTreeNotFresh, rows.writeMain(main));
}

test "V5 keeps the existing row39 PPR1 lookup exactly closed without router forwarding" {
    var ledger = relation_interaction.TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    const tuple = [_]QM31{
        QM31.zero(),
        QM31.fromBase(M31.fromCanonical(leaf_source.PREPROCESSED_ROOT_KIND)),
        QM31.zero(),
        QM31.zero(),
        QM31.fromBase(M31.fromCanonical(17)),
    };
    // The direct row39 source emits twice: row40 projection and row44 Tree0
    // bridge each consume once. A retained V1 router row adds a third emitter.
    try ledger.append(.recursion_verifier_input_word, 39, 0, .emit, QM31.fromBase(M31.fromCanonical(2)), &tuple);
    try ledger.append(.recursion_verifier_input_word, 40, 0, .consume, QM31.one().neg(), &tuple);
    try ledger.append(.recursion_verifier_input_word, 44, 0, .consume, QM31.one().neg(), &tuple);
    try std.testing.expect(ledger.classify().isClosed());
    try ledger.append(.recursion_verifier_input_word, 47, 0, .emit, QM31.one(), &tuple);
    try std.testing.expectEqual(@as(usize, 1), ledger.classify().unmatched_by_domain[@intFromEnum(relation.Domain.recursion_verifier_input_word)]);
}

test "V5 router and two hashes close all 24 direct row40 local IDs" {
    const fixture_mod = @import("tests/ethereum_leaf_child_field_test.zig");
    const projection_air = @import("air/ethereum_leaf_link_projection_v1.zig");
    const direct_program = @import("ethereum_leaf_link_program_v3.zig");
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init(allocator);
    defer fixture.deinit();
    var program = try program_mod.ProgramV1.init(allocator, &fixture_mod.components, &fixture_mod.infra);
    defer program.deinit();
    var witness = try witness_mod.WitnessV1.init(allocator, &program, fixture.input());
    defer witness.deinit();
    const rows = try Rows.init(allocator, &program, &witness, fixture.input());
    var direct = try direct_program.ProgramV3.init(allocator);
    defer direct.deinit();

    var router_definition = try router_air.build(allocator);
    defer router_definition.deinit();
    const router_plan = try router_air.authenticate(&router_definition);
    var hash_definition = try hash_air.build(allocator);
    defer hash_definition.deinit();
    const hash_plan = try hash_relation.authenticate(&hash_definition);
    var projection_definition = try projection_air.build(allocator);
    defer projection_definition.deinit();
    const projection_plan = try projection_air.authenticate(&projection_definition);
    const router_rows = try rows.routerRows();
    defer allocator.free(router_rows);
    const authority_rows = try rows.hashRows(.authority_hash);
    defer allocator.free(authority_rows);
    const receipt_rows = try rows.hashRows(.receipt_hash);
    defer allocator.free(receipt_rows);
    const mask = @as(u64, 1) << @intFromEnum(relation.Domain.recursion_verifier_input_word);
    var ledger = relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try router_plan.appendPreparedTupleContributions(&ledger, 47, router_rows, mask);
    try hash_plan.appendPreparedTupleContributions(&ledger, 48, authority_rows, mask);
    try hash_plan.appendPreparedTupleContributions(&ledger, 49, receipt_rows, mask);
    var row40_count: usize = 0;
    var first: ?projection_air.Row = null;
    for (direct.projection_rows) |schedule| {
        const digest: [8]u32 = switch (schedule.verifier_kind) {
            leaf_source.LOCAL_AUTHORITY_DIGEST_KIND => witness.local_authority_digest,
            leaf_source.LOCAL_WIRE_DIGEST_KIND => witness.local_wire_digest,
            leaf_source.LOCAL_RECEIPT_DIGEST_KIND => witness.local_receipt_digest,
            else => continue,
        };
        if (schedule.verifier_mask != 1 or schedule.verifier_index_0 != 0 or schedule.verifier_index_1 >= 8)
            return error.InvalidLocalIdentityProjection;
        const logical = schedule.logical(M31.fromCanonical(digest[schedule.verifier_index_1]));
        if (first == null) first = logical;
        try projection_plan.appendPreparedTupleContributions(&ledger, 40, &.{logical}, mask);
        row40_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 24), row40_count);
    try std.testing.expect(ledger.classify().isClosed());

    var changed = first.?;
    changed[0] = changed[0].add(M31.one());
    try projection_plan.appendPreparedTupleContributions(&ledger, 40, &.{changed}, mask);
    try std.testing.expectEqual(@as(usize, 1), ledger.classify().unmatched_by_domain[@intFromEnum(relation.Domain.recursion_verifier_input_word)]);
}

const Tree = enum { preprocessed, main, interaction };

fn allocateTree(allocator: std.mem.Allocator, layout: Layout, comptime tree: Tree) ![][]M31 {
    const count = switch (tree) {
        .preprocessed => layout.preprocessed_columns,
        .main => layout.main_columns,
        .interaction => layout.interaction_columns,
    };
    const result = try allocator.alloc([]M31, count);
    errdefer allocator.free(result);
    var filled: usize = 0;
    errdefer for (result[0..filled]) |column| allocator.free(column);
    for (layout.placements, 0..) |placement, row| {
        const n: usize = switch (tree) {
            .preprocessed => if (row == 0) router_air.PREPROCESSED_COLUMN_COUNT else hash_air.PREPROCESSED_COLUMN_COUNT,
            .main => if (row == 0) router_air.PHYSICAL_MAIN_COLUMN_COUNT else hash_air.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction => if (row == 0) router_air.INTERACTION_COLUMN_COUNT else hash_air.INTERACTION_COLUMN_COUNT,
        };
        const size = @as(usize, 1) << @intCast(placement.log_size);
        for (0..n) |_| {
            result[filled] = try allocator.alloc(M31, size);
            @memset(result[filled], M31.zero());
            filled += 1;
        }
    }
    return result;
}

fn freeTree(allocator: std.mem.Allocator, columns: [][]M31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}
