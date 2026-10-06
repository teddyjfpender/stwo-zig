//! Physical V5 replacements and appended rows under one relation draw.
//! The native V2 owner remains responsible for rows 0–38 except the
//! versioned Statement source; this module never creates a wrapper proof.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const plan_mod = @import("air/segment_leaf_wrapper_roster_direct_v5.zig");
const base_rows_mod = @import("segment_leaf_wrapper_cohort_direct_rows_v4.zig");
const local_mod = @import("segment_leaf_wrapper_local_identity_v5.zig");
const statement_air = @import("air/segment_leaf_statement_source_direct_v5.zig");
const program_air = @import("air/transcript_program_v2_field_bridge_v5.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");
const projection_air = @import("air/ethereum_leaf_link_projection_v1.zig");
const arithmetic_air = @import("air/ethereum_leaf_link_arithmetic_v1.zig");
const tree0_air = @import("air/segment_v2_tree0_field_link_direct_v4.zig");
const hash_air = @import("air/vm_public_claim_hash.zig");
const hash_relation = @import("air/vm_public_claim_hash_relation.zig");
const hash_witness = @import("segment_leaf_wrapper_field_hash_witness_v3.zig");
const framework = @import("air/framework_interaction.zig");
const universal = @import("air/universal_challenges.zig");
const DomainAudit = @import("air/relation_interaction.zig").DomainAudit;

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const ROW_MASK: u64 = (@as(u64, 1) << 36) |
    (((@as(u64, 1) << 11) - 1) << 39);

pub const Claims = struct {
    claims: [plan_mod.COMPONENT_COUNT]QM31,
    audits: [plan_mod.COMPONENT_COUNT]DomainAudit,
    present_mask: u64,

    pub fn empty() Claims {
        return .{
            .claims = @splat(QM31.zero()),
            .audits = @splat(emptyAudit()),
            .present_mask = 0,
        };
    }

    fn set(self: *Claims, row: usize, value: ClaimAudit) !void {
        if (row >= plan_mod.COMPONENT_COUNT or self.present_mask & (@as(u64, 1) << @intCast(row)) != 0)
            return error.DuplicateDirectV5Claim;
        self.claims[row] = value.claim;
        self.audits[row] = value.audit;
        self.present_mask |= @as(u64, 1) << @intCast(row);
    }
};

pub const Rows = struct {
    allocator: std.mem.Allocator,
    base: *const base_rows_mod.Rows,
    statement: *const statement_air.Schedule,
    local: *const local_mod.Rows,
    program: []program_air.Row,

    pub fn init(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        base: *const base_rows_mod.Rows,
        statement: *const statement_air.Schedule,
        local: *const local_mod.Rows,
    ) !Rows {
        try plan.validate();
        if (base.native.program.words.len != plan.base_plan.shape.program_words or
            statement.rows.len > traceSize(plan, 36) or
            !std.meta.eql(local.schedule_id, plan.local_schedule_id))
            return error.InvalidDirectV5Rows;
        const local_layout = local.layout;
        for (local_layout.placements, 47..) |placement, row| {
            const item = plan.placements[row].?;
            if (item.geometry.log_size != placement.log_size or
                item.preprocessed_offset != plan.placements[47].?.preprocessed_offset + placement.preprocessed_offset or
                item.main_offset != plan.placements[47].?.main_offset + placement.main_offset or
                item.interaction_offset != plan.placements[47].?.interaction_offset + placement.interaction_offset)
                return error.InvalidDirectV5Rows;
        }
        const fixed = try program_air.FixedSchedule.init(base.native.program.words.len);
        if (fixed.log_size != plan.placements[42].?.geometry.log_size)
            return error.InvalidDirectV5Rows;
        const program = try allocator.alloc(program_air.Row, fixed.rowCapacity());
        errdefer allocator.free(program);
        for (program, 0..) |*row, index| {
            const value = if (index < base.native.program.words.len)
                base.native.program.words[index]
            else
                M31.zero();
            if (program_air.fixedValue(@intCast(index))) |expected| {
                if (value.toU32() != expected) return error.InvalidDirectV5ProgramFixedWord;
            }
            row.* = try fixed.logicalRow(index, value);
        }
        return .{ .allocator = allocator, .base = base, .statement = statement, .local = local, .program = program };
    }

    pub fn deinit(self: *Rows) void {
        self.allocator.free(self.program);
        self.* = undefined;
    }

    pub fn fillPreprocessed(self: *const Rows, plan: *const plan_mod.Plan, tree: [][]M31) !void {
        try self.fillPhysical(plan, tree, .preprocessed);
    }

    pub fn fillMain(self: *const Rows, plan: *const plan_mod.Plan, tree: [][]M31) !void {
        try self.fillPhysical(plan, tree, .main);
    }

    fn fillPhysical(self: *const Rows, plan: *const plan_mod.Plan, tree: [][]M31, comptime kind: Tree) !void {
        try plan.validate();
        if (kind == .preprocessed)
            try writeTyped(statement_air, plan, 36, self.statement.rows, tree, kind);
        // Row36 main is the exact V2 main value already mapped into V5.
        try writeTyped(source_air, plan, 39, self.base.source, tree, kind);
        try writeTyped(projection_air, plan, 40, self.base.projection, tree, kind);
        try writeTyped(arithmetic_air, plan, 41, self.base.arithmetic, tree, kind);
        try writeTyped(program_air, plan, 42, self.program, tree, kind);
        try writeHash(plan, 43, &self.base.native.program_hash, tree, kind);
        try writeTyped(tree0_air, plan, 44, &self.base.native.tree0_link.rows, tree, kind);
        try writeHash(plan, 45, self.base.metadata_hash, tree, kind);
        try writeHash(plan, 46, self.base.link_hash, tree, kind);
        const tail = try localTail(plan, tree, kind);
        if (kind == .preprocessed) try self.local.writePreprocessed(tail) else try self.local.writeMain(tail);
    }

    pub fn fillInteraction(
        self: *const Rows,
        plan: *const plan_mod.Plan,
        relations: *const universal.UniversalRelations,
        tree: [][]M31,
    ) !Claims {
        try plan.validate();
        try relations.validate();
        var result = Claims.empty();
        try result.set(36, try interactTyped(statement_air, self.allocator, plan, 36, self.statement.rows, relations, tree));
        try result.set(39, try interactTyped(source_air, self.allocator, plan, 39, self.base.source, relations, tree));
        try result.set(40, try interactTyped(projection_air, self.allocator, plan, 40, self.base.projection, relations, tree));
        try result.set(41, try interactTyped(arithmetic_air, self.allocator, plan, 41, self.base.arithmetic, relations, tree));
        try result.set(42, try interactTyped(program_air, self.allocator, plan, 42, self.program, relations, tree));
        try result.set(43, try interactHash(self.allocator, plan, 43, &self.base.native.program_hash, relations, tree));
        try result.set(44, try interactTyped(tree0_air, self.allocator, plan, 44, &self.base.native.tree0_link.rows, relations, tree));
        try result.set(45, try interactHash(self.allocator, plan, 45, self.base.metadata_hash, relations, tree));
        try result.set(46, try interactHash(self.allocator, plan, 46, self.base.link_hash, relations, tree));
        const local_claims = try self.local.writeInteraction(relations, try localTail(plan, tree, .interaction));
        for (local_claims.values, local_claims.audits, 47..) |claim, audit, row|
            try result.set(row, .{ .claim = claim, .audit = audit });
        if (result.present_mask != ROW_MASK) return error.IncompleteDirectV5Rows;
        return result;
    }
};

const Tree = enum { preprocessed, main, interaction };
const ClaimAudit = struct { claim: QM31, audit: DomainAudit };

fn traceSize(plan: *const plan_mod.Plan, row: usize) usize {
    return @as(usize, 1) << @intCast(plan.placements[row].?.geometry.log_size);
}

fn localTail(plan: *const plan_mod.Plan, tree: [][]M31, comptime kind: Tree) ![][]M31 {
    const start: usize = switch (kind) {
        .preprocessed => plan.placements[47].?.preprocessed_offset,
        .main => plan.placements[47].?.main_offset,
        .interaction => plan.placements[47].?.interaction_offset,
    };
    const count: usize = switch (kind) {
        .preprocessed => plan.total_preprocessed_columns - start,
        .main => plan.total_main_columns - start,
        .interaction => plan.total_interaction_columns - start,
    };
    if (start > tree.len or count > tree.len - start)
        return error.DirectV5TreeGeometryMismatch;
    return tree[start..][0..count];
}

fn writeTyped(
    comptime Air: type,
    plan: *const plan_mod.Plan,
    row: usize,
    rows: []const if (Air == hash_air) hash_relation.Row else Air.Row,
    destination: [][]M31,
    comptime kind: Tree,
) !void {
    const item = plan.placements[row].?;
    const size = traceSize(plan, row);
    const begin: usize = if (kind == .preprocessed) Air.PHYSICAL_MAIN_COLUMN_COUNT else 0;
    const n: usize = if (kind == .preprocessed) Air.PREPROCESSED_COLUMN_COUNT else Air.PHYSICAL_MAIN_COLUMN_COUNT;
    const offset: usize = if (kind == .preprocessed) item.preprocessed_offset else item.main_offset;
    if (rows.len > size or n != (if (kind == .preprocessed) item.geometry.preprocessed_columns else item.geometry.main_columns) or
        offset > destination.len or n > destination.len - offset)
        return error.DirectV5TreeGeometryMismatch;
    for (destination[offset..][0..n]) |column| {
        if (column.len != size) return error.DirectV5TreeGeometryMismatch;
        for (column) |value| if (!value.isZero()) return error.DirectV5TreeNotFresh;
    }
    for (rows, 0..) |value, logical| {
        const committed = framework.committedRow(logical, item.geometry.log_size);
        for (value[begin..][0..n], 0..) |word, column|
            destination[offset + column][committed] = word;
    }
}

fn hashRows(allocator: std.mem.Allocator, witness: *const hash_witness.HashV1) ![]hash_relation.Row {
    const size = @as(usize, 1) << @intCast(witness.log_size);
    const rows = try allocator.alloc(hash_relation.Row, size);
    errdefer allocator.free(rows);
    for (rows, 0..) |*row, index|
        row.* = if (index < witness.main.len)
            try witness.logicalRow(index)
        else
            [_]M31{M31.zero()} ** hash_air.LOGICAL_INPUT_COUNT;
    return rows;
}

fn writeHash(plan: *const plan_mod.Plan, row: usize, witness: *const hash_witness.HashV1, destination: [][]M31, comptime kind: Tree) !void {
    const rows = try hashRows(witness.allocator, witness);
    defer witness.allocator.free(rows);
    try writeTyped(hash_air, plan, row, rows, destination, kind);
}

fn interactTyped(
    comptime Air: type,
    allocator: std.mem.Allocator,
    plan: *const plan_mod.Plan,
    row: usize,
    rows: []const if (Air == hash_air) hash_relation.Row else Air.Row,
    relations: *const universal.UniversalRelations,
    destination: [][]M31,
) !ClaimAudit {
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const authenticated = if (comptime Air == hash_air)
        try hash_relation.authenticate(&definition)
    else
        try Air.authenticate(&definition);
    const events = if (comptime @hasField(Air.Definition, "events"))
        definition.events
    else
        .{definition.event};
    var generated = try authenticated.generateInteraction(
        allocator,
        &definition.arena,
        Air.SEMANTIC_DIGEST,
        events,
        rows,
        plan.placements[row].?.geometry.log_size,
        relations,
    );
    defer generated.deinit(allocator);
    const claim = generated.claims.total();
    const audit = try authenticated.auditPreparedDomainSums(allocator, rows, relations, claim);
    const item = plan.placements[row].?;
    const size = traceSize(plan, row);
    const n: usize = item.geometry.interaction_columns;
    if (generated.columns.len != n or item.interaction_offset > destination.len or
        n > destination.len - item.interaction_offset)
        return error.DirectV5TreeGeometryMismatch;
    for (generated.columns, destination[item.interaction_offset..][0..n]) |from, to| {
        if (from.len != size or to.len != size) return error.DirectV5TreeGeometryMismatch;
        for (to) |value| if (!value.isZero()) return error.DirectV5TreeNotFresh;
    }
    for (generated.columns, destination[item.interaction_offset..][0..n]) |from, to|
        @memcpy(to, from);
    return .{ .claim = claim, .audit = audit };
}

fn interactHash(allocator: std.mem.Allocator, plan: *const plan_mod.Plan, row: usize, witness: *const hash_witness.HashV1, relations: *const universal.UniversalRelations, destination: [][]M31) !ClaimAudit {
    const rows = try hashRows(allocator, witness);
    defer allocator.free(rows);
    return interactTyped(hash_air, allocator, plan, row, rows, relations, destination);
}

fn emptyAudit() DomainAudit {
    return .{ .values = @splat(QM31.zero()), .total = QM31.zero(), .logical_rows = 0, .event_terms = 0 };
}
