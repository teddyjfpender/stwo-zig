//! Authenticated shadow relation lowering for the canonical Poseidon2 pilot.
//!
//! The pure H-002 graph and H-003 plan contain no protocol effects. This pass
//! admits the H-004 compatibility binding, then derives the four existing
//! Poseidon relation events and their two pairs-batched LogUp columns from a
//! small typed plan. It deliberately remains outside production consumers.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../infra_trace.zig");
const logup = @import("../logup.zig");
const challenges = @import("../relation_challenges.zig");
const compat = @import("typed_poseidon2_compat.zig");
const digest = @import("digest.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;
pub const WIDTH: usize = poseidon.WIDTH;
pub const N_EVENTS: usize = 4;
pub const N_BATCHES: usize = 2;
pub const N_SUMS: usize = N_BATCHES;
pub const N_INTERACTION_COLUMNS: usize = 4 * N_SUMS;
pub const MAX_ARITY: usize = 32;
pub const OUTPUT_COLUMN_START: usize =
    compat.TEMPORARY_START + compat.OUTPUT_START;

pub const Error = error{
    BatchPlanMismatch,
    BindingSealMismatch,
    ClaimMismatch,
    EntryArityMismatch,
    EntryDomainMismatch,
    EntryNumeratorMismatch,
    EntryOrderMismatch,
    EntryRoleMismatch,
    EntryTupleMismatch,
    EventPlanMismatch,
    FormatVersionMismatch,
    GeometryMismatch,
    InteractionColumnMismatch,
    InteractionGeometryMismatch,
    InvalidTraceShape,
    PolicyMismatch,
    PolicyVersionMismatch,
    RelationSchemaMismatch,
    RelationSumNonZero,
};
pub const AuthenticationError = Error || materializer.Error || compat.BindingError;
pub const ClaimError = AuthenticationError || QM31.Error;
pub const InteractionError = AuthenticationError || logup.LogupError;

pub const PolicyId = enum(u32) {
    stark_v_poseidon2_relations = 0x5032_5231,
    _,
};

pub const Identity = struct {
    format_version: u16,
    policy: PolicyId,
    policy_version: u16,
    events: u8,
    batches: u8,
    sums: u8,
    interaction_columns: u8,

    pub fn canonical() Identity {
        return .{
            .format_version = FORMAT_VERSION,
            .policy = .stark_v_poseidon2_relations,
            .policy_version = POLICY_VERSION,
            .events = N_EVENTS,
            .batches = N_BATCHES,
            .sums = N_SUMS,
            .interaction_columns = N_INTERACTION_COLUMNS,
        };
    }

    pub fn validate(self: Identity) Error!void {
        const expected = canonical();
        if (self.format_version != expected.format_version)
            return error.FormatVersionMismatch;
        if (self.policy != expected.policy) return error.PolicyMismatch;
        if (self.policy_version != expected.policy_version)
            return error.PolicyVersionMismatch;
        if (self.events != expected.events or self.batches != expected.batches or
            self.sums != expected.sums or
            self.interaction_columns != expected.interaction_columns)
        {
            return error.GeometryMismatch;
        }
    }
};

pub const EventId = enum(u8) {
    input,
    narrow_output,
    wide_output,
    io,
};

pub const NumeratorFormula = enum(u8) {
    negative_enabled_non_io,
    enabled_narrow,
    enabled_wide,
    enabled_io,
};

pub const TupleProjection = enum(u8) {
    input,
    narrow_output,
    wide_output,
    input_output,
};

/// Static effect metadata. `relation_arity` is the denominator ABI width;
/// `semantic_width` pins the shorter source slice used by diagnostics.
pub const EventPlan = struct {
    id: EventId,
    ordinal: u8,
    schema: types.RelationSchemaId,
    schema_version: u16,
    domain: relation.Domain,
    role: relation.Role,
    access_ordinal: ?u8,
    relation_arity: u8,
    semantic_width: u8,
    numerator: NumeratorFormula,
    projection: TupleProjection,

    pub fn validate(self: EventPlan, ordinal: usize) !void {
        if (ordinal >= N_EVENTS) return error.EventPlanMismatch;
        if (!std.meta.eql(self, canonicalEvent(ordinal)))
            return error.EventPlanMismatch;
        const schema = relation.getById(self.schema) orelse
            return error.RelationSchemaMismatch;
        if (schema.domain != self.domain or schema.version != self.schema_version or
            schema.challenge != .stark_v_alpha_powers_minus_z or
            schema.multiplicity != .role_signed_liveness or
            schema.padding != .inactive_zero)
        {
            return error.RelationSchemaMismatch;
        }
        var field_types = [_]types.Type{.felt} ** MAX_ARITY;
        relation.validateEvent(
            self.schema,
            self.role,
            field_types[0..self.relation_arity],
            self.access_ordinal,
        ) catch return error.RelationSchemaMismatch;
    }
};

pub const BatchPlan = struct {
    ordinal: u8,
    first: EventId,
    second: EventId,
    interaction_column_start: u8,

    pub fn validate(self: BatchPlan, ordinal: usize) Error!void {
        if (ordinal >= N_BATCHES) return error.BatchPlanMismatch;
        if (!std.meta.eql(self, canonicalBatch(ordinal)))
            return error.BatchPlanMismatch;
    }
};

/// All authority needed to reauthenticate a relation plan at a use boundary.
pub const Authority = struct {
    arena: *const ir.Arena,
    definition: poseidon.Definition,
    spans: poseidon.DefinitionSpans,
    materialization_plan: *const materializer.Plan,
    binding: *const compat.OwnedBinding,
};

/// A fixed relation plan sealed to the H-004 semantic/layout binding.
pub const Plan = struct {
    identity: Identity,
    compatibility_identity: compat.Identity,
    materializer_policy_version: u16,
    program_digest: digest.Digest,
    gate: types.ValueId,
    materializer_policy: materializer.Policy,
    events: [N_EVENTS]EventPlan,
    batches: [N_BATCHES]BatchPlan,

    pub fn validateAgainst(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
    ) AuthenticationError!void {
        try self.identity.validate();
        try authority.binding.validateAgainst(
            allocator,
            authority.arena,
            authority.definition,
            authority.spans,
            authority.materialization_plan,
        );
        if (!std.meta.eql(self.compatibility_identity, authority.binding.identity) or
            self.materializer_policy_version != authority.binding.materializer_policy_version or
            !std.mem.eql(u8, &self.program_digest, &authority.binding.program_digest) or
            self.gate != authority.binding.gate or
            !std.meta.eql(self.materializer_policy, authority.binding.policy))
        {
            return error.BindingSealMismatch;
        }
        for (self.events, 0..) |event_plan, ordinal| try event_plan.validate(ordinal);
        for (self.batches, 0..) |batch, ordinal| try batch.validate(ordinal);
    }

    pub fn rowFromMain(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        main: [compat.N_MAIN_COLUMNS]M31,
    ) AuthenticationError!RelationRow {
        try self.validateAgainst(allocator, authority);
        return relationRowFromMain(main);
    }

    /// Exact narrow-output interaction shortcut used by the Merkle witness.
    /// It carries no claim that `output_value` is the typed permutation output;
    /// validation against the separately committed main row supplies that bind.
    pub fn carriedNarrowRow(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        input: [WIDTH]M31,
        output_value: M31,
    ) AuthenticationError!RelationRow {
        try self.validateAgainst(allocator, authority);
        var output = [_]M31{M31.zero()} ** WIDTH;
        output[0] = output_value;
        return .{
            .enabled = M31.one(),
            .input = input,
            .output = output,
            .wide = M31.zero(),
            .io = M31.zero(),
        };
    }

    pub fn entries(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        row: RelationRow,
    ) AuthenticationError![N_EVENTS]Entry {
        try self.validateAgainst(allocator, authority);
        return entriesUnchecked(self, row);
    }

    pub fn validateEntries(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        row: RelationRow,
        actual: [N_EVENTS]Entry,
    ) AuthenticationError!void {
        try self.validateAgainst(allocator, authority);
        const expected = entriesUnchecked(self, row);
        for (actual, expected, 0..) |got, wanted, ordinal| {
            if (got.id != wanted.id or
                @as(usize, @intFromEnum(got.id)) != ordinal)
            {
                return error.EntryOrderMismatch;
            }
            if (got.schema != wanted.schema or got.schema_version != wanted.schema_version or
                got.domain != wanted.domain)
            {
                return error.EntryDomainMismatch;
            }
            if (got.role != wanted.role or got.access_ordinal != wanted.access_ordinal)
                return error.EntryRoleMismatch;
            if (got.arity != wanted.arity or got.semantic_width != wanted.semantic_width)
                return error.EntryArityMismatch;
            if (!got.numerator.eql(wanted.numerator))
                return error.EntryNumeratorMismatch;
            for (got.values, wanted.values) |got_value, wanted_value| {
                if (!got_value.eql(wanted_value)) return error.EntryTupleMismatch;
            }
        }
    }

    pub fn rowPairs(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        row: RelationRow,
        relation_challenges: *const challenges.Relations,
    ) AuthenticationError![N_SUMS]logup.RowPair {
        try self.validateAgainst(allocator, authority);
        return try rowPairsUnchecked(self, row, relation_challenges);
    }

    pub fn rowClaims(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        row: RelationRow,
        relation_challenges: *const challenges.Relations,
    ) ClaimError!Claims {
        const pairs = try self.rowPairs(allocator, authority, row, relation_challenges);
        var sums: [N_SUMS]QM31 = undefined;
        for (&sums, pairs) |*sum, pair| sum.* = try pairSum(pair);
        return .{ .sums = sums };
    }

    pub fn generateInteraction(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        rows: []const RelationRow,
        log_size: u32,
        relation_challenges: *const challenges.Relations,
    ) InteractionError!Interaction {
        try self.validateAgainst(allocator, authority);
        return generateInteractionUnchecked(
            self,
            allocator,
            rows,
            log_size,
            relation_challenges,
        );
    }

    pub fn validateInteraction(
        self: *const Plan,
        allocator: std.mem.Allocator,
        authority: Authority,
        rows: []const RelationRow,
        log_size: u32,
        relation_challenges: *const challenges.Relations,
        actual: *const Interaction,
    ) InteractionError!void {
        try self.validateAgainst(allocator, authority);
        const size = traceSize(log_size) catch return error.InvalidTraceShape;
        for (actual.columns) |column| {
            if (column.len != size) return error.InteractionGeometryMismatch;
        }
        var expected = try generateInteractionUnchecked(
            self,
            allocator,
            rows,
            log_size,
            relation_challenges,
        );
        defer expected.deinit(allocator);
        if (!actual.claims.eql(expected.claims)) return error.ClaimMismatch;
        for (actual.columns, expected.columns) |got, wanted| {
            for (got, wanted) |got_value, wanted_value| {
                if (!got_value.eql(wanted_value))
                    return error.InteractionColumnMismatch;
            }
        }
    }
};

pub fn authenticate(
    allocator: std.mem.Allocator,
    authority: Authority,
) AuthenticationError!Plan {
    var events: [N_EVENTS]EventPlan = undefined;
    for (&events, 0..) |*event_plan, ordinal| event_plan.* = canonicalEvent(ordinal);
    var batches: [N_BATCHES]BatchPlan = undefined;
    for (&batches, 0..) |*batch, ordinal| batch.* = canonicalBatch(ordinal);
    const result = Plan{
        .identity = Identity.canonical(),
        .compatibility_identity = authority.binding.identity,
        .materializer_policy_version = authority.binding.materializer_policy_version,
        .program_digest = authority.binding.program_digest,
        .gate = authority.binding.gate,
        .materializer_policy = authority.binding.policy,
        .events = events,
        .batches = batches,
    };
    try result.validateAgainst(allocator, authority);
    return result;
}

pub const RelationRow = struct {
    enabled: M31,
    input: [WIDTH]M31,
    output: [WIDTH]M31,
    wide: M31,
    io: M31,
};

pub const Entry = struct {
    id: EventId,
    schema: types.RelationSchemaId,
    schema_version: u16,
    domain: relation.Domain,
    role: relation.Role,
    access_ordinal: ?u8,
    numerator: QM31,
    values: [MAX_ARITY]QM31,
    arity: u8,
    semantic_width: u8,

    fn denominator(self: Entry, relation_challenges: *const challenges.Relations) Error!QM31 {
        return switch (self.domain) {
            .poseidon2 => relation_challenges.poseidon2.combineSecure(self.values[0..WIDTH].*),
            .poseidon2_io => relation_challenges.poseidon2_io.combineSecure(self.values[0 .. 2 * WIDTH].*),
            else => error.EntryDomainMismatch,
        };
    }
};

pub const Claims = struct {
    sums: [N_SUMS]QM31,

    pub fn total(self: Claims) QM31 {
        return self.sums[0].add(self.sums[1]);
    }

    pub fn eql(self: Claims, other: Claims) bool {
        for (self.sums, other.sums) |lhs, rhs| if (!lhs.eql(rhs)) return false;
        return true;
    }

    pub fn verifyClosure(self: Claims, counterpart: QM31) Error!void {
        if (!self.total().add(counterpart).isZero())
            return error.RelationSumNonZero;
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,

    pub fn deinit(self: *Interaction, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        self.* = undefined;
    }
};

pub fn paddingPairs() [N_SUMS]logup.RowPair {
    const zero = QM31.zero();
    const one = QM31.one();
    return .{
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
    };
}

fn relationRowFromMain(main: [compat.N_MAIN_COLUMNS]M31) RelationRow {
    var input: [WIDTH]M31 = undefined;
    var output: [WIDTH]M31 = undefined;
    @memcpy(&input, main[compat.INPUT_START..][0..WIDTH]);
    @memcpy(&output, main[OUTPUT_COLUMN_START..][0..WIDTH]);
    return .{
        .enabled = main[compat.ENABLER_COLUMN],
        .input = input,
        .output = output,
        .wide = main[compat.WIDE_COLUMN],
        .io = main[compat.IO_COLUMN],
    };
}

fn entriesUnchecked(plan: *const Plan, row: RelationRow) [N_EVENTS]Entry {
    var result: [N_EVENTS]Entry = undefined;
    for (&result, plan.events) |*entry, event_plan| {
        var values = [_]QM31{QM31.zero()} ** MAX_ARITY;
        switch (event_plan.projection) {
            .input => lift(values[0..WIDTH], &row.input),
            .narrow_output => values[0] = QM31.fromBase(row.output[0]),
            .wide_output => lift(values[0 .. WIDTH / 2], row.output[0 .. WIDTH / 2]),
            .input_output => {
                lift(values[0..WIDTH], &row.input);
                lift(values[WIDTH .. 2 * WIDTH], &row.output);
            },
        }
        entry.* = .{
            .id = event_plan.id,
            .schema = event_plan.schema,
            .schema_version = event_plan.schema_version,
            .domain = event_plan.domain,
            .role = event_plan.role,
            .access_ordinal = event_plan.access_ordinal,
            .numerator = numerator(event_plan.numerator, row),
            .values = values,
            .arity = event_plan.relation_arity,
            .semantic_width = event_plan.semantic_width,
        };
    }
    return result;
}

fn numerator(formula: NumeratorFormula, row: RelationRow) QM31 {
    const enabled = QM31.fromBase(row.enabled);
    const wide = QM31.fromBase(row.wide);
    const io = QM31.fromBase(row.io);
    const one = QM31.one();
    return switch (formula) {
        .negative_enabled_non_io => enabled.mul(one.sub(io)).neg(),
        .enabled_narrow => enabled.mul(one.sub(wide).sub(io)),
        .enabled_wide => enabled.mul(wide),
        .enabled_io => enabled.mul(io),
    };
}

fn rowPairsUnchecked(
    plan: *const Plan,
    row: RelationRow,
    relation_challenges: *const challenges.Relations,
) Error![N_SUMS]logup.RowPair {
    const event_entries = entriesUnchecked(plan, row);
    var result: [N_SUMS]logup.RowPair = undefined;
    for (&result, plan.batches) |*pair, batch| {
        const first = event_entries[@intFromEnum(batch.first)];
        const second = event_entries[@intFromEnum(batch.second)];
        pair.* = .{
            .n1 = first.numerator,
            .d1 = try first.denominator(relation_challenges),
            .n2 = second.numerator,
            .d2 = try second.denominator(relation_challenges),
        };
    }
    return result;
}

fn generateInteractionUnchecked(
    plan: *const Plan,
    allocator: std.mem.Allocator,
    rows: []const RelationRow,
    log_size: u32,
    relation_challenges: *const challenges.Relations,
) (Error || logup.LogupError)!Interaction {
    const size = traceSize(log_size) catch return error.InvalidTraceShape;
    if (rows.len > size) return error.InvalidTraceShape;
    const pairs = try allocator.alloc([N_SUMS]logup.RowPair, size);
    defer allocator.free(pairs);
    for (pairs, 0..) |*row_pairs, row| {
        row_pairs.* = if (row < rows.len)
            try rowPairsUnchecked(plan, rows[row], relation_challenges)
        else
            paddingPairs();
    }

    var cumulative: [N_SUMS]logup.CumulativeColumn = undefined;
    var initialized: usize = 0;
    defer for (cumulative[0..initialized]) |*column| column.deinit(allocator);
    for (&cumulative, 0..) |*column, sum_index| {
        const batch_rows = try allocator.alloc(logup.RowPair, size);
        defer allocator.free(batch_rows);
        for (pairs, batch_rows) |row, *pair| pair.* = row[sum_index];
        column.* = try logup.cumulativeColumn(allocator, batch_rows);
        initialized += 1;
    }

    var columns = try allocateColumns(allocator, size);
    errdefer freeColumns(allocator, &columns);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    for (0..size) |row| {
        const destination = placement.map(row);
        for (0..N_SUMS) |sum_index| {
            const coordinates = cumulative[sum_index].sums[row].toM31Array();
            for (coordinates, 0..) |coordinate, coordinate_index| {
                columns[4 * sum_index + coordinate_index][destination] = coordinate;
            }
        }
    }
    return .{
        .columns = columns,
        .claims = .{ .sums = .{ cumulative[0].claimed, cumulative[1].claimed } },
    };
}

fn pairSum(pair: logup.RowPair) QM31.Error!QM31 {
    return pair.n1.mul(try pair.d1.inv()).add(pair.n2.mul(try pair.d2.inv()));
}

fn canonicalEvent(ordinal: usize) EventPlan {
    return switch (ordinal) {
        0 => makeEvent(.input, .poseidon2, 16, 16, .negative_enabled_non_io, .input),
        1 => makeEvent(.narrow_output, .poseidon2, 16, 1, .enabled_narrow, .narrow_output),
        2 => makeEvent(.wide_output, .poseidon2, 16, 8, .enabled_wide, .wide_output),
        3 => makeEvent(.io, .poseidon2_io, 32, 32, .enabled_io, .input_output),
        else => unreachable,
    };
}

fn makeEvent(
    id: EventId,
    domain: relation.Domain,
    relation_arity: u8,
    semantic_width: u8,
    formula: NumeratorFormula,
    projection: TupleProjection,
) EventPlan {
    const schema = relation.get(domain);
    return .{
        .id = id,
        .ordinal = @intFromEnum(id),
        .schema = schema.id,
        .schema_version = schema.version,
        .domain = domain,
        .role = .request,
        .access_ordinal = null,
        .relation_arity = relation_arity,
        .semantic_width = semantic_width,
        .numerator = formula,
        .projection = projection,
    };
}

fn canonicalBatch(ordinal: usize) BatchPlan {
    return switch (ordinal) {
        0 => .{ .ordinal = 0, .first = .input, .second = .narrow_output, .interaction_column_start = 0 },
        1 => .{ .ordinal = 1, .first = .wide_output, .second = .io, .interaction_column_start = 4 },
        else => unreachable,
    };
}

fn lift(destination: []QM31, values: []const M31) void {
    std.debug.assert(destination.len == values.len);
    for (destination, values) |*target, value| target.* = QM31.fromBase(value);
}

fn traceSize(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    return @as(usize, 1) << @intCast(log_size);
}

fn allocateColumns(
    allocator: std.mem.Allocator,
    len: usize,
) ![N_INTERACTION_COLUMNS][]M31 {
    var columns: [N_INTERACTION_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, len);
        initialized += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

comptime {
    if (WIDTH != 16 or compat.N_MAIN_COLUMNS != 445 or
        compat.N_MATERIALIZATIONS != 426 or OUTPUT_COLUMN_START != 427 or
        OUTPUT_COLUMN_START + WIDTH != compat.WIDE_COLUMN)
    {
        @compileError("Poseidon2 relation projection geometry drifted");
    }
    if (N_INTERACTION_COLUMNS != 8 or
        N_INTERACTION_COLUMNS != N_SUMS * @import("stwo_core").fields.qm31.SECURE_EXTENSION_DEGREE)
    {
        @compileError("Poseidon2 relation interaction geometry drifted");
    }
}
