//! Internal shard of relation_interaction.zig; use the facade.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const fields = stwo_core.fields;
pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const permutation = @import("../../infra_trace/permutation.zig");
pub const logup = @import("../../air/logup.zig");
pub const digest = @import("../../air/lang/digest.zig");
pub const expr = @import("../../air/lang/expr.zig");
pub const ir = @import("../../air/lang/ir.zig");
pub const lower_effects = @import("../../air/lang/lower_effects.zig");
pub const relation = @import("../../air/lang/relation.zig");
pub const types = @import("../../air/lang/types.zig");
pub const validate = @import("../../air/lang/validate.zig");
pub const universal = @import("universal_challenges.zig");
pub const domain_audit = @import("relation_interaction_domain_audit.zig");
pub const tuple_audit = @import("relation_interaction_tuple_audit.zig");
pub const entry_validation = @import("relation_interaction_entry_validation.zig");
pub const claims_derivation = @import("relation_interaction_claims.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const MAX_ARENA_NODES: usize = 512;
pub const MAX_COMPILED_NODES: usize = 192;
pub const MAX_ARITY: usize = universal.MAX_ARITY;
pub const NO_SLOT = std.math.maxInt(u16);

pub const Error = error{
    ArenaNodeLimitExceeded,
    BatchPlanMismatch,
    BindingSealMismatch,
    ClaimMismatch,
    CompiledNodeLimitExceeded,
    EntryArityMismatch,
    EntryNumeratorMismatch,
    EntryOrderMismatch,
    EntryRoleMismatch,
    EntrySchemaMismatch,
    EntryTupleMismatch,
    EventPlanMismatch,
    ExpressionCycle,
    FormatVersionMismatch,
    InteractionColumnMismatch,
    InteractionGeometryMismatch,
    InvalidBatchSize,
    InvalidInputGeometry,
    InvalidTraceShape,
    RegistryOrderMismatch,
    RelationSumNonZero,
    SlotOverflow,
    UnsupportedRelationExpression,
};
pub const AuthenticationError = Error || validate.Error;
pub const RowError = AuthenticationError || universal.Error;
pub const InteractionError = AuthenticationError || logup.LogupError ||
    universal.Error;
pub const ClaimError = RowError || QM31.Error;
pub const DomainAuditError = std.mem.Allocator.Error || universal.Error || error{
    ClaimMismatch,
    InvalidTraceShape,
    ZeroDenominator,
};

/// Cold, diagnostic-only decomposition of one framework claimed sum by the
/// exact universal relation domain carried by each authenticated event.
/// `values` is indexed by `relation.Domain`; `total` is recomputed from those
/// values and is required to equal the component claim supplied by the caller.
pub const DomainAudit = struct {
    values: [universal.RELATION_COUNT]QM31,
    total: QM31,
    logical_rows: usize,
    event_terms: usize,
};

pub const TupleContribution = struct {
    domain: relation.Domain,
    component: u8,
    event: u8,
    role: relation.Role,
    arity: u8,
    /// The exact leading coordinates retained for bounded diagnostic output.
    /// Five covers the verifier-input and verifier-randomness ABIs whose
    /// coordinate drift is otherwise impossible to distinguish from a hash.
    /// The canonical hash remains the grouping authority for wider tuples.
    tuple_prefix: [TUPLE_DIAGNOSTIC_PREFIX_ARITY]QM31,
    tuple_hash: [32]u8,
    signed_weight: QM31,
};

pub const TUPLE_DIAGNOSTIC_PREFIX_ARITY: usize = 5;

pub const TupleClosureReport = struct {
    contribution_count: usize,
    unmatched_tuple_count: usize,
    unmatched_by_domain: [universal.RELATION_COUNT]usize,

    pub fn isClosed(self: TupleClosureReport) bool {
        return self.unmatched_tuple_count == 0;
    }

    pub fn redDomainCount(self: TupleClosureReport) usize {
        var count: usize = 0;
        for (self.unmatched_by_domain) |unmatched|
            count += @intFromBool(unmatched != 0);
        return count;
    }
};

/// Diagnostic-only canonical tuple ledger. It stores one signed contribution
/// per active logical event, keyed by a SHA-256 digest of the exact domain,
/// arity, and QM31 tuple coordinates. This is not protocol authority; it is a
/// collision-resistant engineering instrument for locating an unmatched
/// producer/consumer tuple after the algebraic domain audit turns red.
pub const TupleLedger = struct {
    allocator: std.mem.Allocator,
    contributions: std.ArrayList(TupleContribution) = .empty,

    pub fn init(allocator: std.mem.Allocator) TupleLedger {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *TupleLedger) void {
        self.contributions.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn append(
        self: *TupleLedger,
        domain: relation.Domain,
        component: u8,
        event: u8,
        role: relation.Role,
        signed_weight: QM31,
        values: []const QM31,
    ) std.mem.Allocator.Error!void {
        if (signed_weight.isZero()) return;
        var tuple_prefix =
            [_]QM31{QM31.zero()} ** TUPLE_DIAGNOSTIC_PREFIX_ARITY;
        const prefix_len = @min(values.len, tuple_prefix.len);
        @memcpy(tuple_prefix[0..prefix_len], values[0..prefix_len]);
        try self.contributions.append(self.allocator, .{
            .domain = domain,
            .component = component,
            .event = event,
            .role = role,
            .arity = @intCast(values.len),
            .tuple_prefix = tuple_prefix,
            .tuple_hash = canonicalTupleHash(domain, values),
            .signed_weight = signed_weight,
        });
    }

    /// Challenge-independent exact tuple closure. Sorting is in-place and
    /// allocation-free: equal relation tuples are grouped by their canonical
    /// hash and their signed multiplicities must cancel in M31/QM31 before a
    /// prover is allowed to spend time on denominator inversion or PCS.
    pub fn classify(self: *TupleLedger) TupleClosureReport {
        std.mem.sort(
            TupleContribution,
            self.contributions.items,
            {},
            tupleContributionLessThan,
        );
        var report = TupleClosureReport{
            .contribution_count = self.contributions.items.len,
            .unmatched_tuple_count = 0,
            .unmatched_by_domain = [_]usize{0} ** universal.RELATION_COUNT,
        };
        var cursor: usize = 0;
        while (cursor < self.contributions.items.len) {
            const first = self.contributions.items[cursor];
            var end = cursor + 1;
            var signed_weight = first.signed_weight;
            while (end < self.contributions.items.len and
                self.contributions.items[end].domain == first.domain and
                std.mem.eql(
                    u8,
                    &self.contributions.items[end].tuple_hash,
                    &first.tuple_hash,
                )) : (end += 1)
            {
                signed_weight = signed_weight.add(
                    self.contributions.items[end].signed_weight,
                );
            }
            if (!signed_weight.isZero()) {
                report.unmatched_tuple_count += 1;
                report.unmatched_by_domain[@intFromEnum(first.domain)] += 1;
            }
            cursor = end;
        }
        return report;
    }
};

pub fn tupleContributionLessThan(
    _: void,
    lhs: TupleContribution,
    rhs: TupleContribution,
) bool {
    const lhs_domain = @intFromEnum(lhs.domain);
    const rhs_domain = @intFromEnum(rhs.domain);
    if (lhs_domain != rhs_domain) return lhs_domain < rhs_domain;
    const hash_order = std.mem.order(u8, &lhs.tuple_hash, &rhs.tuple_hash);
    if (hash_order != .eq) return hash_order == .lt;
    if (lhs.component != rhs.component) return lhs.component < rhs.component;
    if (lhs.event != rhs.event) return lhs.event < rhs.event;
    return @intFromEnum(lhs.role) < @intFromEnum(rhs.role);
}

pub fn allDomainMask() u64 {
    comptime std.debug.assert(universal.RELATION_COUNT < @bitSizeOf(u64));
    return (@as(u64, 1) << universal.RELATION_COUNT) - 1;
}

pub fn canonicalTupleHash(
    domain: relation.Domain,
    values: []const QM31,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u8, @intFromEnum(domain));
    hashInt(&hash, u8, values.len);
    for (values) |value| {
        for (value.toM31Array()) |coordinate|
            hashInt(&hash, u32, coordinate.toU32());
    }
    return hash.finalResult();
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

pub const BinarySlots = struct {
    lhs: u16,
    rhs: u16,
};

pub const SelectSlots = struct {
    selector: u16,
    when_true: u16,
    when_false: u16,
};

pub const EvalOp = union(enum) {
    constant: u32,
    add: BinarySlots,
    sub: BinarySlots,
    mul: BinarySlots,
    neg: u16,
    select: SelectSlots,
};

pub const EvalNode = struct {
    source: types.ValueId,
    destination: u16,
    op: EvalOp,
};

pub const EventPlan = struct {
    ordinal: u8,
    effect: types.EffectId,
    schema: types.RelationSchemaId,
    schema_version: u16,
    domain: relation.Domain,
    role: relation.Role,
    numerator_slot: u16,
    value_slots: [MAX_ARITY]u16,
    arity: u8,
};

pub const BatchPlan = struct {
    ordinal: u8,
    first: u8,
    second: ?u8,
    interaction_column_start: u16,
};

pub const Entry = struct {
    ordinal: u8,
    schema: types.RelationSchemaId,
    schema_version: u16,
    domain: relation.Domain,
    role: relation.Role,
    numerator: QM31,
    values: [MAX_ARITY]QM31,
    arity: u8,

    fn denominator(
        self: *const Entry,
        relations: *const universal.UniversalRelations,
    ) universal.Error!QM31 {
        return relations.get(self.domain).combineSecure(self.values[0..self.arity]);
    }
};

pub fn signedNumerator(role: relation.Role, magnitude: QM31) QM31 {
    return switch (role) {
        .request, .consume => magnitude.neg(),
        .emit => magnitude,
    };
}

pub fn emptyEvalNode() EvalNode {
    return .{
        .source = @enumFromInt(0),
        .destination = NO_SLOT,
        .op = .{ .constant = 0 },
    };
}

pub fn emptyEventPlan() EventPlan {
    return .{
        .ordinal = 0,
        .effect = @enumFromInt(0),
        .schema = @enumFromInt(0),
        .schema_version = 0,
        .domain = .registers_state,
        .role = .request,
        .numerator_slot = NO_SLOT,
        .value_slots = [_]u16{NO_SLOT} ** MAX_ARITY,
        .arity = 0,
    };
}

pub fn pairSum(pair: logup.RowPair) QM31.Error!QM31 {
    return pair.n1.mul(try pair.d1.inv()).add(pair.n2.mul(try pair.d2.inv()));
}

pub fn traceSize(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidTraceShape;
    return @as(usize, 1) << @intCast(log_size);
}
