//! Live LogUp lowering for compiler-owned function activations.
//!
//! F-013 authenticates function frames and ordered activation events; F-015
//! authenticates the proof-bearing body behind every participating function.
//! This module is the protocol boundary between those cold compiler records
//! and the existing RISC-V LogUp algebra:
//!
//! * each required function receives an independent `(z, alpha)` pair bound to
//!   the complete frame-plan and exact per-function ABI digest;
//! * callee rows consume `(args..., rets...)`, while caller and public-root rows
//!   emit that same tuple;
//! * an all-source coefficient bound excludes M31 multiplicity wrap before any
//!   interaction output is published;
//! * event claims remain separate and are projected into one independently
//!   checked balance per function relation; and
//! * the prepared evaluator batch-inverts all denominators into caller-owned
//!   scratch and publishes no pair or claim before every denominator is known
//!   to be non-zero.
//!
//! Programs without an owned, relation-backed function return an inactive
//! protocol. They mix no transcript data, draw no challenges, allocate no
//! protocol storage, and their prepared hot path accepts only empty slices.

const std = @import("std");
const alias_check = @import("function_activation_alias.zig");
const authority_impl = @import("function_activation_authority.zig");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const logup = @import("../logup.zig");
const protocol_degree = @import("protocol_degree.zig");
const preflight_impl = @import("function_activation_preflight.zig");
const types = @import("types.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const AddressRange = alias_check.AddressRange;
const objectAddress = alias_check.objectAddress;
const sliceAddress = alias_check.sliceAddress;

pub const FORMAT_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;
pub const TRANSCRIPT_DOMAIN_TAG: u64 = 0x464e_4143_5456_3031; // "FNACTV01"
pub const CLAIM_DOMAIN_TAG: u64 = 0x464e_434c_4149_4d31; // "FNCLAIM1"
pub const DIGEST_DOMAIN = "stwo-zig/typed-air/function-activation-logup/v1\x00";
pub const Digest = [32]u8;
pub const SOURCE_COEFFICIENT_BOUND_EXCLUSIVE: u32 = fields.m31.Modulus;

/// Function activations lower one signed enabler over one challenge-linear
/// denominator into `RowPair.single`.  Derive the certificate from the same
/// recurrence used by production lookup planning; do not maintain a second
/// handwritten degree formula here.
pub const MAXIMUM_CONSTRAINT_DEGREE: protocol_degree.Degree = 3;
pub const DegreeCertificate = struct {
    numerator: protocol_degree.Degree,
    denominator: protocol_degree.Degree,
    row_window: protocol_degree.Degree,
    final: protocol_degree.Degree,
    maximum: protocol_degree.Degree,
    quotient_expansion_bits: u8,
};
pub const DEGREE_CERTIFICATE: DegreeCertificate = blk: {
    const numerator: protocol_degree.Degree = 1;
    const denominator: protocol_degree.Degree = 1;
    const terms = protocol_degree.interactionTerms(
        .{ .numerator = numerator, .denominator = denominator },
        null,
    ) catch @compileError("function activation degree recurrence overflowed");
    if (terms.final > MAXIMUM_CONSTRAINT_DEGREE)
        @compileError("function activation exceeds the degree-three policy");
    break :blk .{
        .numerator = numerator,
        .denominator = denominator,
        .row_window = terms.row_window,
        .final = terms.final,
        .maximum = MAXIMUM_CONSTRAINT_DEGREE,
        .quotient_expansion_bits = protocol_degree.quotientExpansionBits(terms.final),
    };
};

pub const IndexRange = struct {
    start: u32,
    len: u32,

    pub fn init(start: usize, len: usize) ValidationError!IndexRange {
        return .{
            .start = std.math.cast(u32, start) orelse return error.CountOverflow,
            .len = std.math.cast(u32, len) orelse return error.CountOverflow,
        };
    }
};

pub const RelationDescriptor = struct {
    function: types.FunctionId,
    relation: frames.FunctionRelationId,
    tuple_arity: u16,
    alpha_powers: IndexRange,
    relation_digest: Digest,
    z: QM31,
    alpha: QM31,
};

pub const EventDescriptor = struct {
    kind: frames.ActivationKind,
    role: frames.ActivationRole,
    weight: frames.WeightSource,
    relation_index: u32,
    callee: types.FunctionId,
    owner: ?types.FunctionId,
    call: ?types.CallId,
    tuple: IndexRange,
};

pub const RowOrigin = enum(u8) {
    /// Values and the unit enabler come from an authenticated function table
    /// or call-site trace row. Inactive rows are omitted from this sparse view.
    trace = 0,
    /// Values and multiplicity come from the verifier-visible public statement.
    public_statement = 1,
};

/// Exactly one batch is supplied for every authenticated event, in event
/// order. A batch may contain zero dynamic trace rows. A public root has one
/// statement-origin row whose multiplicity may aggregate identical roots.
pub const EventBatch = struct {
    event_index: u32,
    origin: RowOrigin,
    rows: IndexRange,
};

pub const ActivationRow = struct {
    tuple: IndexRange,
    multiplicity: M31,
};

/// Verifier-owned public activation input. `multiplicity` remains an integer
/// until this boundary so a decoded field element cannot disguise a wrapped
/// negative coefficient. Roots are supplied in canonical public-event order.
pub const PublicRoot = struct {
    event_index: u32,
    tuple: IndexRange,
    multiplicity: u32,
};

pub const ValidationError = frames.Error || error{
    CountOverflow,
    DegenerateChallenge,
    DigestMismatch,
    DuplicateChallenge,
    DuplicateRelationIdentity,
    InvalidEvent,
    InvalidFormat,
    InvalidPlanBinding,
    InvalidProtocolShape,
    InvalidRelation,
    InvalidRange,
    NonCanonicalChallenge,
    UnownedActivation,
};

pub const EvaluateError = error{
    AddressOverflow,
    AliasedBuffer,
    ClaimProjectionMismatch,
    CoefficientBoundExceeded,
    DenominatorCollision,
    InvalidBatchShape,
    InvalidMultiplicity,
    InvalidPublicRootBatch,
    InvalidPublicRoot,
    InvalidRange,
    InvalidRowOrigin,
    NonCanonicalClaim,
    NonCanonicalValue,
    PublicClaimMismatch,
    UnbalancedRelation,
};

pub const OwnedProtocol = struct {
    allocator: std.mem.Allocator,
    active: bool,
    format_version: u16,
    policy_version: u16,
    semantic_identity_format_version: u16,
    semantic_digest: Digest,
    frame_plan_digest: Digest,
    relations: []RelationDescriptor,
    alpha_powers: []QM31,
    events: []EventDescriptor,
    tuple_values: []types.ValueId,
    protocol_digest: Digest,

    pub fn deinit(self: *OwnedProtocol) void {
        if (self.active) {
            self.allocator.free(self.tuple_values);
            self.allocator.free(self.events);
            self.allocator.free(self.alpha_powers);
            self.allocator.free(self.relations);
        }
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedProtocol) ValidationError!void {
        if (!self.active) {
            if (self.format_version != FORMAT_VERSION or
                self.policy_version != POLICY_VERSION or
                self.semantic_identity_format_version != 0 or
                !digestIsZero(self.semantic_digest) or
                !digestIsZero(self.frame_plan_digest) or
                self.relations.len != 0 or self.alpha_powers.len != 0 or
                self.events.len != 0 or self.tuple_values.len != 0 or
                !digestIsZero(self.protocol_digest))
            {
                return error.InvalidProtocolShape;
            }
            return;
        }
        if (self.format_version != FORMAT_VERSION or
            self.policy_version != POLICY_VERSION or
            self.semantic_identity_format_version == 0 or
            digestIsZero(self.semantic_digest) or
            digestIsZero(self.frame_plan_digest) or
            digestIsZero(self.protocol_digest) or
            self.relations.len == 0 or self.events.len < self.relations.len)
        {
            return error.InvalidProtocolShape;
        }

        var power_cursor: usize = 0;
        for (self.relations, 0..) |relation, relation_index| {
            if (relation_index != 0 and
                types.idIndex(relation.function) <=
                    types.idIndex(self.relations[relation_index - 1].function))
            {
                return error.InvalidRelation;
            }
            if (@intFromEnum(relation.relation) != types.idIndex(relation.function) or
                relation.tuple_arity == 0 or
                relation.tuple_arity > frames.MAX_ACTIVATION_ARITY or
                relation.alpha_powers.start != power_cursor or
                digestIsZero(relation.relation_digest))
            {
                return error.InvalidRelation;
            }
            try validateChallengePair(relation.z, relation.alpha);
            const powers = rangeSlice(QM31, relation.alpha_powers, self.alpha_powers) orelse
                return error.InvalidRange;
            if (powers.len != relation.tuple_arity)
                return error.InvalidRelation;
            var expected = QM31.one();
            for (powers) |power| {
                if (!power.eql(expected)) return error.InvalidRelation;
                expected = expected.mul(relation.alpha);
            }
            for (self.relations[0..relation_index]) |prior| {
                if (std.mem.eql(u8, &prior.relation_digest, &relation.relation_digest))
                    return error.DuplicateRelationIdentity;
                if (prior.z.eql(relation.z) or prior.z.eql(relation.alpha) or
                    prior.alpha.eql(relation.z) or prior.alpha.eql(relation.alpha))
                {
                    return error.DuplicateChallenge;
                }
            }
            power_cursor += powers.len;
        }
        if (power_cursor != self.alpha_powers.len) return error.InvalidRange;

        var tuple_cursor: usize = 0;
        var previous_call: ?usize = null;
        for (self.events, 0..) |event, event_index| {
            if (event.relation_index >= self.relations.len or
                event.tuple.start != tuple_cursor)
            {
                return error.InvalidEvent;
            }
            const relation = self.relations[event.relation_index];
            if (event.callee != relation.function)
                return error.InvalidEvent;
            const tuple = rangeSlice(types.ValueId, event.tuple, self.tuple_values) orelse
                return error.InvalidRange;
            if (tuple.len != relation.tuple_arity) return error.InvalidEvent;

            if (event_index < self.relations.len) {
                if (event_index != event.relation_index or
                    event.kind != .callee_consume or event.role != .consume or
                    event.weight != .callee_enabler or
                    event.owner != event.callee or event.call != null)
                {
                    return error.InvalidEvent;
                }
            } else switch (event.kind) {
                .caller_emit => {
                    if (event.role != .emit or event.weight != .caller_enabler or
                        event.owner == null or event.call == null)
                    {
                        return error.InvalidEvent;
                    }
                },
                .public_emit => {
                    if (event.role != .emit or event.weight != .public_multiplicity or
                        event.owner != null or event.call == null)
                    {
                        return error.InvalidEvent;
                    }
                },
                .callee_consume => return error.InvalidEvent,
            }
            if (event.call) |call_id| {
                const call_index = types.idIndex(call_id);
                if (previous_call != null and call_index <= previous_call.?)
                    return error.InvalidEvent;
                previous_call = call_index;
            }
            tuple_cursor += tuple.len;
        }
        if (tuple_cursor != self.tuple_values.len) return error.InvalidRange;
        const actual_digest = hashProtocol(self);
        if (!std.mem.eql(u8, &actual_digest, &self.protocol_digest))
            return error.DigestMismatch;
    }

    /// Cold authentication against the complete logical arena and sealed frame
    /// plan. Challenges are already authenticated by `protocol_digest`; their
    /// transcript is replayed independently by prover and verifier.
    pub fn validateAgainst(
        self: *const OwnedProtocol,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        plan: *const frames.OwnedPlan,
    ) ValidationError!void {
        try self.validate();
        try plan.validateAgainst(allocator, arena);
        const should_activate = plan.body_ownership_version != 0 and
            requiredRelationCount(plan) != 0;
        if (self.active != should_activate) return error.InvalidPlanBinding;
        if (!self.active) return;
        try validateOwnedAuthority(arena, plan);
        if (self.semantic_identity_format_version !=
            plan.semantic_identity_format_version or
            !std.mem.eql(u8, &self.semantic_digest, &plan.semantic_digest) or
            !std.mem.eql(u8, &self.frame_plan_digest, &plan.plan_digest) or
            !descriptorsMatchPlan(self, plan))
        {
            return error.InvalidPlanBinding;
        }
    }

    pub fn prepare(self: *const OwnedProtocol) ValidationError!PreparedProtocol {
        try self.validate();
        return .{
            .active = self.active,
            .protocol_digest = self.protocol_digest,
            .relations = self.relations,
            .alpha_powers = self.alpha_powers,
            .events = self.events,
            .tuple_values = self.tuple_values,
        };
    }
};

pub const PreparedProtocol = struct {
    active: bool,
    protocol_digest: Digest,
    relations: []const RelationDescriptor,
    alpha_powers: []const QM31,
    events: []const EventDescriptor,
    tuple_values: []const types.ValueId,

    pub fn tupleIds(
        self: *const PreparedProtocol,
        event_index: usize,
    ) ?[]const types.ValueId {
        if (event_index >= self.events.len) return null;
        return rangeSlice(types.ValueId, self.events[event_index].tuple, self.tuple_values);
    }

    pub fn scratchLen(_: *const PreparedProtocol, row_count: usize) usize {
        return row_count;
    }

    pub fn claimScratchLen(self: *const PreparedProtocol) usize {
        return self.relations.len;
    }

    pub fn publicRootCount(self: *const PreparedProtocol) usize {
        var count: usize = 0;
        for (self.events) |event| {
            if (event.kind == .public_emit) count += 1;
        }
        return count;
    }

    /// Evaluate exact live LogUp terms and claims with no allocation or hash
    /// work. All structural and alias checks precede scratch writes. A failed
    /// value-canonicity check or batch inversion may modify the two scratch
    /// slices, but row pairs and claims remain untouched until every
    /// denominator is valid.
    pub fn evaluateInto(
        self: *const PreparedProtocol,
        batches: []const EventBatch,
        rows: []const ActivationRow,
        values: []const M31,
        denominators: []QM31,
        inverses: []QM31,
        row_pairs: []logup.RowPair,
        event_claims: []QM31,
        relation_claims: []QM31,
    ) EvaluateError!void {
        try preflightEvaluation(
            self,
            batches,
            rows,
            values,
            denominators,
            inverses,
            row_pairs,
            event_claims,
            relation_claims,
        );
        if (!self.active) return;

        for (batches) |batch| {
            const event = self.events[batch.event_index];
            const relation = self.relations[event.relation_index];
            const powers = rangeSlice(
                QM31,
                relation.alpha_powers,
                self.alpha_powers,
            ).?;
            const batch_rows = rangeSlice(ActivationRow, batch.rows, rows).?;
            for (batch_rows, @as(usize, batch.rows.start)..) |row, row_index| {
                const tuple = rangeSlice(M31, row.tuple, values).?;
                var combined = QM31.zero();
                for (tuple, powers) |value, power| {
                    if (value.toU32() >= fields.m31.Modulus)
                        return error.NonCanonicalValue;
                    combined = combined.add(power.mulM31(value));
                }
                denominators[row_index] = combined.sub(relation.z);
            }
        }
        fields.batchInverseInPlace(QM31, denominators, inverses) catch
            return error.DenominatorCollision;

        @memset(event_claims, QM31.zero());
        @memset(relation_claims, QM31.zero());
        for (batches) |batch| {
            const event_index: usize = batch.event_index;
            const event = self.events[event_index];
            const batch_rows = rangeSlice(ActivationRow, batch.rows, rows).?;
            for (batch_rows, @as(usize, batch.rows.start)..) |row, row_index| {
                var numerator = QM31.fromBase(row.multiplicity);
                if (event.role == .consume) numerator = numerator.neg();
                row_pairs[row_index] = logup.RowPair.single(
                    numerator,
                    denominators[row_index],
                );
                const term = numerator.mul(inverses[row_index]);
                event_claims[event_index] = event_claims[event_index].add(term);
                relation_claims[event.relation_index] =
                    relation_claims[event.relation_index].add(term);
            }
        }
    }

    /// Recomputes the per-function projection from event claims. This is the
    /// verifier-side check that prevents offsets between independent function
    /// relations from masquerading as one global zero.
    pub fn validateClaimProjection(
        self: *const PreparedProtocol,
        event_claims: []const QM31,
        relation_claims: []const QM31,
    ) EvaluateError!void {
        if (event_claims.len != self.events.len or
            relation_claims.len != self.relations.len)
        {
            return error.InvalidBatchShape;
        }
        for (relation_claims, 0..) |claimed, relation_index| {
            var expected = QM31.zero();
            for (self.events, event_claims) |event, event_claim| {
                if (event.relation_index == relation_index)
                    expected = expected.add(event_claim);
            }
            if (!claimed.eql(expected)) return error.ClaimProjectionMismatch;
        }
    }

    pub fn verifyClosed(
        self: *const PreparedProtocol,
        relation_claims: []const QM31,
    ) EvaluateError!void {
        if (relation_claims.len != self.relations.len)
            return error.InvalidBatchShape;
        for (relation_claims) |claim| {
            if (!claim.isZero()) return error.UnbalancedRelation;
        }
    }

    /// Recompute every public event from verifier-owned statement values,
    /// verify every independently challenged function relation, then extend
    /// the claim-phase transcript. `relation_scratch` is caller-owned and
    /// makes verification O(public fields + events + relations), allocation-
    /// free. The channel is staged, so malformed claims or aliases leave it
    /// byte-for-byte unchanged. Inactive protocols are a literal no-op.
    pub fn mixClaims(
        self: *const PreparedProtocol,
        channel: anytype,
        event_claims: []const QM31,
        public_roots: []const PublicRoot,
        public_values: []const M31,
        relation_scratch: []QM31,
    ) EvaluateError!void {
        if (!self.active) {
            if (event_claims.len != 0 or public_roots.len != 0 or
                public_values.len != 0 or relation_scratch.len != 0)
            {
                return error.InvalidBatchShape;
            }
            return;
        }
        if (event_claims.len != self.events.len or
            public_roots.len != self.publicRootCount() or
            relation_scratch.len != self.relations.len)
        {
            return error.InvalidBatchShape;
        }
        var public_cursor: usize = 0;
        var value_cursor: usize = 0;
        var public_coefficient_total: u64 = 0;
        for (self.events, 0..) |event, event_index| {
            if (event.kind != .public_emit) continue;
            if (public_cursor >= public_roots.len) return error.InvalidPublicRoot;
            const root = public_roots[public_cursor];
            if (root.event_index != event_index or root.tuple.start != value_cursor or
                root.multiplicity == 0 or
                root.multiplicity >= SOURCE_COEFFICIENT_BOUND_EXCLUSIVE)
            {
                return error.InvalidPublicRoot;
            }
            const tuple = rangeSlice(M31, root.tuple, public_values) orelse
                return error.InvalidRange;
            if (tuple.len != self.relations[event.relation_index].tuple_arity)
                return error.InvalidPublicRoot;
            public_coefficient_total = std.math.add(
                u64,
                public_coefficient_total,
                @as(u64, root.multiplicity),
            ) catch return error.CoefficientBoundExceeded;
            if (public_coefficient_total >=
                @as(u64, SOURCE_COEFFICIENT_BOUND_EXCLUSIVE))
            {
                return error.CoefficientBoundExceeded;
            }
            value_cursor += tuple.len;
            public_cursor += 1;
        }
        if (public_cursor != public_roots.len or value_cursor != public_values.len)
            return error.InvalidPublicRoot;

        const claim_ranges = [_]?AddressRange{
            try sliceAddress(QM31, event_claims),
            try sliceAddress(PublicRoot, public_roots),
            try sliceAddress(M31, public_values),
            try sliceAddress(QM31, relation_scratch),
            try sliceAddress(RelationDescriptor, self.relations),
            try sliceAddress(QM31, self.alpha_powers),
            try sliceAddress(EventDescriptor, self.events),
            try sliceAddress(types.ValueId, self.tuple_values),
            try objectAddress(self),
            try objectAddress(channel),
        };
        for (claim_ranges, 0..) |candidate, index| {
            const present = candidate orelse continue;
            for (claim_ranges[0..index]) |prior| {
                if (prior != null and present.overlaps(prior.?))
                    return error.AliasedBuffer;
            }
        }

        public_cursor = 0;
        for (self.events, event_claims, 0..) |event, claim, event_index| {
            if (!qm31IsCanonical(claim)) return error.NonCanonicalClaim;
            if (event.kind != .public_emit) continue;
            const root = public_roots[public_cursor];
            const tuple = rangeSlice(M31, root.tuple, public_values).?;
            const relation = self.relations[event.relation_index];
            const powers = rangeSlice(
                QM31,
                relation.alpha_powers,
                self.alpha_powers,
            ).?;
            var combined = QM31.zero();
            for (tuple, powers) |value, power| {
                if (value.toU32() >= fields.m31.Modulus)
                    return error.NonCanonicalValue;
                combined = combined.add(power.mulM31(value));
            }
            const denominator = combined.sub(relation.z);
            const inverse = denominator.inv() catch
                return error.DenominatorCollision;
            const expected = QM31.fromBase(
                M31.fromCanonical(root.multiplicity),
            ).mul(inverse);
            if (!claim.eql(expected)) return error.PublicClaimMismatch;
            std.debug.assert(root.event_index == event_index);
            public_cursor += 1;
        }

        @memset(relation_scratch, QM31.zero());
        for (self.events, event_claims) |event, claim| {
            relation_scratch[event.relation_index] =
                relation_scratch[event.relation_index].add(claim);
        }
        for (relation_scratch) |claim| {
            if (!claim.isZero()) return error.UnbalancedRelation;
        }

        var staged_channel = channel.*;
        staged_channel.mixU64(CLAIM_DOMAIN_TAG);
        mixDigest(&staged_channel, self.protocol_digest);
        staged_channel.mixU64(@intCast(event_claims.len));
        staged_channel.mixFelts(event_claims);
        channel.* = staged_channel;
    }
};

/// Cold prover/verifier-common compilation and challenge derivation. `channel`
/// is a mutable pointer to copyable transcript state implementing `mixU64`,
/// `mixU32s`, and allocating `drawSecureFelts`. It is copied and committed only
/// after every allocation, ownership check, challenge-collision check, and
/// protocol validation succeeds.
pub fn compileAndDraw(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    plan: *const frames.OwnedPlan,
    channel: anytype,
) !OwnedProtocol {
    return authority_impl.compileAndDraw(@This(), allocator, arena, plan, channel);
}

fn validateOwnedAuthority(
    arena: *const ir.Arena,
    plan: *const frames.OwnedPlan,
) ValidationError!void {
    return authority_impl.validateOwnedAuthority(@This(), arena, plan);
}

fn descriptorsMatchPlan(
    protocol: *const OwnedProtocol,
    plan: *const frames.OwnedPlan,
) bool {
    return authority_impl.descriptorsMatchPlan(@This(), protocol, plan);
}
fn preflightEvaluation(
    prepared: *const PreparedProtocol,
    batches: []const EventBatch,
    rows: []const ActivationRow,
    values: []const M31,
    denominators: []QM31,
    inverses: []QM31,
    row_pairs: []logup.RowPair,
    event_claims: []QM31,
    relation_claims: []QM31,
) EvaluateError!void {
    return preflight_impl.preflightEvaluation(
        @This(),
        prepared,
        batches,
        rows,
        values,
        denominators,
        inverses,
        row_pairs,
        event_claims,
        relation_claims,
    );
}
fn requiredRelationCount(plan: *const frames.OwnedPlan) usize {
    return authority_impl.requiredRelationCount(plan);
}
fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        word.* = std.mem.readInt(u32, digest[4 * index ..][0..4], .little);
    }
    channel.mixU32s(&words);
}

fn hashProtocol(protocol: *const OwnedProtocol) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, protocol.format_version);
    hashInt(&hash, u16, protocol.policy_version);
    hashInt(&hash, u64, degreeCertificateWord());
    hashInt(&hash, u32, SOURCE_COEFFICIENT_BOUND_EXCLUSIVE);
    hashInt(&hash, u16, protocol.semantic_identity_format_version);
    hash.update(&protocol.semantic_digest);
    hash.update(&protocol.frame_plan_digest);
    hashInt(&hash, u32, @intCast(protocol.relations.len));
    hashInt(&hash, u32, @intCast(protocol.alpha_powers.len));
    hashInt(&hash, u32, @intCast(protocol.events.len));
    hashInt(&hash, u32, @intCast(protocol.tuple_values.len));
    for (protocol.relations) |relation| {
        hashInt(&hash, u32, @intFromEnum(relation.function));
        hashInt(&hash, u32, @intFromEnum(relation.relation));
        hashInt(&hash, u16, relation.tuple_arity);
        hashRange(&hash, relation.alpha_powers);
        hash.update(&relation.relation_digest);
        hashQM31(&hash, relation.z);
        hashQM31(&hash, relation.alpha);
    }
    for (protocol.alpha_powers) |power| hashQM31(&hash, power);
    for (protocol.events) |event| {
        hashInt(&hash, u8, @intFromEnum(event.kind));
        hashInt(&hash, u8, @intFromEnum(event.role));
        hashInt(&hash, u8, @intFromEnum(event.weight));
        hashInt(&hash, u32, event.relation_index);
        hashInt(&hash, u32, @intFromEnum(event.callee));
        hashOptionalId(types.FunctionId, &hash, event.owner);
        hashOptionalId(types.CallId, &hash, event.call);
        hashRange(&hash, event.tuple);
    }
    for (protocol.tuple_values) |value|
        hashInt(&hash, u32, @intFromEnum(value));
    return hash.finalResult();
}

fn hashRange(hash: *Sha256, range: IndexRange) void {
    hashInt(hash, u32, range.start);
    hashInt(hash, u32, range.len);
}

fn hashQM31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashOptionalId(
    comptime Id: type,
    hash: *Sha256,
    id: ?Id,
) void {
    if (id) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u32, @intFromEnum(present));
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn degreeCertificateWord() u64 {
    comptime {
        if (DEGREE_CERTIFICATE.numerator > std.math.maxInt(u8) or
            DEGREE_CERTIFICATE.denominator > std.math.maxInt(u8) or
            DEGREE_CERTIFICATE.row_window > std.math.maxInt(u8) or
            DEGREE_CERTIFICATE.final > std.math.maxInt(u8) or
            DEGREE_CERTIFICATE.maximum > std.math.maxInt(u8))
        {
            @compileError("function activation degree certificate exceeds wire width");
        }
    }
    return (@as(u64, DEGREE_CERTIFICATE.numerator) << 40) |
        (@as(u64, DEGREE_CERTIFICATE.denominator) << 32) |
        (@as(u64, DEGREE_CERTIFICATE.row_window) << 24) |
        (@as(u64, DEGREE_CERTIFICATE.final) << 16) |
        (@as(u64, DEGREE_CERTIFICATE.maximum) << 8) |
        DEGREE_CERTIFICATE.quotient_expansion_bits;
}

fn rangeSlice(
    comptime T: type,
    range: IndexRange,
    values: []const T,
) ?[]const T {
    const start: usize = range.start;
    const len: usize = range.len;
    const end = std.math.add(usize, start, len) catch return null;
    if (end > values.len) return null;
    return values[start..end];
}

fn rangeSliceMut(comptime T: type, range: IndexRange, values: []T) ?[]T {
    const start: usize = range.start;
    const len: usize = range.len;
    const end = std.math.add(usize, start, len) catch return null;
    if (end > values.len) return null;
    return values[start..end];
}

fn emptyMutable(comptime T: type) []T {
    return @constCast((&[_]T{})[0..]);
}

fn digestIsZero(digest: Digest) bool {
    return std.mem.allEqual(u8, &digest, 0);
}

fn qm31IsCanonical(value: QM31) bool {
    for (value.toM31Array()) |limb| {
        if (limb.toU32() >= fields.m31.Modulus) return false;
    }
    return true;
}

fn validateChallengePair(z: QM31, alpha: QM31) ValidationError!void {
    if (!qm31IsCanonical(z) or !qm31IsCanonical(alpha))
        return error.NonCanonicalChallenge;
    if (alpha.isZero()) return error.DegenerateChallenge;
    if (z.eql(alpha)) return error.DuplicateChallenge;
}

/// Explicit cold-authority hooks used by the implementation shard. These are
/// not a second protocol surface: all types and constants remain owned here.
pub const AuthorityHooks = struct {
    pub const degreeCertificateWord = activationDegreeCertificateWord;
    pub const hashProtocol = activationHashProtocol;
    pub const rangeSlice = activationRangeSlice;
    pub const rangeSliceMut = activationRangeSliceMut;
    pub const validateChallengePair = activationValidateChallengePair;
};

/// Narrow alias-safety hook for the allocation-free preflight shard.
pub const PreflightHooks = struct {
    pub const rangeSlice = activationRangeSlice;
};

const activationDegreeCertificateWord = degreeCertificateWord;
const activationHashProtocol = hashProtocol;
const activationRangeSlice = rangeSlice;
const activationRangeSliceMut = rangeSliceMut;
const activationValidateChallengePair = validateChallengePair;
