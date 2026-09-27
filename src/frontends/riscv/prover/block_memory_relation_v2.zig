//! Block-only memory buses. The v1 universal registry and its 47 challenge
//! draws are frozen; these three relations are drawn only after that prefix in
//! the sealed v2 block transcript. This module defines tuple/challenge/claim
//! semantics. It does not by itself authenticate an interaction AIR claim.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const universal = @import("../recursion/air/universal_challenges.zig");
const relation = @import("../air/relation_challenges.zig");
const manifest = @import("block_commitment_manifest.zig");
const source_seal = @import("block_memory_source_seal_v2.zig");
const memory = @import("../air/block/memory_transition.zig");
const canonical = @import("../recursion/air/universal_provider_relations.zig");
const schema_registry = @import("../air/lang/relation.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const TRANSITION_ARITY: usize = 21;
pub const LINK_ARITY: usize = 25;
pub const INITIAL_ARITY: usize = 9;
pub const TRANSCRIPT_TAG: u32 = 0x42324d52; // B2MR
pub const TransitionTuple = [TRANSITION_ARITY]M31;
pub const LinkTuple = [LINK_ARITY]M31;
pub const InitialTuple = [INITIAL_ARITY]M31;

/// Versioned identity for block-only relation semantics. The manifest binds
/// this ID separately from the frozen 47-relation universal order digest.
pub fn relationAbiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/riscv/block-memory-relations/v2\x00");
    hash.update(&schema_registry.registryOrderDigest());
    hash.update(&[_]u8{ @intCast(FORMAT_VERSION), @intCast(TRANSITION_ARITY), @intCast(LINK_ARITY), @intCast(INITIAL_ARITY) });
    var tag: [4]u8 = undefined;
    std.mem.writeInt(u32, &tag, TRANSCRIPT_TAG, .little);
    hash.update(&tag);
    hash.update("transition:space-bit,address-le4,clock-le8,before-le4,after-le4\x00");
    hash.update("link:ordinal-le8,space-bit,address-le4,clock-le8,after-le4\x00");
    hash.update("initial:space-bit,address-le4,before-le4\x00");
    hash.update("source-seal:B2SS-v3,register-mask,execution-count,memory-count,source-roster,range-shard-roster,first-round-roots-before-universal-prefix\x00");
    hash.update("execution=emit,sorted=consume,link-post=emit,link-previous=consume,initial-state=emit,first-touch=consume;alpha-powers-minus-z\x00");
    return hash.finalResult();
}

/// The global ordinal is the zero-based position in the complete sorted
/// stream, independent of the component instance that contains this row.
pub const LinkPoint = struct {
    ordinal: u64,
    space: u1,
    address: u32,
    clock: u64,
    value: u32,
};

pub const Challenges = struct {
    transition: relation.RelationElements(TRANSITION_ARITY),
    link: relation.RelationElements(LINK_ARITY),
    initial: relation.RelationElements(INITIAL_ARITY),
    /// A verifier can replay this exact suffix from the sealed manifest. The
    /// returned universal bundle proves that the 47-draw prefix was consumed
    /// in its original order before either block-specific challenge.
    universal_prefix: universal.UniversalRelations,

    /// Production block proofs pass `SourceSeal`; bare manifest `Sealed` is
    /// retained only for isolated experimental quotient tests.
    pub fn draw(allocator: std.mem.Allocator, sealed: anytype) !Challenges {
        var channel = sealed.sharedChannel();
        return drawFromChannel(allocator, &channel);
    }

    /// Caller-owned transcript cursor for a joint PCS proof. The caller must
    /// first absorb the complete v3 first-round root roster; this function
    /// consumes the frozen universal prefix exactly once, then the block bus.
    pub fn drawFromChannel(allocator: std.mem.Allocator, channel: anytype) !Challenges {
        const prefix = try universal.UniversalRelations.draw(allocator, channel);
        channel.mixU32s(&.{ TRANSCRIPT_TAG, FORMAT_VERSION, TRANSITION_ARITY, LINK_ARITY, INITIAL_ARITY });
        const transition_z = channel.drawSecureFelt();
        const transition_alpha = channel.drawSecureFelt();
        const link_z = channel.drawSecureFelt();
        const link_alpha = channel.drawSecureFelt();
        const initial_z = channel.drawSecureFelt();
        const initial_alpha = channel.drawSecureFelt();
        return .{
            .transition = .init(transition_z, transition_alpha),
            .link = .init(link_z, link_alpha),
            .initial = .init(initial_z, initial_alpha),
            .universal_prefix = prefix,
        };
    }

    pub fn validate(self: *const Challenges, allocator: std.mem.Allocator, sealed: anytype) !void {
        const expected = try draw(allocator, sealed);
        try self.universal_prefix.validate();
        if (!sameElement(TRANSITION_ARITY, &self.transition, &expected.transition) or
            !sameElement(LINK_ARITY, &self.link, &expected.link) or
            !sameElement(INITIAL_ARITY, &self.initial, &expected.initial)) return error.BlockMemoryChallengeMismatch;
        for (self.universal_prefix.elements, expected.universal_prefix.elements) |actual, wanted| {
            if (!actual.z.eql(wanted.z) or !actual.alpha.eql(wanted.alpha) or actual.arity != wanted.arity)
                return error.BlockMemoryChallengeMismatch;
            for (actual.alpha_powers[0..actual.arity], wanted.alpha_powers[0..wanted.arity]) |present, required| {
                if (!present.eql(required)) return error.BlockMemoryChallengeMismatch;
            }
        }
    }
};

/// Every coordinate is a canonical byte (except space, which is a bit).
/// Thus the map is injective even when clock exceeds the M31 modulus.
pub fn transitionTuple(value: memory.Transition) TransitionTuple {
    var tuple: TransitionTuple = undefined;
    tuple[0] = M31.fromCanonical(value.space);
    putBytes(tuple[1..5], value.address);
    putBytes(tuple[5..13], value.clock);
    putBytes(tuple[13..17], value.before);
    putBytes(tuple[17..21], value.after);
    return tuple;
}

/// One row emits its post-state at `ordinal`; the succeeding row consumes
/// exactly that tuple, including across independently sized instances.
pub fn linkTuple(value: LinkPoint) LinkTuple {
    var tuple: LinkTuple = undefined;
    putBytes(tuple[0..8], value.ordinal);
    tuple[8] = M31.fromCanonical(value.space);
    putBytes(tuple[9..13], value.address);
    putBytes(tuple[13..21], value.clock);
    putBytes(tuple[21..25], value.value);
    return tuple;
}

/// First-touch value must come from a separately proved initial-state table.
pub fn initialTuple(value: memory.Transition) InitialTuple {
    var tuple: InitialTuple = undefined;
    tuple[0] = M31.fromCanonical(value.space);
    putBytes(tuple[1..5], value.address);
    putBytes(tuple[5..9], value.before);
    return tuple;
}

pub fn decodeInitialTuple(tuple: InitialTuple) !struct { space: u1, address: u32, value: u32 } {
    if (tuple[0].toU32() > 1) return error.InvalidBlockMemoryTuple;
    return .{ .space = @intCast(tuple[0].toU32()), .address = @intCast(try readBytes(tuple[1..5])), .value = @intCast(try readBytes(tuple[5..9])) };
}

/// Canonical re-decoding is useful at host admission. AIR callers must prove
/// byte range constraints on their committed source columns independently.
pub fn decodeTransitionTuple(tuple: TransitionTuple) !memory.Transition {
    if (tuple[0].toU32() > 1) return error.InvalidBlockMemoryTuple;
    return .{
        .space = @intCast(tuple[0].toU32()),
        .address = @intCast(try readBytes(tuple[1..5])),
        .clock = try readBytes(tuple[5..13]),
        .before = @intCast(try readBytes(tuple[13..17])),
        .after = @intCast(try readBytes(tuple[17..21])),
    };
}

pub fn decodeLinkTuple(tuple: LinkTuple) !LinkPoint {
    if (tuple[8].toU32() > 1) return error.InvalidBlockMemoryTuple;
    return .{
        .ordinal = try readBytes(tuple[0..8]),
        .space = @intCast(tuple[8].toU32()),
        .address = @intCast(try readBytes(tuple[9..13])),
        .clock = try readBytes(tuple[13..21]),
        .value = @intCast(try readBytes(tuple[21..25])),
    };
}

/// This only computes native witness-side sums. A proof verifier must first
/// authenticate the corresponding committed interaction AIR claims; callers
/// cannot use `closed` as a substitute for that check.
pub const WitnessSums = struct {
    transition: QM31 = QM31.zero(),
    link: QM31 = QM31.zero(),
    initial: QM31 = QM31.zero(),

    pub fn addTransition(self: *WitnessSums, challenges: *const Challenges, value: memory.Transition, role: enum { execution, sorted }) !void {
        const inverse = try challenges.transition.combineBase(transitionTuple(value)).inv();
        self.transition = self.transition.add(if (role == .execution) inverse else inverse.neg());
    }

    pub fn addLink(self: *WitnessSums, challenges: *const Challenges, value: LinkPoint, role: enum { emit, consume }) !void {
        const inverse = try challenges.link.combineBase(linkTuple(value)).inv();
        self.link = self.link.add(if (role == .emit) inverse else inverse.neg());
    }

    pub fn addInitial(self: *WitnessSums, challenges: *const Challenges, value: InitialTuple, role: enum { emit, consume }) !void {
        _ = try decodeInitialTuple(value);
        const inverse = try challenges.initial.combineBase(value).inv();
        self.initial = self.initial.add(if (role == .emit) inverse else inverse.neg());
    }

    pub fn add(self: *WitnessSums, other: WitnessSums) void {
        self.transition = self.transition.add(other.transition);
        self.link = self.link.add(other.link);
        self.initial = self.initial.add(other.initial);
    }

    pub fn closed(self: WitnessSums) bool {
        return self.transition.eql(QM31.zero()) and self.link.eql(QM31.zero()) and self.initial.eql(QM31.zero());
    }
};

/// Claimed sums for one separately proved block component. The claim is
/// verifier input, not authority: its three values must first be checked by the
/// component's committed interaction trace and AIR quotient.
pub const ComponentClaim = struct {
    instance_index: u32,
    transition_sum: QM31,
    link_sum: QM31,
    initial_sum: QM31 = QM31.zero(),

    pub fn total(self: ComponentClaim) QM31 {
        return self.transition_sum.add(self.link_sum).add(self.initial_sum);
    }

    pub fn validateCanonical(self: ComponentClaim) !void {
        if (!canonical.secureIsCanonical(&self.transition_sum) or
            !canonical.secureIsCanonical(&self.link_sum) or
            !canonical.secureIsCanonical(&self.initial_sum)) return error.InvalidBlockMemoryClaim;
    }

    /// Mix before the interaction PCS commitment, in exact manifest order.
    pub fn mixInto(self: ComponentClaim, channel: anytype) !void {
        try self.validateCanonical();
        channel.mixU32s(&.{ TRANSCRIPT_TAG, FORMAT_VERSION, self.instance_index });
        for (self.transition_sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        for (self.link_sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        for (self.initial_sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    }
};

/// Logical row inputs to the v2 interaction writer. The AIR must derive these
/// tuples and selectors from committed main/fixed columns; the writer cannot
/// establish that provenance. `link_emit` is false at the global final row and
/// `link_consume` is false at the global first row.
pub const EventRow = struct {
    active: bool,
    transition: TransitionTuple,
    link_emit: bool = false,
    emitted: LinkTuple = @splat(M31.zero()),
    link_consume: bool = false,
    consumed: LinkTuple = @splat(M31.zero()),
    initial_request: bool = false,
    initial: InitialTuple = @splat(M31.zero()),
};

pub const InteractionColumns = struct {
    /// Three QM31 columns, in the framework's four-coordinate storage order.
    /// Column 0 is transition, column 1 initial request, and column 2 is the
    /// shifted cross-row prefix of transition, initial, and link fractions.
    columns: [12][]M31,
    storage: []M31,
    claim: ComponentClaim,

    pub fn deinit(self: *InteractionColumns, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }
};

pub const RowRole = enum { execution, sorted };

/// Point-evaluation inputs for the v2 LogUp quotient. Every field here must
/// be read from the PCS-opened fixed/main/interaction columns by the generic
/// prover and verifier adapters. In particular `first` and `domain_last`
/// are fixed-row selectors, not prover-chosen booleans. `domain_last` pins the
/// final padded domain row, which can follow the last active memory event.
pub const InteractionPoint = struct {
    active: QM31,
    transition: [TRANSITION_ARITY]QM31,
    link_emit: QM31,
    emitted: [LINK_ARITY]QM31,
    link_consume: QM31,
    consumed: [LINK_ARITY]QM31,
    initial_request: QM31,
    initial: [INITIAL_ARITY]QM31,
    first: QM31,
    domain_last: QM31,
    transition_column: QM31,
    initial_column: QM31,
    prefix_column: QM31,
    previous_prefix_column: QM31,
};

/// Four polynomial identities for one v2 interaction row. The first three
/// must vanish on the full trace domain; the fourth pins the domain terminal
/// prefix. `active`, link masks and fixed selectors require separate Boolean
/// and geometry constraints from the component's direct AIR.
pub fn interactionConstraints(
    challenges: *const Challenges,
    role: RowRole,
    point: InteractionPoint,
    claim: ComponentClaim,
    trace_size: u32,
) ![4]QM31 {
    if (trace_size == 0) return error.InvalidBlockMemoryInteractionShape;
    const one = QM31.one();
    const transition_raw = challenges.transition.combineSecure(point.transition);
    const transition_den = point.active.mul(transition_raw).add(one.sub(point.active));
    const signed_active = if (role == .execution) point.active else point.active.neg();
    const transition_identity = transition_den.mul(point.transition_column).sub(signed_active);
    const initial_raw = challenges.initial.combineSecure(point.initial);
    const initial_den = point.initial_request.mul(initial_raw).add(one.sub(point.initial_request));
    const initial_identity = initial_den.mul(point.initial_column).add(point.initial_request);
    // Inactive sides have denominator one. Thus they cannot make the link
    // equation vacuous by setting an unused tuple's raw denominator to zero.
    const emitted_raw = challenges.link.combineSecure(point.emitted);
    const consumed_raw = challenges.link.combineSecure(point.consumed);
    const emitted_den = point.link_emit.mul(emitted_raw).add(one.sub(point.link_emit));
    const consumed_den = point.link_consume.mul(consumed_raw).add(one.sub(point.link_consume));
    // The prefix is cyclic on the circle domain. The terminal constraint
    // fixes its final row to zero, so row zero's predecessor is exactly zero
    // without multiplying by a first-row selector. This keeps the link
    // identity at degree five when emit/consume selectors are fixed-linear.
    const previous = point.previous_prefix_column;
    const shift = try claim.total().divM31(M31.fromCanonical(trace_size));
    const link_delta = point.prefix_column.sub(previous).add(shift).sub(point.transition_column).sub(point.initial_column);
    const link_identity = link_delta.mul(emitted_den).mul(consumed_den)
        .sub(point.link_emit.mul(consumed_den))
        .add(point.link_consume.mul(emitted_den));
    const terminal_identity = point.domain_last.mul(point.prefix_column);
    return .{ transition_identity, initial_identity, link_identity, terminal_identity };
}

/// Native v2 interaction columns with the same circle-domain row order and
/// inclusive prefix convention as the pinned framework. These columns become
/// proof authority only when the v2 quotient evaluator constrains their two
/// recurrence equations and the verifier binds the claim before PCS commit.
pub fn generateInteractionColumns(
    allocator: std.mem.Allocator,
    challenges: *const Challenges,
    instance_index: u32,
    role: RowRole,
    rows: []const EventRow,
    log_size: u32,
) !InteractionColumns {
    const Source = struct {
        rows: []const EventRow,
        fn domainSize(self: @This()) usize {
            return self.rows.len;
        }
        fn eventRow(self: @This(), index: usize) EventRow {
            return self.rows[index];
        }
    };
    return generateInteractionFromSource(allocator, challenges, instance_index, role, Source{ .rows = rows }, log_size);
}

/// Streams rows directly from a committed-column trace adapter exposing
/// `domainSize()` and `eventRow(logical_index)`. No row-major tuple slab is
/// retained: the two passes reuse the output interaction columns as scratch.
pub fn generateInteractionFromSource(
    allocator: std.mem.Allocator,
    challenges: *const Challenges,
    instance_index: u32,
    role: RowRole,
    source: anytype,
    log_size: u32,
) !InteractionColumns {
    if (log_size == 0 or log_size > 30) return error.InvalidBlockMemoryInteractionShape;
    const count: usize = @as(usize, 1) << @intCast(log_size);
    if (source.domainSize() != count) return error.InvalidBlockMemoryInteractionShape;
    var storage = try allocator.alloc(M31, count * 12);
    errdefer allocator.free(storage);
    var columns: [12][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = storage[index * count ..][0..count];
    var transition_sum = QM31.zero();
    var link_sum = QM31.zero();
    var initial_sum = QM31.zero();
    // The first pass writes each row's transition and link fraction into the
    // final output slab, while computing the exact claim. No tuple rows are
    // allocated or re-read after this pass.
    for (0..count) |logical_index| {
        const row = source.eventRow(logical_index);
        var transition_term = QM31.zero();
        var link_term = QM31.zero();
        var initial_term = QM31.zero();
        if (!row.active) {
            if (row.link_emit or row.link_consume or row.initial_request) return error.InvalidBlockMemoryInteractionRow;
        } else {
            _ = try decodeTransitionTuple(row.transition);
            transition_term = try challenges.transition.combineBase(row.transition).inv();
            if (role == .sorted) transition_term = transition_term.neg();
            if (row.link_emit) {
                _ = try decodeLinkTuple(row.emitted);
                link_term = link_term.add(try challenges.link.combineBase(row.emitted).inv());
            }
            if (row.link_consume) {
                _ = try decodeLinkTuple(row.consumed);
                link_term = link_term.sub(try challenges.link.combineBase(row.consumed).inv());
            }
            if (row.initial_request) {
                _ = try decodeInitialTuple(row.initial);
                initial_term = (try challenges.initial.combineBase(row.initial).inv()).neg();
            }
        }
        transition_sum = transition_sum.add(transition_term);
        link_sum = link_sum.add(link_term);
        initial_sum = initial_sum.add(initial_term);
        const committed_index = @import("../recursion/air/framework_interaction.zig").committedRow(logical_index, log_size);
        writeSecure(&columns, 0, committed_index, transition_term);
        writeSecure(&columns, 1, committed_index, initial_term);
        writeSecure(&columns, 2, committed_index, link_term);
    }
    const claimed_sum = transition_sum.add(link_sum).add(initial_sum);
    const shift = try claimed_sum.divM31(M31.fromU64(count));
    var prefix = QM31.zero();
    for (0..count) |logical_index| {
        const committed_index = @import("../recursion/air/framework_interaction.zig").committedRow(logical_index, log_size);
        const transition_term = secureAt(&columns, 0, committed_index);
        const initial_term = secureAt(&columns, 1, committed_index);
        const link_term = secureAt(&columns, 2, committed_index);
        prefix = prefix.add(transition_term).add(initial_term).add(link_term).sub(shift);
        writeSecure(&columns, 2, committed_index, prefix);
    }
    if (!prefix.isZero()) return error.InvalidBlockMemoryInteractionPrefix;
    return .{
        .columns = columns,
        .storage = storage,
        .claim = .{ .instance_index = instance_index, .transition_sum = transition_sum, .link_sum = link_sum, .initial_sum = initial_sum },
    };
}

/// Call only after every listed component claim has been independently bound
/// to a successful native/recursive proof under the same sealed manifest.
/// This function checks the algebraic terminal condition and exact census; it
/// does not verify a proof or grant that prerequisite by itself.
pub fn requireClosedAfterProofVerification(
    sealed: manifest.Sealed,
    claims: []const ComponentClaim,
) !void {
    if (claims.len != sealed.instance_count) return error.BlockMemoryClaimCensusMismatch;
    var transition_sum = QM31.zero();
    var link_sum = QM31.zero();
    var initial_sum = QM31.zero();
    for (claims, 0..) |claim, index| {
        try claim.validateCanonical();
        if (claim.instance_index != index) return error.BlockMemoryClaimCensusMismatch;
        transition_sum = transition_sum.add(claim.transition_sum);
        link_sum = link_sum.add(claim.link_sum);
        initial_sum = initial_sum.add(claim.initial_sum);
    }
    if (!transition_sum.isZero() or !link_sum.isZero() or !initial_sum.isZero())
        return error.UnclosedBlockMemoryRelation;
}

fn putBytes(out: []M31, value: u64) void {
    for (out, 0..) |*item, index| item.* = M31.fromCanonical(@as(u8, @truncate(value >> @intCast(index * 8))));
}

fn readBytes(values: []const M31) !u64 {
    var result: u64 = 0;
    for (values, 0..) |value, index| {
        if (value.toU32() > 255) return error.InvalidBlockMemoryTuple;
        result |= @as(u64, value.toU32()) << @intCast(index * 8);
    }
    return result;
}

fn sameElement(comptime arity: usize, lhs: *const relation.RelationElements(arity), rhs: *const relation.RelationElements(arity)) bool {
    if (!lhs.z.eql(rhs.z) or !lhs.alpha.eql(rhs.alpha)) return false;
    for (lhs.alpha_powers, rhs.alpha_powers) |actual, wanted| if (!actual.eql(wanted)) return false;
    return true;
}

fn writeSecure(columns: *[12][]M31, secure_column: usize, row: usize, value: QM31) void {
    for (value.toM31Array(), 0..) |limb, coordinate| columns[secure_column * 4 + coordinate][row] = limb;
}

test "block v2 relation draws only after the unchanged 47 universal challenges" {
    try std.testing.expect(!std.meta.eql(relationAbiId(), schema_registry.registryOrderDigest()));
    const sealed = manifest.Sealed{ .digest = @splat(7), .instance_count = 3 };
    const actual = try Challenges.draw(std.testing.allocator, sealed);
    try actual.validate(std.testing.allocator, sealed);
    var channel = sealed.sharedChannel();
    const original = try universal.UniversalRelations.draw(std.testing.allocator, &channel);
    for (actual.universal_prefix.elements, original.elements) |a, b| {
        try std.testing.expect(a.z.eql(b.z));
        try std.testing.expect(a.alpha.eql(b.alpha));
    }
    var changed = sealed;
    changed.digest[0] ^= 1;
    try std.testing.expectError(error.BlockMemoryChallengeMismatch, actual.validate(std.testing.allocator, changed));
    var forged = actual;
    forged.universal_prefix.elements[0].alpha_powers[0] = QM31.zero();
    try std.testing.expectError(error.BlockMemoryChallengeMismatch, forged.validate(std.testing.allocator, sealed));
}

test "block v2 source roster and register mask bind the universal challenge prefix" {
    const base = manifest.Sealed{ .digest = @splat(21), .instance_count = 1 };
    const first = try source_seal.SourceSeal.init(base, 3, @splat(5));
    const changed_mask = try source_seal.SourceSeal.init(base, 2, @splat(5));
    const changed_roster = try source_seal.SourceSeal.init(base, 3, @splat(6));
    const a = try Challenges.draw(std.testing.allocator, first);
    try a.validate(std.testing.allocator, first);
    const b = try Challenges.draw(std.testing.allocator, changed_mask);
    const c = try Challenges.draw(std.testing.allocator, changed_roster);
    try std.testing.expect(!a.universal_prefix.elements[0].z.eql(b.universal_prefix.elements[0].z));
    try std.testing.expect(!a.universal_prefix.elements[0].z.eql(c.universal_prefix.elements[0].z));
    try std.testing.expectError(error.BlockMemoryChallengeMismatch, a.validate(std.testing.allocator, changed_mask));
}

test "block v2 memory tuple is injective over canonical byte limbs" {
    const source = memory.Transition{ .space = 1, .address = 0xf1234567, .clock = 0xfedcba9876543210, .before = 0x12345678, .after = 0x87654321 };
    const encoded = transitionTuple(source);
    try std.testing.expectEqualDeep(source, try decodeTransitionTuple(encoded));
    var corrupt = encoded;
    corrupt[6] = M31.fromCanonical(256);
    try std.testing.expectError(error.InvalidBlockMemoryTuple, decodeTransitionTuple(corrupt));
    const point = LinkPoint{ .ordinal = std.math.maxInt(u64), .space = 1, .address = source.address, .clock = source.clock, .value = source.after };
    try std.testing.expectEqualDeep(point, try decodeLinkTuple(linkTuple(point)));
}

test "block-v2 all components draw identical buses from bound source seal" {
    const a = std.testing.allocator;
    const base = manifest.Sealed{ .digest = @splat(57), .instance_count = 1 };
    const sealed = try source_seal.SourceSeal.initBound(base, 1, @splat(58), 1, 1, @splat(59), @splat(60));
    const direct = try Challenges.draw(a, sealed);
    var cursor = sealed.sharedChannel();
    const from_cursor = try Challenges.drawFromChannel(a, &cursor);
    try std.testing.expect(sameElement(TRANSITION_ARITY, &direct.transition, &from_cursor.transition));
    try std.testing.expect(sameElement(LINK_ARITY, &direct.link, &from_cursor.link));
    try std.testing.expect(sameElement(INITIAL_ARITY, &direct.initial, &from_cursor.initial));
    try std.testing.expectEqualDeep(direct.universal_prefix, from_cursor.universal_prefix);
    const changed = try source_seal.SourceSeal.initBound(base, 1, @splat(58), 1, 1, @splat(59), @splat(61));
    const other = try Challenges.draw(a, changed);
    try std.testing.expect(!sameElement(TRANSITION_ARITY, &direct.transition, &other.transition));
}

test "native witness-side transition and cross-instance link sums detect altered events" {
    const challenges = try Challenges.draw(std.testing.allocator, manifest.Sealed{ .digest = @splat(11), .instance_count = 2 });
    const value = memory.Transition{ .space = 1, .address = 9, .clock = 17, .before = 5, .after = 8 };
    var sums = WitnessSums{};
    try sums.addTransition(&challenges, value, .execution);
    try sums.addTransition(&challenges, value, .sorted);
    const point = LinkPoint{ .ordinal = 71, .space = value.space, .address = value.address, .clock = value.clock, .value = value.after };
    try sums.addLink(&challenges, point, .emit);
    try sums.addLink(&challenges, point, .consume);
    try std.testing.expect(sums.closed());
    var tampered = value;
    tampered.after ^= 1;
    try sums.addTransition(&challenges, tampered, .execution);
    try std.testing.expect(!sums.closed());
}

test "block relation claim closure rejects missing, reordered and nonzero verified inputs" {
    const sealed = manifest.Sealed{ .digest = @splat(7), .instance_count = 2 };
    const one = QM31.one();
    const a = ComponentClaim{ .instance_index = 0, .transition_sum = one, .link_sum = one.neg() };
    const b = ComponentClaim{ .instance_index = 1, .transition_sum = one.neg(), .link_sum = one };
    try requireClosedAfterProofVerification(sealed, &.{ a, b });
    try std.testing.expectError(error.BlockMemoryClaimCensusMismatch, requireClosedAfterProofVerification(sealed, &.{a}));
    try std.testing.expectError(error.BlockMemoryClaimCensusMismatch, requireClosedAfterProofVerification(sealed, &.{ b, a }));
    var changed = b;
    changed.link_sum = QM31.zero();
    try std.testing.expectError(error.UnclosedBlockMemoryRelation, requireClosedAfterProofVerification(sealed, &.{ a, changed }));
}

test "v2 interaction writer commits two-column framework recurrence and exact claims" {
    const a = std.testing.allocator;
    const challenges = try Challenges.draw(a, manifest.Sealed{ .digest = @splat(12), .instance_count = 2 });
    const transition = memory.Transition{ .space = 1, .address = 7, .clock = 17, .before = 2, .after = 3 };
    const empty = EventRow{ .active = false, .transition = @splat(M31.zero()) };
    const event = EventRow{ .active = true, .transition = transitionTuple(transition) };
    var execution = try generateInteractionColumns(a, &challenges, 0, .execution, &.{ event, empty }, 1);
    defer execution.deinit(a);
    var sorted = try generateInteractionColumns(a, &challenges, 1, .sorted, &.{ event, empty }, 1);
    defer sorted.deinit(a);
    try requireClosedAfterProofVerification(.{ .digest = @splat(12), .instance_count = 2 }, &.{ execution.claim, sorted.claim });
    const first = @import("../recursion/air/framework_interaction.zig").committedRow(0, 1);
    const second = @import("../recursion/air/framework_interaction.zig").committedRow(1, 1);
    const transition_term = try challenges.transition.combineBase(event.transition).inv();
    try std.testing.expect(secureAt(&execution.columns, 0, first).eql(transition_term));
    try std.testing.expect(secureAt(&execution.columns, 2, second).isZero());
    try std.testing.expect(secureAt(&sorted.columns, 0, first).eql(transition_term.neg()));
}

test "v2 link claim crosses independently sized sorted instances without padding leaves" {
    const a = std.testing.allocator;
    const sealed = manifest.Sealed{ .digest = @splat(13), .instance_count = 2 };
    const challenges = try Challenges.draw(a, sealed);
    const first = memory.Transition{ .space = 1, .address = 7, .clock = 17, .before = 2, .after = 3 };
    const second = memory.Transition{ .space = 1, .address = 7, .clock = 29, .before = 3, .after = 5 };
    const boundary = linkTuple(.{ .ordinal = 0, .space = first.space, .address = first.address, .clock = first.clock, .value = first.after });
    const empty = EventRow{ .active = false, .transition = @splat(M31.zero()) };
    var left = try generateInteractionColumns(a, &challenges, 0, .sorted, &.{ .{ .active = true, .transition = transitionTuple(first), .link_emit = true, .emitted = boundary }, empty }, 1);
    defer left.deinit(a);
    var right = try generateInteractionColumns(a, &challenges, 1, .sorted, &.{ .{ .active = true, .transition = transitionTuple(second), .link_consume = true, .consumed = boundary }, empty }, 1);
    defer right.deinit(a);
    try std.testing.expect(left.claim.link_sum.add(right.claim.link_sum).isZero());
    var forged = boundary;
    forged[21] = M31.fromCanonical(9);
    var altered = try generateInteractionColumns(a, &challenges, 1, .sorted, &.{ .{ .active = true, .transition = transitionTuple(second), .link_consume = true, .consumed = forged }, empty }, 1);
    defer altered.deinit(a);
    try std.testing.expect(!left.claim.link_sum.add(altered.claim.link_sum).isZero());
}

fn secureAt(columns: *const [12][]M31, secure_column: usize, row: usize) QM31 {
    return QM31.fromM31Array(.{
        columns[secure_column * 4][row],
        columns[secure_column * 4 + 1][row],
        columns[secure_column * 4 + 2][row],
        columns[secure_column * 4 + 3][row],
    });
}

test "v2 polynomial interaction identities accept committed rows and reject tampering" {
    const a = std.testing.allocator;
    const challenges = try Challenges.draw(a, manifest.Sealed{ .digest = @splat(14), .instance_count = 1 });
    const value = memory.Transition{ .space = 0, .address = 10, .clock = 40, .before = 7, .after = 9 };
    const event = EventRow{ .active = true, .transition = transitionTuple(value) };
    const empty = EventRow{ .active = false, .transition = @splat(M31.zero()) };
    var generated = try generateInteractionColumns(a, &challenges, 0, .execution, &.{ event, empty }, 1);
    defer generated.deinit(a);
    const row0 = @import("../recursion/air/framework_interaction.zig").committedRow(0, 1);
    const row1 = @import("../recursion/air/framework_interaction.zig").committedRow(1, 1);
    var first = pointFromEvent(event);
    first.first = QM31.one();
    first.transition_column = secureAt(&generated.columns, 0, row0);
    first.initial_column = secureAt(&generated.columns, 1, row0);
    first.prefix_column = secureAt(&generated.columns, 2, row0);
    first.previous_prefix_column = secureAt(&generated.columns, 2, row1);
    for (try interactionConstraints(&challenges, .execution, first, generated.claim, 2)) |constraint| try std.testing.expect(constraint.isZero());
    var final = pointFromEvent(empty);
    final.domain_last = QM31.one();
    final.transition_column = secureAt(&generated.columns, 0, row1);
    final.initial_column = secureAt(&generated.columns, 1, row1);
    final.prefix_column = secureAt(&generated.columns, 2, row1);
    final.previous_prefix_column = secureAt(&generated.columns, 2, row0);
    for (try interactionConstraints(&challenges, .execution, final, generated.claim, 2)) |constraint| try std.testing.expect(constraint.isZero());
    first.transition_column = first.transition_column.add(QM31.one());
    try std.testing.expect(!(try interactionConstraints(&challenges, .execution, first, generated.claim, 2))[0].isZero());
}

fn pointFromEvent(row: EventRow) InteractionPoint {
    var result = InteractionPoint{
        .active = QM31.fromBase(M31.fromCanonical(@intFromBool(row.active))),
        .transition = undefined,
        .link_emit = QM31.fromBase(M31.fromCanonical(@intFromBool(row.link_emit))),
        .emitted = undefined,
        .link_consume = QM31.fromBase(M31.fromCanonical(@intFromBool(row.link_consume))),
        .consumed = undefined,
        .initial_request = QM31.fromBase(M31.fromCanonical(@intFromBool(row.initial_request))),
        .initial = undefined,
        .first = QM31.zero(),
        .domain_last = QM31.zero(),
        .transition_column = QM31.zero(),
        .initial_column = QM31.zero(),
        .prefix_column = QM31.zero(),
        .previous_prefix_column = QM31.zero(),
    };
    for (row.transition, &result.transition) |value, *slot| slot.* = QM31.fromBase(value);
    for (row.emitted, &result.emitted) |value, *slot| slot.* = QM31.fromBase(value);
    for (row.consumed, &result.consumed) |value, *slot| slot.* = QM31.fromBase(value);
    for (row.initial, &result.initial) |value, *slot| slot.* = QM31.fromBase(value);
    return result;
}
