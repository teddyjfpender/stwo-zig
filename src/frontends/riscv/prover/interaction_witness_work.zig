//! Exact logical field work for relation challenges and Tree-2 interactions.
//!
//! One request plans this site before its relation draw. Challenge and trace
//! producers then return session-bound receipts; the Tree-2 owner publishes
//! exactly once, only after every selected producer and the Tree-2 seal have
//! succeeded. Ordinary proofs never construct this authority.

const std = @import("std");
const builtin = @import("builtin");
const prover_api = @import("stwo_prover_api");
const relation_challenges = @import("../air/relation_challenges.zig");
const guest_relations = @import("../air/guest_precompile/relation_challenges.zig");

const stage_profile = prover_api.stage_profile;
const work_profile = prover_api.work_profile;
const Sha256 = std.crypto.hash.sha2.Sha256;
const QM31 = @import("stwo_core").fields.qm31.QM31;

pub const SCHEMA_VERSION: u16 = 1;
pub const SOURCE_DOMAIN = "stwo-zig/riscv/interaction-witness-work/source/v1\x00";
pub const SESSION_DOMAIN = "stwo-zig/riscv/interaction-witness-work/session/v1\x00";
pub const PRODUCER_DOMAIN = "stwo-zig/riscv/interaction-witness-work/producer/v1\x00";
pub const RECEIPT_DOMAIN = "stwo-zig/riscv/interaction-witness-work/receipt/v1\x00";
pub const Digest = [Sha256.digest_length]u8;

pub const BASE_ALPHA_POWER_MULTIPLICATIONS: u64 = 80;
pub const GUEST_ALPHA_POWER_MULTIPLICATIONS: u64 = 32;

pub const ExecutionCapability = enum(u8) {
    shared_host_frontend = 1,
};

pub const SessionKind = enum(u8) {
    base = 1,
    poseidon2_guest = 2,
};

pub const Phase = enum(u8) {
    base_challenge_suite = 1,
    guest_challenge_extension = 2,
    base_interaction_trace = 3,
    guest_interaction_trace = 4,
};

/// Primitive schedule events. Relation combination is represented by its
/// number of values and calls: each arity-a combine executes `a` products,
/// `a` accumulator additions and one final subtraction. Pair normalization
/// excludes the following prefix multiply/add, which has its own counter.
pub const Counts = struct {
    challenge_alpha_powers: u64 = 0,
    relation_combinations: u64 = 0,
    relation_inputs: u64 = 0,
    pair_normalizations: u64 = 0,
    prefix_terms: u64 = 0,
    batch_inverse_multiplications: u64 = 0,
    batch_inverse_calls: u64 = 0,
    direct_inversions: u64 = 0,
    chunk_scan_additions: u64 = 0,
    offset_additions: u64 = 0,

    pub fn operations(self: Counts) !work_profile.FieldOperations {
        return .{
            .additions = try sum(&.{
                self.relation_inputs,
                self.relation_combinations,
                try mul(self.pair_normalizations, 1),
                self.prefix_terms,
                self.chunk_scan_additions,
                self.offset_additions,
            }),
            .multiplications = try sum(&.{
                self.challenge_alpha_powers,
                self.relation_inputs,
                try mul(self.pair_normalizations, 3),
                self.prefix_terms,
                self.batch_inverse_multiplications,
            }),
            .inversions = try add(self.batch_inverse_calls, self.direct_inversions),
        };
    }

    pub fn merge(self: *Counts, other: Counts) !void {
        var next = self.*;
        inline for (std.meta.fields(Counts)) |field| {
            @field(next, field.name) = try add(
                @field(next, field.name),
                @field(other, field.name),
            );
        }
        self.* = next;
    }
};

pub const Authority = struct {
    schema_version: u16 = SCHEMA_VERSION,
    capability: ExecutionCapability = .shared_host_frontend,
    base_alpha_power_multiplications: u64 = BASE_ALPHA_POWER_MULTIPLICATIONS,
    guest_alpha_power_multiplications: u64 = GUEST_ALPHA_POWER_MULTIPLICATIONS,
    source_digest: Digest,

    pub fn init() Authority {
        var result = Authority{ .source_digest = undefined };
        result.source_digest = authorityDigest(&result);
        return result;
    }

    pub fn validate(self: *const Authority) !void {
        if (self.schema_version != SCHEMA_VERSION or
            self.capability != .shared_host_frontend or
            self.base_alpha_power_multiplications !=
                BASE_ALPHA_POWER_MULTIPLICATIONS or
            self.guest_alpha_power_multiplications !=
                GUEST_ALPHA_POWER_MULTIPLICATIONS)
        {
            return error.InteractionWorkSourceMismatch;
        }
        const expected = authorityDigest(self);
        if (!std.mem.eql(u8, &self.source_digest, &expected))
            return error.InteractionWorkSourceMismatch;
    }
};

pub const ProducerReceipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    capability: ExecutionCapability = .shared_host_frontend,
    phase: Phase,
    session_kind: SessionKind,
    session_digest: Digest,
    counts: Counts,
    operations: work_profile.FieldOperations,
    source_digest: Digest,
    receipt_digest: Digest,

    pub fn validate(
        self: *const ProducerReceipt,
        authority: *const Authority,
        session_kind: SessionKind,
        session_digest: Digest,
    ) !void {
        try authority.validate();
        if (self.schema_version != SCHEMA_VERSION or
            self.capability != authority.capability or
            self.session_kind != session_kind or
            !phaseAllowed(self.phase, session_kind) or
            !std.mem.eql(u8, &self.session_digest, &session_digest) or
            !std.mem.eql(u8, &self.source_digest, &authority.source_digest))
        {
            return error.InvalidInteractionWorkReceipt;
        }
        try validatePhaseCounts(self.phase, authority, self.counts);
        if (!std.meta.eql(self.operations, try self.counts.operations()))
            return error.InvalidInteractionWorkReceipt;
        const expected = producerDigest(self);
        if (!std.mem.eql(u8, &self.receipt_digest, &expected))
            return error.InvalidInteractionWorkReceipt;
    }
};

pub const PhaseCounts = struct {
    base_challenge_suite: u64 = 0,
    guest_challenge_extension: u64 = 0,
    base_interaction_trace: u64 = 0,
    guest_interaction_trace: u64 = 0,
};

pub const Shard = struct {
    phase_counts: PhaseCounts = .{},
    counts: Counts = .{},
    operations: work_profile.FieldOperations = .{},

    /// Validation and addition happen on a private copy so a rejected replay,
    /// duplicate challenge, or overflow cannot partially advance the owner.
    pub fn observe(
        self: *Shard,
        authority: *const Authority,
        session_kind: SessionKind,
        session_digest: Digest,
        receipt: ProducerReceipt,
    ) !void {
        try receipt.validate(authority, session_kind, session_digest);
        var next = self.*;
        const phase_count = phaseCounter(&next.phase_counts, receipt.phase);
        if ((receipt.phase == .base_challenge_suite or
            receipt.phase == .guest_challenge_extension or
            receipt.phase == .guest_interaction_trace) and phase_count.* != 0)
        {
            return error.DuplicateInteractionWorkProducer;
        }
        phase_count.* = try add(phase_count.*, 1);
        try next.counts.merge(receipt.counts);
        next.operations = try addOperations(next.operations, receipt.operations);
        self.* = next;
    }

    pub fn merge(self: *Shard, other: Shard) !void {
        var next = self.*;
        inline for (std.meta.fields(PhaseCounts)) |field| {
            @field(next.phase_counts, field.name) = try add(
                @field(next.phase_counts, field.name),
                @field(other.phase_counts, field.name),
            );
        }
        try next.counts.merge(other.counts);
        next.operations = try addOperations(next.operations, other.operations);
        self.* = next;
    }
};

pub const Receipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    capability: ExecutionCapability = .shared_host_frontend,
    session_kind: SessionKind,
    session_digest: Digest,
    source_digest: Digest,
    completed: Shard,
    receipt_digest: Digest,

    pub fn validate(self: *const Receipt, authority: *const Authority) !void {
        try authority.validate();
        if (self.schema_version != SCHEMA_VERSION or
            self.capability != authority.capability or
            !std.mem.eql(u8, &self.source_digest, &authority.source_digest))
        {
            return error.InvalidInteractionWorkReceipt;
        }
        try validateCompleted(self.session_kind, self.completed);
        if (!std.meta.eql(self.completed.operations, try self.completed.counts.operations()))
            return error.InvalidInteractionWorkReceipt;
        const expected = receiptDigest(self);
        if (!std.mem.eql(u8, &self.receipt_digest, &expected))
            return error.InvalidInteractionWorkReceipt;
    }

    pub fn delta(self: *const Receipt) work_profile.Delta {
        var result = self.completed.operations.delta();
        result.site = .relation_challenges_and_interaction_traces;
        return result;
    }
};

pub fn plan(recorder: ?*stage_profile.Recorder) !?Authority {
    const active = recorder orelse return null;
    const work = active.workCaptureRecorder() orelse return null;
    try work.expectProducer(.relation_challenges_and_interaction_traces);
    const authority = Authority.init();
    try authority.validate();
    return authority;
}

pub fn publish(recorder: ?*stage_profile.Recorder, receipt: Receipt) !void {
    const active = recorder orelse return error.InteractionWorkRecorderMissing;
    const work = active.workCaptureRecorder() orelse
        return error.InteractionWorkRecorderMissing;
    try work.recordCompletedDelta(receipt.delta());
}

pub fn baseSessionDigest(
    interaction_pow: u64,
    relations: *const relation_challenges.Relations,
) Digest {
    return sessionDigest(.base, interaction_pow, relations, null);
}

pub fn guestSessionDigest(
    interaction_pow: u64,
    relations: *const guest_relations.Poseidon2V1Relations,
) Digest {
    return sessionDigest(
        .poseidon2_guest,
        interaction_pow,
        &relations.base,
        .{ relations.guest_poseidon2_io.z, relations.guest_poseidon2_io.alpha },
    );
}

pub fn completeBaseChallenges(
    authority: *const Authority,
    session_kind: SessionKind,
    session_digest: Digest,
) !ProducerReceipt {
    return complete(authority, .base_challenge_suite, session_kind, session_digest, .{
        .challenge_alpha_powers = authority.base_alpha_power_multiplications,
    });
}

pub fn completeGuestChallenges(
    authority: *const Authority,
    session_digest: Digest,
) !ProducerReceipt {
    return complete(authority, .guest_challenge_extension, .poseidon2_guest, session_digest, .{
        .challenge_alpha_powers = authority.guest_alpha_power_multiplications,
    });
}

pub fn completeInteraction(
    authority: *const Authority,
    phase: Phase,
    session_kind: SessionKind,
    session_digest: Digest,
    counts: Counts,
) !ProducerReceipt {
    if (phase != .base_interaction_trace and phase != .guest_interaction_trace)
        return error.InvalidInteractionWorkPhase;
    return complete(authority, phase, session_kind, session_digest, counts);
}

pub fn seal(
    authority: *const Authority,
    session_kind: SessionKind,
    session_digest: Digest,
    completed: Shard,
) !Receipt {
    try authority.validate();
    try validateCompleted(session_kind, completed);
    if (!std.meta.eql(completed.operations, try completed.counts.operations()))
        return error.InvalidInteractionWorkReceipt;
    var result = Receipt{
        .session_kind = session_kind,
        .session_digest = session_digest,
        .source_digest = authority.source_digest,
        .completed = completed,
        .receipt_digest = undefined,
    };
    result.receipt_digest = receiptDigest(&result);
    return result;
}

/// Exact logical multiplication count of the live QM31 Montgomery schedule.
/// Packed AArch64 kernels are expanded back to scalar QM31 lanes.
pub fn logicalBatchInverseMultiplications(element_count: usize) !u64 {
    if (element_count == 0) return error.InvalidInteractionBatch;
    const n: u64 = @intCast(element_count);
    if (builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c) {
        if (element_count >= 32 and element_count & 31 == 0)
            return add(try mul(n, 3), 29);
        if (element_count >= 16 and element_count & 15 == 0)
            return add(try mul(n, 3), 13);
        if (element_count >= 8 and element_count & 7 == 0)
            return add(try mul(n, 3), 5);
    }
    if (element_count > 8 and element_count & 7 == 0)
        return add(try mul(n, 3), 5);
    if (element_count > 4 and element_count & 3 == 0)
        return add(try mul(n, 3), 1);
    return mul(n - 1, 3);
}

pub fn observeRelationRows(
    counts: *Counts,
    rows: usize,
    combinations_per_row: usize,
    inputs_per_row: usize,
) !void {
    counts.relation_combinations = try add(
        counts.relation_combinations,
        try mul(@intCast(rows), @intCast(combinations_per_row)),
    );
    counts.relation_inputs = try add(
        counts.relation_inputs,
        try mul(@intCast(rows), @intCast(inputs_per_row)),
    );
}

pub fn observeLogupTerms(
    counts: *Counts,
    paired_terms: usize,
    prefix_terms: usize,
    direct_inversions: usize,
) !void {
    counts.pair_normalizations = try add(counts.pair_normalizations, @intCast(paired_terms));
    counts.prefix_terms = try add(counts.prefix_terms, @intCast(prefix_terms));
    counts.direct_inversions = try add(counts.direct_inversions, @intCast(direct_inversions));
}

pub fn observeBatchInverse(counts: *Counts, elements: usize) !void {
    counts.batch_inverse_multiplications = try add(
        counts.batch_inverse_multiplications,
        try logicalBatchInverseMultiplications(elements),
    );
    counts.batch_inverse_calls = try add(counts.batch_inverse_calls, 1);
}

fn complete(
    authority: *const Authority,
    phase: Phase,
    session_kind: SessionKind,
    session_digest: Digest,
    counts: Counts,
) !ProducerReceipt {
    try authority.validate();
    if (!phaseAllowed(phase, session_kind)) return error.InvalidInteractionWorkPhase;
    try validatePhaseCounts(phase, authority, counts);
    var result = ProducerReceipt{
        .phase = phase,
        .session_kind = session_kind,
        .session_digest = session_digest,
        .counts = counts,
        .operations = try counts.operations(),
        .source_digest = authority.source_digest,
        .receipt_digest = undefined,
    };
    result.receipt_digest = producerDigest(&result);
    return result;
}

fn phaseAllowed(phase: Phase, session_kind: SessionKind) bool {
    return switch (phase) {
        .base_challenge_suite, .base_interaction_trace => true,
        .guest_challenge_extension, .guest_interaction_trace => session_kind == .poseidon2_guest,
    };
}

fn validatePhaseCounts(
    phase: Phase,
    authority: *const Authority,
    counts: Counts,
) !void {
    switch (phase) {
        .base_challenge_suite => if (!std.meta.eql(counts, Counts{
            .challenge_alpha_powers = authority.base_alpha_power_multiplications,
        })) return error.InvalidInteractionWorkReceipt,
        .guest_challenge_extension => if (!std.meta.eql(counts, Counts{
            .challenge_alpha_powers = authority.guest_alpha_power_multiplications,
        })) return error.InvalidInteractionWorkReceipt,
        .base_interaction_trace, .guest_interaction_trace => if (counts.challenge_alpha_powers != 0)
            return error.InvalidInteractionWorkReceipt,
    }
}

fn validateCompleted(kind: SessionKind, completed: Shard) !void {
    const phases = completed.phase_counts;
    if (phases.base_challenge_suite != 1 or
        phases.base_interaction_trace == 0)
    {
        return error.IncompleteInteractionWorkReceipt;
    }
    switch (kind) {
        .base => if (phases.guest_challenge_extension != 0 or
            phases.guest_interaction_trace != 0)
            return error.IncompleteInteractionWorkReceipt,
        .poseidon2_guest => if (phases.guest_challenge_extension != 1 or
            phases.guest_interaction_trace != 1)
            return error.IncompleteInteractionWorkReceipt,
    }
}

fn phaseCounter(counts: *PhaseCounts, phase: Phase) *u64 {
    return switch (phase) {
        .base_challenge_suite => &counts.base_challenge_suite,
        .guest_challenge_extension => &counts.guest_challenge_extension,
        .base_interaction_trace => &counts.base_interaction_trace,
        .guest_interaction_trace => &counts.guest_interaction_trace,
    };
}

fn sessionDigest(
    kind: SessionKind,
    interaction_pow: u64,
    relations: *const relation_challenges.Relations,
    guest_pair: ?[2]QM31,
) Digest {
    var hash = Sha256.init(.{});
    hashString(&hash, SESSION_DOMAIN);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u8, @intFromEnum(kind));
    hashInt(&hash, u64, interaction_pow);
    var draws: [relation_challenges.DRAW_COUNT]QM31 = undefined;
    relations.writeDraws(&draws) catch unreachable;
    for (draws) |draw| hashQM31(&hash, draw);
    if (guest_pair) |pair| for (pair) |draw| hashQM31(&hash, draw);
    return finish(&hash);
}

fn authorityDigest(authority: *const Authority) Digest {
    var hash = Sha256.init(.{});
    hashString(&hash, SOURCE_DOMAIN);
    hashInt(&hash, u16, authority.schema_version);
    hashInt(&hash, u8, @intFromEnum(authority.capability));
    hashInt(&hash, u64, authority.base_alpha_power_multiplications);
    hashInt(&hash, u64, authority.guest_alpha_power_multiplications);
    // Pin the live relation geometry independently of the reviewed literals.
    hashInt(&hash, u32, relation_challenges.RELATION_COUNT);
    inline for (.{ 2, 7, 5, 4, 16, 32, 4, 1, 2, 3, 2, 2 }) |arity|
        hashInt(&hash, u8, arity);
    return finish(&hash);
}

fn producerDigest(receipt: *const ProducerReceipt) Digest {
    var hash = Sha256.init(.{});
    hashString(&hash, PRODUCER_DOMAIN);
    hashInt(&hash, u16, receipt.schema_version);
    hashInt(&hash, u8, @intFromEnum(receipt.capability));
    hashInt(&hash, u8, @intFromEnum(receipt.phase));
    hashInt(&hash, u8, @intFromEnum(receipt.session_kind));
    hash.update(&receipt.session_digest);
    hashCounts(&hash, receipt.counts);
    hashOperations(&hash, receipt.operations);
    hash.update(&receipt.source_digest);
    return finish(&hash);
}

fn receiptDigest(receipt: *const Receipt) Digest {
    var hash = Sha256.init(.{});
    hashString(&hash, RECEIPT_DOMAIN);
    hashInt(&hash, u16, receipt.schema_version);
    hashInt(&hash, u8, @intFromEnum(receipt.capability));
    hashInt(&hash, u8, @intFromEnum(receipt.session_kind));
    hash.update(&receipt.session_digest);
    hash.update(&receipt.source_digest);
    inline for (std.meta.fields(PhaseCounts)) |field|
        hashInt(&hash, u64, @field(receipt.completed.phase_counts, field.name));
    hashCounts(&hash, receipt.completed.counts);
    hashOperations(&hash, receipt.completed.operations);
    return finish(&hash);
}

fn hashCounts(hash: *Sha256, counts: Counts) void {
    inline for (std.meta.fields(Counts)) |field|
        hashInt(hash, u64, @field(counts, field.name));
}

fn hashOperations(hash: *Sha256, operations: work_profile.FieldOperations) void {
    hashInt(hash, u64, operations.additions);
    hashInt(hash, u64, operations.multiplications);
    hashInt(hash, u64, operations.inversions);
}

fn hashQM31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |limb| hashInt(hash, u32, limb.toU32());
}

fn hashString(hash: *Sha256, value: []const u8) void {
    hashInt(hash, u32, @intCast(value.len));
    hash.update(value);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn finish(hash: *Sha256) Digest {
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn addOperations(
    lhs: work_profile.FieldOperations,
    rhs: work_profile.FieldOperations,
) !work_profile.FieldOperations {
    return .{
        .additions = try add(lhs.additions, rhs.additions),
        .multiplications = try add(lhs.multiplications, rhs.multiplications),
        .inversions = try add(lhs.inversions, rhs.inversions),
    };
}

fn sum(values: []const u64) !u64 {
    var result: u64 = 0;
    for (values) |value| result = try add(result, value);
    return result;
}

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.InteractionWorkOverflow;
}

fn mul(lhs: u64, rhs: u64) !u64 {
    return std.math.mul(u64, lhs, rhs) catch error.InteractionWorkOverflow;
}

test "challenge receipts are ordered, session-bound, and non-duplicable" {
    const authority = Authority.init();
    const relations = relation_challenges.Relations.dummy();
    const binding = baseSessionDigest(9, &relations);
    const challenge = try completeBaseChallenges(&authority, .base, binding);
    const interaction = try completeInteraction(
        &authority,
        .base_interaction_trace,
        .base,
        binding,
        .{ .prefix_terms = 1 },
    );
    var completed = Shard{};
    try completed.observe(&authority, .base, binding, challenge);
    try std.testing.expectError(
        error.DuplicateInteractionWorkProducer,
        completed.observe(&authority, .base, binding, challenge),
    );
    try completed.observe(&authority, .base, binding, interaction);
    const receipt = try seal(&authority, .base, binding, completed);
    try receipt.validate(&authority);
    try std.testing.expectEqual(
        work_profile.Site.relation_challenges_and_interaction_traces,
        receipt.delta().site,
    );

    const detached = baseSessionDigest(10, &relations);
    var detached_shard = Shard{};
    try std.testing.expectError(
        error.InvalidInteractionWorkReceipt,
        detached_shard.observe(&authority, .base, detached, challenge),
    );
}

test "guest completion requires distinct base and extension challenge receipts" {
    const authority = Authority.init();
    const relations = guest_relations.Poseidon2V1Relations.dummy();
    const binding = guestSessionDigest(17, &relations);
    var completed = Shard{};
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        try completeBaseChallenges(&authority, .poseidon2_guest, binding),
    );
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        try completeInteraction(
            &authority,
            .base_interaction_trace,
            .poseidon2_guest,
            binding,
            .{ .prefix_terms = 1 },
        ),
    );
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        try completeInteraction(
            &authority,
            .guest_interaction_trace,
            .poseidon2_guest,
            binding,
            .{},
        ),
    );
    try std.testing.expectError(
        error.IncompleteInteractionWorkReceipt,
        seal(&authority, .poseidon2_guest, binding, completed),
    );
    try completed.observe(
        &authority,
        .poseidon2_guest,
        binding,
        try completeGuestChallenges(&authority, binding),
    );
    const receipt = try seal(&authority, .poseidon2_guest, binding, completed);
    try receipt.validate(&authority);
    try std.testing.expectEqual(
        BASE_ALPHA_POWER_MULTIPLICATIONS + GUEST_ALPHA_POWER_MULTIPLICATIONS + 1,
        receipt.completed.operations.multiplications,
    );
}

test "count derivation and overflow are failure atomic" {
    var counts = Counts{};
    try observeRelationRows(&counts, 3, 7, 24);
    try observeLogupTerms(&counts, 5, 6, 7);
    try observeBatchInverse(&counts, 8);
    const operations = try counts.operations();
    try std.testing.expectEqual(@as(u64, 72 + 21 + 5 + 6), operations.additions);
    try std.testing.expectEqual(
        72 + 15 + 6 + try logicalBatchInverseMultiplications(8),
        operations.multiplications,
    );
    try std.testing.expectEqual(@as(u64, 8), operations.inversions);

    var saturated = Counts{ .prefix_terms = std.math.maxInt(u64) };
    const before = saturated;
    try std.testing.expectError(
        error.InteractionWorkOverflow,
        observeLogupTerms(&saturated, 0, 1, 0),
    );
    try std.testing.expectEqualDeep(before, saturated);
}

comptime {
    if (relation_challenges.RELATION_COUNT != 12 or
        relation_challenges.DRAW_COUNT != 24 or
        guest_relations.relation_count != 13 or
        BASE_ALPHA_POWER_MULTIPLICATIONS != 80 or
        GUEST_ALPHA_POWER_MULTIPLICATIONS != 32)
    {
        @compileError("interaction work challenge schedule drifted");
    }
}
