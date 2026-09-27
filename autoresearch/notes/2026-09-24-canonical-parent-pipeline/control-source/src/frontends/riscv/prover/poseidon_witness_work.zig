//! Exact logical work for sparse-memory and guest Poseidon2 witnesses.
//!
//! Producers return one digest-bound receipt only after their complete route
//! succeeds.  The request owner merges those receipts transactionally and
//! publishes one typed-site delta after every selected witness route closes.
//! Ordinary unprofiled paths never construct an authority or enter this code.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_profile = prover_api.work_profile;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const SOURCE_DOMAIN = "stwo-zig/riscv/poseidon-witness-work/source/v1\x00";
pub const PRODUCER_DOMAIN = "stwo-zig/riscv/poseidon-witness-work/producer/v1\x00";
pub const RECEIPT_DOMAIN = "stwo-zig/riscv/poseidon-witness-work/receipt/v1\x00";
pub const Digest = [Sha256.digest_length]u8;

/// All shipping CPU and Metal RISC-V provers execute these witness routes on
/// the host frontend.  `shared_host_frontend` therefore closes both lanes but
/// makes no claim that Metal executed the permutations.
pub const ExecutionCapability = enum(u8) {
    shared_host_frontend = 1,
};

pub const Algorithm = enum(u8) {
    /// Pinned Stark-V Poseidon2-M31 used by sparse trees and the active AIR.
    stark_v_m31_width_16 = 1,
    /// Retained legacy/common implementation.  The production callsite audit
    /// is empty; a future use must select and complete this explicit phase.
    legacy_common_m31_width_16 = 2,
};

pub const Phase = enum(u8) {
    sparse_tree_permutation = 1,
    base_air_row_materialization = 2,
    guest_provider_preflight = 3,
    guest_provider_materialization = 4,
    legacy_common_trace = 5,
};

pub const Counts = struct {
    sparse_tree_permutations: u64 = 0,
    base_air_rows: u64 = 0,
    guest_provider_preflight_rows: u64 = 0,
    guest_provider_materialization_rows: u64 = 0,
    legacy_common_traces: u64 = 0,

    pub fn total(self: Counts) !u64 {
        var result: u64 = 0;
        inline for (std.meta.fields(Counts)) |field| {
            result = try add(result, @field(self, field.name));
        }
        return result;
    }
};

pub const Authority = struct {
    schema_version: u16 = SCHEMA_VERSION,
    capability: ExecutionCapability = .shared_host_frontend,
    stark_v_permutation: work_profile.FieldOperations,
    legacy_common_permutation: work_profile.FieldOperations,
    source_digest: Digest,

    pub fn init() Authority {
        var result = Authority{
            .stark_v_permutation = starkVPermutationOperations(),
            .legacy_common_permutation = legacyCommonPermutationOperations(),
            .source_digest = undefined,
        };
        result.source_digest = computeAuthorityDigest(&result);
        return result;
    }

    pub fn validate(self: *const Authority) !void {
        if (self.schema_version != SCHEMA_VERSION or
            self.capability != .shared_host_frontend or
            !std.meta.eql(self.stark_v_permutation, starkVPermutationOperations()) or
            !std.meta.eql(
                self.legacy_common_permutation,
                legacyCommonPermutationOperations(),
            ))
        {
            return error.PoseidonWorkSourceMismatch;
        }
        const expected = computeAuthorityDigest(self);
        if (!std.mem.eql(u8, &self.source_digest, &expected))
            return error.PoseidonWorkSourceMismatch;
    }
};

/// One completed producer boundary.  Counts and operation totals are both
/// bound so neither a route substitution nor a formula mutation can survive
/// request aggregation.
pub const ProducerReceipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    capability: ExecutionCapability = .shared_host_frontend,
    algorithm: Algorithm,
    phase: Phase,
    completed_permutations: u64,
    operations: work_profile.FieldOperations,
    source_digest: Digest,
    receipt_digest: Digest,

    pub fn validate(
        self: *const ProducerReceipt,
        authority: *const Authority,
    ) !void {
        try authority.validate();
        if (self.schema_version != SCHEMA_VERSION or
            self.capability != authority.capability or
            self.algorithm != algorithmForPhase(self.phase) or
            !std.mem.eql(u8, &self.source_digest, &authority.source_digest))
        {
            return error.InvalidPoseidonWorkReceipt;
        }
        const expected_operations = try scaledOperations(
            operationsForAlgorithm(authority, self.algorithm),
            self.completed_permutations,
        );
        if (!std.meta.eql(self.operations, expected_operations))
            return error.InvalidPoseidonWorkReceipt;
        const expected_digest = computeProducerDigest(self);
        if (!std.mem.eql(u8, &self.receipt_digest, &expected_digest))
            return error.InvalidPoseidonWorkReceipt;
    }
};

pub const Shard = struct {
    counts: Counts = .{},
    operations: work_profile.FieldOperations = .{},

    /// Checked publication is failure atomic: validation and every sum run on
    /// a copy before the coordinator-visible shard changes.
    pub fn observe(
        self: *Shard,
        authority: *const Authority,
        receipt: ProducerReceipt,
    ) !void {
        try receipt.validate(authority);
        var next = self.*;
        switch (receipt.phase) {
            .sparse_tree_permutation => next.counts.sparse_tree_permutations =
                try add(
                    next.counts.sparse_tree_permutations,
                    receipt.completed_permutations,
                ),
            .base_air_row_materialization => next.counts.base_air_rows = try add(
                next.counts.base_air_rows,
                receipt.completed_permutations,
            ),
            .guest_provider_preflight => next.counts.guest_provider_preflight_rows = try add(
                next.counts.guest_provider_preflight_rows,
                receipt.completed_permutations,
            ),
            .guest_provider_materialization => next.counts.guest_provider_materialization_rows = try add(
                next.counts.guest_provider_materialization_rows,
                receipt.completed_permutations,
            ),
            .legacy_common_trace => next.counts.legacy_common_traces = try add(
                next.counts.legacy_common_traces,
                receipt.completed_permutations,
            ),
        }
        next.operations = try addOperations(next.operations, receipt.operations);
        self.* = next;
    }

    pub fn merge(self: *Shard, other: Shard) !void {
        var next = self.*;
        inline for (std.meta.fields(Counts)) |field| {
            @field(next.counts, field.name) = try add(
                @field(next.counts, field.name),
                @field(other.counts, field.name),
            );
        }
        next.operations = try addOperations(next.operations, other.operations);
        self.* = next;
    }

    pub fn validate(self: Shard, authority: *const Authority) !void {
        try authority.validate();
        var expected = work_profile.FieldOperations{};
        inline for (.{
            .{ Phase.sparse_tree_permutation, self.counts.sparse_tree_permutations },
            .{ Phase.base_air_row_materialization, self.counts.base_air_rows },
            .{ Phase.guest_provider_preflight, self.counts.guest_provider_preflight_rows },
            .{ Phase.guest_provider_materialization, self.counts.guest_provider_materialization_rows },
            .{ Phase.legacy_common_trace, self.counts.legacy_common_traces },
        }) |item| {
            expected = try addOperations(
                expected,
                try scaledOperations(
                    operationsForAlgorithm(authority, algorithmForPhase(item[0])),
                    item[1],
                ),
            );
        }
        if (!std.meta.eql(self.operations, expected))
            return error.InvalidPoseidonWorkReceipt;
    }
};

pub const Receipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    capability: ExecutionCapability = .shared_host_frontend,
    source_digest: Digest,
    completed: Shard,
    receipt_digest: Digest,

    pub fn validate(self: *const Receipt, authority: *const Authority) !void {
        if (self.schema_version != SCHEMA_VERSION or
            self.capability != authority.capability or
            !std.mem.eql(u8, &self.source_digest, &authority.source_digest))
        {
            return error.InvalidPoseidonWorkReceipt;
        }
        try self.completed.validate(authority);
        const expected = computeReceiptDigest(self);
        if (!std.mem.eql(u8, &self.receipt_digest, &expected))
            return error.InvalidPoseidonWorkReceipt;
    }

    pub fn delta(self: *const Receipt) work_profile.Delta {
        var result = self.completed.operations.delta();
        result.site = .sparse_memory_and_guest_poseidon_witness;
        return result;
    }
};

pub fn complete(
    authority: *const Authority,
    phase: Phase,
    completed_permutations: u64,
) !ProducerReceipt {
    try authority.validate();
    const algorithm = algorithmForPhase(phase);
    var result = ProducerReceipt{
        .algorithm = algorithm,
        .phase = phase,
        .completed_permutations = completed_permutations,
        .operations = try scaledOperations(
            operationsForAlgorithm(authority, algorithm),
            completed_permutations,
        ),
        .source_digest = authority.source_digest,
        .receipt_digest = undefined,
    };
    result.receipt_digest = computeProducerDigest(&result);
    return result;
}

pub fn seal(authority: *const Authority, completed: Shard) !Receipt {
    try completed.validate(authority);
    var result = Receipt{
        .source_digest = authority.source_digest,
        .completed = completed,
        .receipt_digest = undefined,
    };
    result.receipt_digest = computeReceiptDigest(&result);
    return result;
}

/// Request-level selection boundary. It is called before sparse witness
/// construction and plans exactly one aggregate typed site, regardless of the
/// number of trees, worker chunks, or guest calls that later complete.
pub fn plan(
    recorder: ?*stage_profile.Recorder,
) !?Authority {
    const active = recorder orelse return null;
    const work = active.workCaptureRecorder() orelse return null;
    try work.expectProducer(.sparse_memory_and_guest_poseidon_witness);
    const authority = Authority.init();
    try authority.validate();
    return authority;
}

pub fn publish(
    recorder: ?*stage_profile.Recorder,
    receipt: Receipt,
) !void {
    const authority = Authority.init();
    try receipt.validate(&authority);
    const active = recorder orelse return error.PoseidonWorkRecorderMissing;
    const work = active.workCaptureRecorder() orelse
        return error.PoseidonWorkRecorderMissing;
    try work.recordCompletedDelta(receipt.delta());
}

/// The structural derivation deliberately does not trust the historical
/// literal.  It follows the live width-16 Stark-V schedule:
/// nine 92-add external layers, eight 16-lane constant/S-box rounds, fourteen
/// partial S-boxes, and fourteen 16-lane diagonal-plus-sum layers.
pub fn starkVPermutationOperations() work_profile.FieldOperations {
    const external_additions: u64 = 4 * 16 + 4 * 3 + 16;
    const full_sboxes: u64 = 8 * 16;
    const partial_sboxes: u64 = 14;
    const internal_additions: u64 = 14 * (16 + 16);
    const internal_multiplications: u64 = 14 * 16;
    return .{
        .additions = 9 * external_additions + full_sboxes +
            partial_sboxes + internal_additions,
        .multiplications = 3 * (full_sboxes + partial_sboxes) +
            internal_multiplications,
    };
}

/// The legacy/common matrix uses fifteen additions per four-lane block rather
/// than Stark-V's sixteen.  No production prover currently calls this route;
/// retaining its distinct formula prevents a future substitution from being
/// misreported as Stark-V work.
pub fn legacyCommonPermutationOperations() work_profile.FieldOperations {
    const external_additions: u64 = 4 * 15 + 4 * 3 + 16;
    const full_sboxes: u64 = 8 * 16;
    const partial_sboxes: u64 = 14;
    const internal_additions: u64 = 14 * (16 + 16);
    const internal_multiplications: u64 = 14 * 16;
    return .{
        .additions = 9 * external_additions + full_sboxes +
            partial_sboxes + internal_additions,
        .multiplications = 3 * (full_sboxes + partial_sboxes) +
            internal_multiplications,
    };
}

fn algorithmForPhase(phase: Phase) Algorithm {
    return switch (phase) {
        .sparse_tree_permutation,
        .base_air_row_materialization,
        .guest_provider_preflight,
        .guest_provider_materialization,
        => .stark_v_m31_width_16,
        .legacy_common_trace => .legacy_common_m31_width_16,
    };
}

fn operationsForAlgorithm(
    authority: *const Authority,
    algorithm: Algorithm,
) work_profile.FieldOperations {
    return switch (algorithm) {
        .stark_v_m31_width_16 => authority.stark_v_permutation,
        .legacy_common_m31_width_16 => authority.legacy_common_permutation,
    };
}

fn scaledOperations(
    operations: work_profile.FieldOperations,
    scale: u64,
) !work_profile.FieldOperations {
    return .{
        .additions = try mul(operations.additions, scale),
        .multiplications = try mul(operations.multiplications, scale),
        .inversions = try mul(operations.inversions, scale),
    };
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

fn computeAuthorityDigest(authority: *const Authority) Digest {
    var hash = Sha256.init(.{});
    hashString(&hash, SOURCE_DOMAIN);
    hashInt(&hash, u16, authority.schema_version);
    hashInt(&hash, u8, @intFromEnum(authority.capability));
    hashOperations(&hash, authority.stark_v_permutation);
    hashOperations(&hash, authority.legacy_common_permutation);
    return finish(&hash);
}

fn computeProducerDigest(receipt: *const ProducerReceipt) Digest {
    var hash = Sha256.init(.{});
    hashString(&hash, PRODUCER_DOMAIN);
    hashInt(&hash, u16, receipt.schema_version);
    hashInt(&hash, u8, @intFromEnum(receipt.capability));
    hashInt(&hash, u8, @intFromEnum(receipt.algorithm));
    hashInt(&hash, u8, @intFromEnum(receipt.phase));
    hashInt(&hash, u64, receipt.completed_permutations);
    hashOperations(&hash, receipt.operations);
    hash.update(&receipt.source_digest);
    return finish(&hash);
}

fn computeReceiptDigest(receipt: *const Receipt) Digest {
    var hash = Sha256.init(.{});
    hashString(&hash, RECEIPT_DOMAIN);
    hashInt(&hash, u16, receipt.schema_version);
    hashInt(&hash, u8, @intFromEnum(receipt.capability));
    hash.update(&receipt.source_digest);
    inline for (std.meta.fields(Counts)) |field|
        hashInt(&hash, u64, @field(receipt.completed.counts, field.name));
    hashOperations(&hash, receipt.completed.operations);
    return finish(&hash);
}

fn hashOperations(hash: *Sha256, operations: work_profile.FieldOperations) void {
    hashInt(hash, u64, operations.additions);
    hashInt(hash, u64, operations.multiplications);
    hashInt(hash, u64, operations.inversions);
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

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.PoseidonWorkOverflow;
}

fn mul(lhs: u64, rhs: u64) !u64 {
    return std.math.mul(u64, lhs, rhs) catch error.PoseidonWorkOverflow;
}
