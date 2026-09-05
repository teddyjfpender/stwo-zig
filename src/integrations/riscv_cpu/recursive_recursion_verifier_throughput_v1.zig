//! Process-local throughput receipts for recursive cold verification.
//!
//! The receipt distinguishes mandatory per-proof cryptography from repeated
//! same-owner projections. Every cold boundary still performs an independent
//! q193/PCS verification, transcript replay, and authenticated graph record.
//! A reuse receipt is valid only when those expensive counters do not advance
//! and the exact nonserializable owner/token pointer closure remains intact.

const std = @import("std");

const validation =
    @import("recursive_process_local_validation_token_v1.zig");
const preprocessed =
    @import("recursive_process_local_preprocessed_authority_v1.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const TARGET_REPEATED_WORK_REDUCTION_BPS: u16 = 9_900;
pub const SERIALIZABLE_VERIFIER_CAPABILITY = false;
pub const EVERY_PROOF_RETAINS_FRESH_Q193 = true;

pub const Error = error{
    InvalidVerifierThroughputReceipt,
    VerifierCounterRegression,
};

pub const ValidationDeltaV1 = struct {
    q193_cold_verifications: u64,
    transcript_replays: u64,
    graph_records: u64,
    full_audits: u64,
    token_checks: u64,
    graph_view_borrows: u64,
    q193_cold_verification_ns: u64,
    transcript_replay_ns: u64,
    graph_record_ns: u64,
    full_audit_ns: u64,
    token_check_ns: u64,
    graph_view_borrow_ns: u64,

    pub fn between(
        before: validation.CounterSnapshotV1,
        after: validation.CounterSnapshotV1,
    ) Error!ValidationDeltaV1 {
        return .{
            .q193_cold_verifications = try difference(
                after.q193_cold_verifications,
                before.q193_cold_verifications,
            ),
            .transcript_replays = try difference(
                after.transcript_replays,
                before.transcript_replays,
            ),
            .graph_records = try difference(
                after.graph_records,
                before.graph_records,
            ),
            .full_audits = try difference(
                after.full_audits,
                before.full_audits,
            ),
            .token_checks = try difference(
                after.token_checks,
                before.token_checks,
            ),
            .graph_view_borrows = try difference(
                after.graph_view_borrows,
                before.graph_view_borrows,
            ),
            .q193_cold_verification_ns = try difference(
                after.q193_cold_verification_ns,
                before.q193_cold_verification_ns,
            ),
            .transcript_replay_ns = try difference(
                after.transcript_replay_ns,
                before.transcript_replay_ns,
            ),
            .graph_record_ns = try difference(
                after.graph_record_ns,
                before.graph_record_ns,
            ),
            .full_audit_ns = try difference(
                after.full_audit_ns,
                before.full_audit_ns,
            ),
            .token_check_ns = try difference(
                after.token_check_ns,
                before.token_check_ns,
            ),
            .graph_view_borrow_ns = try difference(
                after.graph_view_borrow_ns,
                before.graph_view_borrow_ns,
            ),
        };
    }

    pub fn mandatoryCryptoCount(self: ValidationDeltaV1) u64 {
        return self.q193_cold_verifications + self.transcript_replays +
            self.graph_records;
    }

    pub fn mandatoryCryptoNs(self: ValidationDeltaV1) u64 {
        return self.q193_cold_verification_ns + self.transcript_replay_ns +
            self.graph_record_ns;
    }

    pub fn cheapReuseNs(self: ValidationDeltaV1) u64 {
        return self.token_check_ns + self.graph_view_borrow_ns;
    }
};

pub const CacheDeltaV1 = struct {
    lookups: u64,
    hits: u64,
    misses: u64,
    full_rebuilds: u64,
    rejections: u64,
    evictions: u64,
    lookup_ns: u64,
    hit_validation_ns: u64,
    rebuild_ns: u64,

    pub fn between(
        before: preprocessed.CounterSnapshotV1,
        after: preprocessed.CounterSnapshotV1,
    ) Error!CacheDeltaV1 {
        return .{
            .lookups = try difference(after.lookups, before.lookups),
            .hits = try difference(after.hits, before.hits),
            .misses = try difference(after.misses, before.misses),
            .full_rebuilds = try difference(
                after.full_rebuilds,
                before.full_rebuilds,
            ),
            .rejections = try difference(
                after.rejections,
                before.rejections,
            ),
            .evictions = try difference(after.evictions, before.evictions),
            .lookup_ns = try difference(after.lookup_ns, before.lookup_ns),
            .hit_validation_ns = try difference(
                after.hit_validation_ns,
                before.hit_validation_ns,
            ),
            .rebuild_ns = try difference(
                after.rebuild_ns,
                before.rebuild_ns,
            ),
        };
    }
};

/// One mandatory cold boundary. This is profiling evidence only and contains
/// an owner pointer specifically to make cross-process/copy promotion fail.
pub const ColdBoundaryReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    owner_ptr: usize,
    token_seal_sha256: [32]u8,
    validation: ValidationDeltaV1,
    preprocessed_cache: CacheDeltaV1,
    prove_ns: u64,
    total_cold_open_ns: u64,

    pub fn init(
        owner: *const validation.ValidatedOwnerV1,
        validation_before: validation.CounterSnapshotV1,
        validation_after: validation.CounterSnapshotV1,
        cache_before: preprocessed.CounterSnapshotV1,
        cache_after: preprocessed.CounterSnapshotV1,
        prove_ns: u64,
        total_cold_open_ns: u64,
    ) Error!ColdBoundaryReceiptV1 {
        const result = ColdBoundaryReceiptV1{
            .owner_ptr = @intFromPtr(owner),
            .token_seal_sha256 = owner.token.seal_sha256,
            .validation = try .between(validation_before, validation_after),
            .preprocessed_cache = try .between(cache_before, cache_after),
            .prove_ns = prove_ns,
            .total_cold_open_ns = total_cold_open_ns,
        };
        try result.validateAgainst(owner);
        return result;
    }

    pub fn validateAgainst(
        self: *const ColdBoundaryReceiptV1,
        owner: *const validation.ValidatedOwnerV1,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.owner_ptr != @intFromPtr(owner) or
            self.owner_ptr == 0 or std.mem.allEqual(
            u8,
            &self.token_seal_sha256,
            0,
        ) or !std.mem.eql(
            u8,
            &self.token_seal_sha256,
            &owner.token.seal_sha256,
        ) or self.validation.q193_cold_verifications != 1 or
            self.validation.transcript_replays == 0 or
            self.validation.graph_records != 1 or
            self.preprocessed_cache.lookups == 0 or
            self.preprocessed_cache.hits + self.preprocessed_cache.misses !=
                self.preprocessed_cache.lookups or
            self.preprocessed_cache.full_rebuilds >
                self.preprocessed_cache.misses)
        {
            return error.InvalidVerifierThroughputReceipt;
        }
    }
};

/// A/B receipt for repeated views from one already cold-verified owner. The
/// optimized path must not advance q193/replay/graph counters. `baseline_ns`
/// is a measured full-audit loop over the same owner and input cardinality;
/// `optimized_ns` is the measured token/view loop.
pub const ReuseReceiptV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    owner_ptr: usize,
    token_seal_sha256: [32]u8,
    repeated_operations: u64,
    delta: ValidationDeltaV1,
    measured_baseline_ns: u64,
    measured_optimized_ns: u64,
    measured_reduction_bps: u16,

    pub fn init(
        owner: *const validation.ValidatedOwnerV1,
        before: validation.CounterSnapshotV1,
        after: validation.CounterSnapshotV1,
        repeated_operations: u64,
        measured_baseline_ns: u64,
        measured_optimized_ns: u64,
    ) Error!ReuseReceiptV1 {
        const result = ReuseReceiptV1{
            .owner_ptr = @intFromPtr(owner),
            .token_seal_sha256 = owner.token.seal_sha256,
            .repeated_operations = repeated_operations,
            .delta = try .between(before, after),
            .measured_baseline_ns = measured_baseline_ns,
            .measured_optimized_ns = measured_optimized_ns,
            .measured_reduction_bps = reductionBasisPoints(
                measured_baseline_ns,
                measured_optimized_ns,
            ),
        };
        try result.validateAgainst(owner);
        return result;
    }

    pub fn validateAgainst(
        self: *const ReuseReceiptV1,
        owner: *const validation.ValidatedOwnerV1,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.owner_ptr != @intFromPtr(owner) or self.owner_ptr == 0 or
            !std.mem.eql(
                u8,
                &self.token_seal_sha256,
                &owner.token.seal_sha256,
            ) or self.repeated_operations == 0 or
            self.delta.q193_cold_verifications != 0 or
            self.delta.transcript_replays != 0 or
            self.delta.graph_records != 0 or
            self.delta.full_audits != 0 or
            self.delta.token_checks < self.repeated_operations or
            self.delta.graph_view_borrows < self.repeated_operations or
            self.measured_baseline_ns == 0 or
            self.measured_optimized_ns == 0 or
            self.measured_reduction_bps != reductionBasisPoints(
                self.measured_baseline_ns,
                self.measured_optimized_ns,
            ))
        {
            return error.InvalidVerifierThroughputReceipt;
        }
    }

    pub fn meetsStretchTarget(self: ReuseReceiptV1) bool {
        return self.measured_reduction_bps >=
            TARGET_REPEATED_WORK_REDUCTION_BPS;
    }
};

pub fn reductionBasisPoints(baseline_ns: u64, optimized_ns: u64) u16 {
    if (baseline_ns == 0 or optimized_ns >= baseline_ns) return 0;
    const saved = baseline_ns - optimized_ns;
    const scaled = @as(u128, saved) * 10_000;
    return @intCast(@min(scaled / baseline_ns, 10_000));
}

fn difference(after: u64, before: u64) Error!u64 {
    return std.math.sub(u64, after, before) catch
        error.VerifierCounterRegression;
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        TARGET_REPEATED_WORK_REDUCTION_BPS != 9_900 or
        SERIALIZABLE_VERIFIER_CAPABILITY or
        !EVERY_PROOF_RETAINS_FRESH_Q193 or
        @hasDecl(ColdBoundaryReceiptV1, "encode") or
        @hasDecl(ReuseReceiptV1, "encode"))
    {
        @compileError("recursive verifier throughput receipt drifted");
    }
}
