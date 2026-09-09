//! Versioned exact logical-work authority for profiled prover requests.
//!
//! Counters are recorded at completed algorithm boundaries, never by adding
//! branches or atomics to scalar/SIMD field primitives. This keeps the normal
//! prover path untouched and gives CPU and device backends the same units:
//!
//! - field operations count executed scalar-lane operations in the field of
//!   the operation; subtraction is an addition, while negation is free;
//!   extension-field operations are not expanded into base-field coordinates,
//!   and a batch inversion counts the primitives its implementation executes;
//! - one FFT butterfly transforms one scalar element pair for one layer;
//! - one FRI fold consumes one scalar pair for one halving step;
//! - one Merkle compression combines two child digests into one parent;
//! - fused/SIMD/device kernels expand their completed logical lane count.
//!
//! `SourceMask` authenticates category presence, not producer-site coverage.
//! Exact publication additionally requires a versioned expected/completed
//! producer ledger and a terminal request seal. A missing, duplicated, or
//! newly added producer therefore cannot be hidden by another producer setting
//! the same category bit.

const std = @import("std");
pub const producer_inventory = @import("work_profile_inventory.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

const work_core = @import("work_profile_core.zig");
pub const SCHEMA = work_core.SCHEMA;
pub const SCHEMA_VERSION = work_core.SCHEMA_VERSION;
pub const DIGEST_DOMAIN = work_core.DIGEST_DOMAIN;
pub const PRODUCER_LEDGER_SCHEMA_VERSION = work_core.PRODUCER_LEDGER_SCHEMA_VERSION;
pub const Digest = work_core.Digest;
pub const Error = work_core.Error;
pub const Authority = work_core.Authority;
pub const Source = work_core.Source;
pub const SOURCE_COUNT = work_core.SOURCE_COUNT;
pub const ALL_SOURCE_BITS = work_core.ALL_SOURCE_BITS;
pub const ProducerBoundary = work_core.ProducerBoundary;
pub const Site = work_core.Site;
pub const SITE_COUNT = work_core.SITE_COUNT;
pub const SiteCounts = work_core.SiteCounts;
pub const PRODUCER_COUNT = work_core.PRODUCER_COUNT;
pub const ProducerCounts = work_core.ProducerCounts;
pub const zeroProducerCounts = work_core.zeroProducerCounts;
pub const zeroSiteCounts = work_core.zeroSiteCounts;
pub const ExpectedProducerLedger = work_core.ExpectedProducerLedger;
pub const ProducerLedger = work_core.ProducerLedger;
pub const SourceMask = work_core.SourceMask;
pub const Counters = work_core.Counters;
pub const FieldOperations = work_core.FieldOperations;
pub const boundaryForSite = work_core.boundaryForSite;
const executions = @import("work_profile_execution.zig");
pub const M31_INTERPOLATION_EXECUTION_SCHEMA_VERSION = executions.M31_INTERPOLATION_EXECUTION_SCHEMA_VERSION;
pub const M31InterpolationExecution = executions.M31InterpolationExecution;
pub const M31ForwardFftExecution = executions.M31ForwardFftExecution;
pub const M31_CIRCLE_LDE_EXECUTION_SCHEMA_VERSION = executions.M31_CIRCLE_LDE_EXECUTION_SCHEMA_VERSION;
pub const M31CircleLdeExecution = executions.M31CircleLdeExecution;
pub const M31InterpolationBackendResult = executions.M31InterpolationBackendResult;
pub const SAMPLED_COEFFICIENT_EXECUTION_SCHEMA_VERSION = executions.SAMPLED_COEFFICIENT_EXECUTION_SCHEMA_VERSION;
pub const SampledCoefficientExecution = executions.SampledCoefficientExecution;
pub const SAMPLED_BARYCENTRIC_EXECUTION_SCHEMA_VERSION = executions.SAMPLED_BARYCENTRIC_EXECUTION_SCHEMA_VERSION;
pub const SampledBarycentricExecution = executions.SampledBarycentricExecution;
pub const QUOTIENT_PREPARATION_EXECUTION_SCHEMA_VERSION = executions.QUOTIENT_PREPARATION_EXECUTION_SCHEMA_VERSION;
pub const QUOTIENT_ROW_EXECUTION_SCHEMA_VERSION = executions.QUOTIENT_ROW_EXECUTION_SCHEMA_VERSION;
pub const QuotientPreparationExecution = executions.QuotientPreparationExecution;
pub const QuotientRowPath = executions.QuotientRowPath;
pub const QuotientRowExecution = executions.QuotientRowExecution;
pub const FRI_FOLD_EXECUTION_SCHEMA_VERSION = executions.FRI_FOLD_EXECUTION_SCHEMA_VERSION;
pub const FRI_LINE_INTERPOLATION_EXECUTION_SCHEMA_VERSION = executions.FRI_LINE_INTERPOLATION_EXECUTION_SCHEMA_VERSION;
pub const MAX_FRI_FOLD_EXECUTIONS = executions.MAX_FRI_FOLD_EXECUTIONS;
pub const FriInversePath = executions.FriInversePath;
pub const FriFoldKind = executions.FriFoldKind;
pub const FriFoldExecution = executions.FriFoldExecution;
pub const logicalM31BatchInverseMultiplications = executions.logicalM31BatchInverseMultiplications;
pub const FriFoldExecutionLedger = executions.FriFoldExecutionLedger;
pub const FriLineInterpolationExecution = executions.FriLineInterpolationExecution;
pub const logicalSampledCoefficientBasisMultiplications = executions.logicalSampledCoefficientBasisMultiplications;

/// Publishes one already-completed whole-operation contribution. A null
/// capability is the compile-time-disabled/ordinary request path.
pub fn recordFieldOperations(
    recorder: ?*Recorder(true),
    operations: FieldOperations,
) Error!void {
    const active = recorder orelse return;
    try active.record(operations.delta());
}

/// One completed boundary contribution. A set bit with a zero value means the
/// producer was exercised and authoritatively observed zero operations.
pub const Delta = work_core.Delta;

/// Fixed-shape authenticated snapshot. Partial exact snapshots are valid for
/// development diagnostics but do not satisfy `completeExact`.
pub const Profile = struct {
    schema_version: u16 = SCHEMA_VERSION,
    authority: Authority,
    source_mask: SourceMask,
    producer_ledger: ProducerLedger = .{},
    counters: Counters,
    record_count: u64,
    profile_digest: Digest,

    pub fn seal(
        authority: Authority,
        source_mask: SourceMask,
        counters: Counters,
        record_count: u64,
        producer_ledger: ProducerLedger,
    ) Error!Profile {
        var result = Profile{
            .authority = authority,
            .source_mask = source_mask,
            .producer_ledger = producer_ledger,
            .counters = counters,
            .record_count = record_count,
            .profile_digest = undefined,
        };
        try result.validateShape();
        result.profile_digest = computeDigest(&result);
        return result;
    }

    pub fn unavailable() Profile {
        return seal(.unavailable, .empty(), .{}, 0, .{}) catch unreachable;
    }

    pub fn validate(self: *const Profile) Error!void {
        try self.validateShape();
        if (!std.mem.eql(u8, &computeDigest(self), &self.profile_digest))
            return error.InvalidWorkProfile;
    }

    pub fn completeExact(self: *const Profile) bool {
        self.validate() catch return false;
        return self.authority == .instrumented_exact and
            self.source_mask.complete() and
            self.producer_ledger.complete();
    }

    fn validateShape(self: *const Profile) Error!void {
        if (self.schema_version != SCHEMA_VERSION)
            return error.InvalidWorkProfile;
        self.source_mask.validate() catch return error.InvalidWorkProfile;
        self.producer_ledger.validate() catch return error.InvalidWorkProfile;
        if (!countersRespectMask(self.counters, self.source_mask))
            return error.InvalidWorkProfile;
        switch (self.authority) {
            .unavailable => if (self.source_mask.bits != 0 or
                !self.counters.isZero() or self.record_count != 0 or
                self.producer_ledger.terminal_sealed or
                !allProducerCountsZero(self.producer_ledger.completed))
            {
                return error.InvalidWorkProfile;
            },
            .structural_estimate, .instrumented_exact => if (self.source_mask.bits == 0 or self.record_count == 0) {
                return error.InvalidWorkProfile;
            },
        }
        const completed_count = sumProducerCounts(
            self.producer_ledger.completed,
        ) catch return error.InvalidWorkProfile;
        if (completed_count != self.record_count)
            return error.InvalidWorkProfile;
        if (self.producer_ledger.terminal_sealed and !self.source_mask.complete())
            return error.InvalidWorkProfile;
    }
};

/// Optional transport used by the typed-AIR runtime receipt. Keeping this
/// representation here makes counter grouping and authority semantics SSOT;
/// Profile remains the stronger source-mask-authenticated producer record.
pub const ReceiptCounters = struct {
    authority: Authority = .unavailable,
    field_additions: ?u64 = null,
    field_multiplications: ?u64 = null,
    field_inversions: ?u64 = null,
    fft_butterflies: ?u64 = null,
    fri_folds: ?u64 = null,
    merkle_compressions: ?u64 = null,

    pub fn complete(self: ReceiptCounters) bool {
        return self.field_additions != null and
            self.field_multiplications != null and
            self.field_inversions != null and
            self.fft_butterflies != null and
            self.fri_folds != null and
            self.merkle_compressions != null;
    }

    pub fn validate(self: ReceiptCounters) Error!void {
        const present = self.presentCount();
        switch (self.authority) {
            .unavailable => if (present != 0) return error.InvalidCounterGroup,
            .structural_estimate, .instrumented_exact => if (present != SOURCE_COUNT)
                return error.InvalidCounterGroup,
        }
    }

    pub fn fromProfile(profile: *const Profile) Error!ReceiptCounters {
        try profile.validate();
        if (profile.authority == .unavailable) return .{};
        if (!profile.source_mask.complete()) return error.InvalidCounterGroup;
        return .{
            .authority = profile.authority,
            .field_additions = profile.counters.field_additions,
            .field_multiplications = profile.counters.field_multiplications,
            .field_inversions = profile.counters.field_inversions,
            .fft_butterflies = profile.counters.fft_butterflies,
            .fri_folds = profile.counters.fri_folds,
            .merkle_compressions = profile.counters.merkle_compressions,
        };
    }

    fn presentCount(self: ReceiptCounters) u4 {
        var count: u4 = 0;
        inline for (.{
            self.field_additions,
            self.field_multiplications,
            self.field_inversions,
            self.fft_butterflies,
            self.fri_folds,
            self.merkle_compressions,
        }) |value| {
            if (value != null) count += 1;
        }
        return count;
    }
};

/// Compile-time capability. `Recorder(false)` has no state and `record` is an
/// empty inline function, so code that selects the disabled capability cannot
/// retain a lock, counter update, or runtime branch after optimization.
pub fn Recorder(comptime enabled: bool) type {
    if (!enabled) return struct {
        pub inline fn record(_: *@This(), _: Delta) Error!void {}

        pub inline fn recordCompletedDelta(_: *@This(), _: Delta) Error!void {}

        pub inline fn markIncomplete(_: *@This()) void {}

        pub inline fn expectProducer(_: *@This(), _: anytype) Error!void {}

        pub inline fn finalizeFieldCoverage(_: *@This()) Error!void {}

        pub inline fn finalizeProducerCoverage(
            _: *@This(),
            _: ExpectedProducerLedger,
        ) Error!void {}

        pub inline fn finalizePlannedProducerCoverage(_: *@This()) Error!bool {
            return false;
        }

        pub inline fn snapshot(_: *const @This()) Error!Profile {
            return Profile.unavailable();
        }
    };

    return struct {
        const Self = @This();

        mutex: std.Thread.Mutex = .{},
        source_mask: SourceMask = .empty(),
        counters: Counters = .{},
        record_count: u64 = 0,
        completed_producers: ProducerCounts = .{0} ** PRODUCER_COUNT,
        planned_producers: ProducerCounts = .{0} ** PRODUCER_COUNT,
        expected_producers: ProducerCounts = .{0} ** PRODUCER_COUNT,
        completed_sites: SiteCounts = .{0} ** SITE_COUNT,
        planned_sites: SiteCounts = .{0} ** SITE_COUNT,
        legacy_site_coverage: bool = false,
        incomplete: bool = false,
        field_coverage_finalized: bool = false,
        producer_coverage_finalized: bool = false,

        /// Validation and all checked sums happen before publication. An
        /// invalid/overflowing delta leaves the recorder byte-for-byte intact.
        pub fn record(self: *Self, delta: Delta) Error!void {
            try delta.validate();
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.producer_coverage_finalized)
                return error.InvalidProducerCoverage;

            const field_bits = SourceMask.one(.field_additions).bits |
                SourceMask.one(.field_multiplications).bits |
                SourceMask.one(.field_inversions).bits;
            if (self.field_coverage_finalized and
                delta.source_mask.bits & field_bits != 0)
            {
                return error.InvalidCounterGroup;
            }

            const next_counters = try self.counters.add(delta.counters);
            const next_record_count = try addCounter(self.record_count, 1);
            const producer_index = @intFromEnum(delta.producer);
            const next_producer_count = try addCounter(
                self.completed_producers[producer_index],
                1,
            );
            const next_site_count = if (delta.site) |site|
                try addCounter(self.completed_sites[@intFromEnum(site)], 1)
            else
                0;
            self.counters = next_counters;
            self.source_mask = self.source_mask.merge(delta.source_mask);
            self.record_count = next_record_count;
            self.completed_producers[producer_index] = next_producer_count;
            if (delta.site) |site|
                self.completed_sites[@intFromEnum(site)] = next_site_count
            else
                self.legacy_site_coverage = true;
        }

        /// Exact-site completion entry point. Producer helpers use this
        /// instead of the compatibility `record` surface so omission of a
        /// site cannot silently downgrade a newly migrated call path.
        pub fn recordCompletedDelta(self: *Self, delta: Delta) Error!void {
            if (delta.site == null) return error.InvalidProducerCoverage;
            return self.record(delta);
        }

        /// Fail-closes a request that exercised a producer path whose exact
        /// logical work is not yet represented. Later observations may still
        /// be collected for diagnostics, but no exact receipt can escape.
        pub fn markIncomplete(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.incomplete = true;
        }

        /// Registers one independently selected whole-operation boundary
        /// before dispatch. Completion is recorded at the lower-level
        /// producer after the operation succeeds.
        pub fn expectProducer(self: *Self, producer: anytype) Error!void {
            const Producer = @TypeOf(producer);
            if (Producer == Site)
                return self.expectSite(producer);
            if (Producer == ProducerBoundary)
                return self.expectBoundary(producer);
            if (@typeInfo(Producer) == .enum_literal) {
                const name = @tagName(producer);
                if (comptime std.meta.stringToEnum(Site, name)) |site|
                    return self.expectSite(site);
                if (comptime std.meta.stringToEnum(ProducerBoundary, name)) |boundary|
                    return self.expectBoundary(boundary);
                @compileError("unknown logical-work producer site ." ++ name);
            }
            @compileError(
                "expectProducer requires a typed Site, ProducerBoundary adapter, " ++
                    "or bare enum literal",
            );
        }

        fn expectSite(self: *Self, site: Site) Error!void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.producer_coverage_finalized)
                return error.InvalidProducerCoverage;
            const boundary_index = @intFromEnum(producer_inventory.boundary(site));
            const site_index = @intFromEnum(site);
            const next_boundary_count = try addCounter(
                self.planned_producers[boundary_index],
                1,
            );
            const next_site_count = try addCounter(
                self.planned_sites[site_index],
                1,
            );
            self.planned_producers[boundary_index] = next_boundary_count;
            self.planned_sites[site_index] = next_site_count;
        }

        /// Compatibility adapter for callers not yet migrated to executable
        /// Site identity. Its observations remain available diagnostically,
        /// but terminal exact-site publication fails closed.
        fn expectBoundary(self: *Self, producer: ProducerBoundary) Error!void {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.producer_coverage_finalized)
                return error.InvalidProducerCoverage;
            const index = @intFromEnum(producer);
            const next_count = try addCounter(self.planned_producers[index], 1);
            self.planned_producers[index] = next_count;
            self.legacy_site_coverage = true;
        }

        /// Closes the all-request field boundary after every selected
        /// producer has published its completed delta. No subsequent field
        /// delta is accepted, preventing an early finalization from silently
        /// omitting work that executes later in the request.
        pub fn finalizeFieldCoverage(self: *Self) Error!void {
            self.mutex.lock();
            defer self.mutex.unlock();
            const required = SourceMask.one(.field_additions).bits |
                SourceMask.one(.field_multiplications).bits |
                SourceMask.one(.field_inversions).bits;
            if (self.source_mask.bits & required != required)
                return error.InvalidCounterGroup;
            self.field_coverage_finalized = true;
        }

        /// Terminally binds the independently derived request plan to actual
        /// completed producer boundaries. It cannot be reopened: later work is
        /// rejected, and any missing or duplicated boundary fails atomically.
        pub fn finalizeProducerCoverage(
            self: *Self,
            expected: ExpectedProducerLedger,
        ) Error!void {
            try expected.validate();
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.producer_coverage_finalized or
                !self.field_coverage_finalized or
                !self.source_mask.complete() or
                self.legacy_site_coverage or
                !std.mem.eql(u64, &self.planned_sites, &self.completed_sites) or
                (try sumSiteCounts(self.planned_sites)) != self.record_count or
                !std.mem.eql(u64, &expected.counts, &self.completed_producers) or
                (try sumProducerCounts(expected.counts)) != self.record_count)
            {
                return error.InvalidProducerCoverage;
            }
            self.expected_producers = expected.counts;
            self.producer_coverage_finalized = true;
        }

        /// Verified-request terminal used by production. Incomplete field
        /// instrumentation remains unavailable without failing the proof; once
        /// all source families are present, any planned/completed mismatch is
        /// a hard error rather than a partial receipt.
        pub fn finalizePlannedProducerCoverage(self: *Self) Error!bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.producer_coverage_finalized) return true;
            if (self.incomplete or !self.source_mask.complete()) return false;
            if (self.legacy_site_coverage) return false;
            if (!std.mem.eql(u64, &self.planned_sites, &self.completed_sites) or
                (try sumSiteCounts(self.planned_sites)) != self.record_count or
                !std.mem.eql(u64, &self.planned_producers, &self.completed_producers) or
                (try sumProducerCounts(self.planned_producers)) != self.record_count)
            {
                return error.InvalidProducerCoverage;
            }
            // This is the terminal production-request boundary: every
            // independently planned site has completed and all six source
            // families are present. Close field coverage in the same commit
            // as producer coverage so the production adapter does not depend
            // on a separate, caller-owned pre-seal. No state changes before
            // the equality checks above, preserving failure atomicity.
            self.field_coverage_finalized = true;
            self.expected_producers = self.planned_producers;
            self.producer_coverage_finalized = true;
            return true;
        }

        pub fn snapshot(self: *Self) Error!Profile {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.incomplete or self.record_count == 0)
                return Profile.unavailable();
            return Profile.seal(
                .instrumented_exact,
                self.source_mask,
                self.counters,
                self.record_count,
                .{
                    .expected = self.expected_producers,
                    .completed = self.completed_producers,
                    .terminal_sealed = self.producer_coverage_finalized,
                },
            );
        }
    };
}

fn countersRespectMask(counters: Counters, mask: SourceMask) bool {
    return (mask.contains(.field_additions) or counters.field_additions == 0) and
        (mask.contains(.field_multiplications) or
            counters.field_multiplications == 0) and
        (mask.contains(.field_inversions) or counters.field_inversions == 0) and
        (mask.contains(.fft_butterflies) or counters.fft_butterflies == 0) and
        (mask.contains(.fri_folds) or counters.fri_folds == 0) and
        (mask.contains(.merkle_compressions) or
            counters.merkle_compressions == 0);
}

const work_math = @import("work_profile_math.zig");
const addCounter = work_math.addCounter;
const multiplyCounter = work_math.multiplyCounter;
pub const logicalFftButterflies = work_math.logicalFftButterflies;
pub const logicalM31ForwardFftFieldOperations = work_math.logicalM31ForwardFftFieldOperations;
pub const logicalM31InterpolationWork = work_math.logicalM31InterpolationWork;
pub const logicalM31InterpolationExecutionWork = work_math.logicalM31InterpolationExecutionWork;
pub const logicalM31ColdTwiddleWork = work_math.logicalM31ColdTwiddleWork;
pub const logicalMerkleCompressions = work_math.logicalMerkleCompressions;
fn sumProducerCounts(counts: ProducerCounts) Error!u64 {
    var total: u64 = 0;
    for (counts) |count| total = try addCounter(total, count);
    return total;
}

fn sumSiteCounts(counts: SiteCounts) Error!u64 {
    var total: u64 = 0;
    for (counts) |count| total = try addCounter(total, count);
    return total;
}

fn allProducerCountsZero(counts: ProducerCounts) bool {
    for (counts) |count| if (count != 0) return false;
    return true;
}

/// Exact scalar-pair operations for a radix-2 transform. Specialized
/// whole-transform implementations report any degenerate layers they elide;
/// fused radix and SIMD kernels still expand to their completed logical pairs.
fn computeDigest(profile: *const Profile) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInteger(&hash, u16, profile.schema_version);
    hashInteger(&hash, u8, @intFromEnum(profile.authority));
    hashInteger(&hash, u8, profile.source_mask.bits);
    hashInteger(&hash, u64, profile.record_count);
    hashInteger(&hash, u16, profile.producer_ledger.schema_version);
    hashInteger(&hash, u8, @intFromBool(profile.producer_ledger.terminal_sealed));
    for (profile.producer_ledger.expected) |value|
        hashInteger(&hash, u64, value);
    for (profile.producer_ledger.completed) |value|
        hashInteger(&hash, u64, value);
    inline for (.{
        profile.counters.field_additions,
        profile.counters.field_multiplications,
        profile.counters.field_inversions,
        profile.counters.fft_butterflies,
        profile.counters.fri_folds,
        profile.counters.merkle_compressions,
    }) |value| hashInteger(&hash, u64, value);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashInteger(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
