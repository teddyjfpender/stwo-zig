//! Stable logical-work schema, counters, and producer-ledger primitives.

const std = @import("std");
const producer_inventory = @import("work_profile_inventory.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA = "stwo.prover.logical-work-profile.v2";
pub const SCHEMA_VERSION: u16 = 2;
pub const DIGEST_DOMAIN = "stwo-zig/prover/logical-work-profile/v2\x00";
pub const PRODUCER_LEDGER_SCHEMA_VERSION: u16 = 2;

pub const Digest = [Sha256.digest_length]u8;
pub const Error = error{
    CounterOverflow,
    InvalidCounterGroup,
    InvalidProducerCoverage,
    InvalidWorkProfile,
};

/// Authority is explicit so an estimate can never be promoted as observed
/// implementation work. Only `instrumented_exact` is emitted by Recorder.
pub const Authority = enum(u8) {
    unavailable = 0,
    structural_estimate = 1,
    instrumented_exact = 2,
};

pub const Source = enum(u3) {
    field_additions = 0,
    field_multiplications = 1,
    field_inversions = 2,
    fft_butterflies = 3,
    fri_folds = 4,
    merkle_compressions = 5,
};

pub const SOURCE_COUNT: u4 = 6;
pub const ALL_SOURCE_BITS: u8 = (@as(u8, 1) << SOURCE_COUNT) - 1;

/// Version-one whole-operation boundaries. These are deliberately finer than
/// counter categories: three distinct FFT call families, two commitment-tree
/// implementations, and the FRI protocol cannot authenticate one another.
/// Adding a producer is a ledger/schema event, not an invisible call-site edit.
pub const ProducerBoundary = producer_inventory.Boundary;
pub const Site = producer_inventory.Site;
pub const SITE_COUNT = producer_inventory.SITE_COUNT;
pub const SiteCounts = producer_inventory.SiteCounts;

pub const PRODUCER_COUNT: usize = 7;
pub const ProducerCounts = [PRODUCER_COUNT]u64;

pub fn zeroProducerCounts() ProducerCounts {
    return .{0} ** PRODUCER_COUNT;
}

pub fn zeroSiteCounts() SiteCounts {
    return producer_inventory.zeroSiteCounts();
}

/// Stable aggregate transport boundary for one exact executable site.
pub inline fn boundaryForSite(site: Site) ProducerBoundary {
    return producer_inventory.boundary(site);
}

/// Independently derived request plan supplied only at the terminal proving
/// boundary. The recorder never manufactures this from its completed counts.
pub const ExpectedProducerLedger = struct {
    schema_version: u16 = PRODUCER_LEDGER_SCHEMA_VERSION,
    counts: ProducerCounts,

    pub fn validate(self: ExpectedProducerLedger) Error!void {
        if (self.schema_version != PRODUCER_LEDGER_SCHEMA_VERSION or
            (try sumProducerCounts(self.counts)) == 0)
        {
            return error.InvalidProducerCoverage;
        }
    }
};

/// Digest-bound evidence that the independent plan and the completed
/// producer observations agreed at the terminal request boundary.
pub const ProducerLedger = struct {
    schema_version: u16 = PRODUCER_LEDGER_SCHEMA_VERSION,
    expected: ProducerCounts = .{0} ** PRODUCER_COUNT,
    completed: ProducerCounts = .{0} ** PRODUCER_COUNT,
    terminal_sealed: bool = false,

    pub fn validate(self: ProducerLedger) Error!void {
        if (self.schema_version != PRODUCER_LEDGER_SCHEMA_VERSION)
            return error.InvalidProducerCoverage;
        if (self.terminal_sealed) {
            if (!std.mem.eql(u64, &self.expected, &self.completed) or
                (try sumProducerCounts(self.expected)) == 0)
            {
                return error.InvalidProducerCoverage;
            }
        } else if (!allProducerCountsZero(self.expected)) {
            return error.InvalidProducerCoverage;
        }
    }

    pub fn complete(self: ProducerLedger) bool {
        self.validate() catch return false;
        return self.terminal_sealed;
    }
};

/// Coverage mask for the six independently instrumented producer families.
/// Unknown/reserved bits fail closed rather than being silently discarded.
pub const SourceMask = packed struct(u8) {
    bits: u8 = 0,

    pub fn empty() SourceMask {
        return .{};
    }

    pub fn all() SourceMask {
        return .{ .bits = ALL_SOURCE_BITS };
    }

    pub fn one(source: Source) SourceMask {
        return .{ .bits = bit(source) };
    }

    pub fn contains(self: SourceMask, source: Source) bool {
        return self.bits & bit(source) != 0;
    }

    pub fn merge(self: SourceMask, other: SourceMask) SourceMask {
        return .{ .bits = self.bits | other.bits };
    }

    pub fn complete(self: SourceMask) bool {
        return self.bits == ALL_SOURCE_BITS;
    }

    pub fn validate(self: SourceMask) Error!void {
        if (self.bits & ~ALL_SOURCE_BITS != 0) return error.InvalidCounterGroup;
    }

    fn bit(source: Source) u8 {
        return @as(u8, 1) << @intFromEnum(source);
    }
};

/// Exact logical operation totals. Zero is a valid observed value; coverage is
/// represented by SourceMask rather than overloaded onto the counter value.
pub const Counters = struct {
    field_additions: u64 = 0,
    field_multiplications: u64 = 0,
    field_inversions: u64 = 0,
    fft_butterflies: u64 = 0,
    fri_folds: u64 = 0,
    merkle_compressions: u64 = 0,

    pub fn isZero(self: Counters) bool {
        return self.field_additions == 0 and
            self.field_multiplications == 0 and
            self.field_inversions == 0 and
            self.fft_butterflies == 0 and
            self.fri_folds == 0 and
            self.merkle_compressions == 0;
    }

    /// Returns the complete sum or an error without mutating either operand.
    pub fn add(self: Counters, other: Counters) Error!Counters {
        return .{
            .field_additions = try addCounter(
                self.field_additions,
                other.field_additions,
            ),
            .field_multiplications = try addCounter(
                self.field_multiplications,
                other.field_multiplications,
            ),
            .field_inversions = try addCounter(
                self.field_inversions,
                other.field_inversions,
            ),
            .fft_butterflies = try addCounter(
                self.fft_butterflies,
                other.fft_butterflies,
            ),
            .fri_folds = try addCounter(self.fri_folds, other.fri_folds),
            .merkle_compressions = try addCounter(
                self.merkle_compressions,
                other.merkle_compressions,
            ),
        };
    }
};

/// One completed whole-operation field contribution. The operation's own
/// field is the unit: a QM31 addition is one addition, not four M31
/// additions. Callers derive this once at an algorithm boundary; primitive
/// field methods and SIMD lanes remain free of profiling branches.
pub const FieldOperations = struct {
    additions: u64 = 0,
    multiplications: u64 = 0,
    inversions: u64 = 0,

    pub fn delta(self: FieldOperations) Delta {
        return .{
            .producer = .field_operations,
            .source_mask = .{ .bits = SourceMask.one(.field_additions).bits |
                SourceMask.one(.field_multiplications).bits |
                SourceMask.one(.field_inversions).bits },
            .counters = .{
                .field_additions = self.additions,
                .field_multiplications = self.multiplications,
                .field_inversions = self.inversions,
            },
        };
    }
};

pub const Delta = struct {
    /// Exact executable producer identity. Null is the compatibility boundary
    /// adapter and can never participate in a terminal exact-site seal.
    site: ?Site = null,
    producer: ProducerBoundary,
    source_mask: SourceMask,
    counters: Counters = .{},

    pub fn validate(self: Delta) Error!void {
        if (self.site) |site| {
            if (producer_inventory.boundary(site) != self.producer)
                return error.InvalidProducerCoverage;
        }
        try self.source_mask.validate();
        if (self.source_mask.bits == 0 or
            (!self.source_mask.contains(.field_additions) and
                self.counters.field_additions != 0) or
            (!self.source_mask.contains(.field_multiplications) and
                self.counters.field_multiplications != 0) or
            (!self.source_mask.contains(.field_inversions) and
                self.counters.field_inversions != 0) or
            (!self.source_mask.contains(.fft_butterflies) and
                self.counters.fft_butterflies != 0) or
            (!self.source_mask.contains(.fri_folds) and
                self.counters.fri_folds != 0) or
            (!self.source_mask.contains(.merkle_compressions) and
                self.counters.merkle_compressions != 0))
        {
            return error.InvalidCounterGroup;
        }
        const field_bits = SourceMask.one(.field_additions).bits |
            SourceMask.one(.field_multiplications).bits |
            SourceMask.one(.field_inversions).bits;
        const fft_bit = SourceMask.one(.fft_butterflies).bits;
        const fri_bit = SourceMask.one(.fri_folds).bits;
        const merkle_bit = SourceMask.one(.merkle_compressions).bits;
        switch (self.producer) {
            .field_operations => if (self.source_mask.bits != field_bits)
                return error.InvalidProducerCoverage,
            .column_preparation_fft,
            .polynomial_commit_fft,
            .secure_composition_fft,
            => if (self.source_mask.bits != fft_bit and
                self.source_mask.bits != fft_bit | field_bits)
                return error.InvalidProducerCoverage,
            .commitment_tree_merkle,
            .streaming_commitment_merkle,
            => if (self.source_mask.bits != merkle_bit)
                return error.InvalidProducerCoverage,
            .fri_protocol => if (!self.source_mask.contains(.fri_folds) or
                self.source_mask.bits & ~(field_bits | fft_bit | fri_bit | merkle_bit) != 0)
            {
                return error.InvalidProducerCoverage;
            },
        }
    }
};

fn addCounter(lhs: u64, rhs: u64) Error!u64 {
    return std.math.add(u64, lhs, rhs) catch error.CounterOverflow;
}

fn sumProducerCounts(counts: ProducerCounts) Error!u64 {
    var total: u64 = 0;
    for (counts) |count| total = try addCounter(total, count);
    return total;
}

fn allProducerCountsZero(counts: ProducerCounts) bool {
    for (counts) |count| if (count != 0) return false;
    return true;
}
