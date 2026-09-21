//! Diagnostic CPU shadows for resident RISC-V composition partitions.
//!
//! These helpers are process-local and environment-gated by their caller.
//! They never touch the transcript. Every reference uses the proof's exact
//! global random-power vector and the ordinary component vtable.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const QM31 = core.fields.qm31.QM31;
const Component = prover.air.component_prover.ComponentProver;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const SecureColumn = prover.secure_column.SecureColumnByCoords;

pub const Mismatch = struct {
    row: usize,
    coordinate: usize,
    expected: u32,
    actual: u32,
};

pub fn firstMismatch(
    expected: *const SecureColumn,
    actual: *const SecureColumn,
) ?Mismatch {
    if (expected.len() != actual.len()) return .{
        .row = @min(expected.len(), actual.len()),
        .coordinate = 0,
        .expected = std.math.cast(u32, expected.len()) orelse
            std.math.maxInt(u32),
        .actual = std.math.cast(u32, actual.len()) orelse
            std.math.maxInt(u32),
    };
    for (0..expected.len()) |row| {
        inline for (0..4) |coordinate| {
            const expected_value = expected.columns[coordinate][row];
            const actual_value = actual.columns[coordinate][row];
            if (!expected_value.eql(actual_value)) return .{
                .row = row,
                .coordinate = coordinate,
                .expected = expected_value.toU32(),
                .actual = actual_value.toU32(),
            };
        }
    }
    return null;
}

/// Finalizes a clone of a completed device bucket set. The caller's buckets
/// remain untouched and can still be merged into the proof accumulator.
pub fn finalizeBucketClone(
    allocator: std.mem.Allocator,
    buckets: []const ?SecureColumn,
    max_log_size: u32,
) !SecureColumn {
    var no_powers: [0]QM31 = .{};
    var accumulator = try Accumulator.initForComponent(
        no_powers[0..],
        allocator,
        max_log_size,
        0,
    );
    defer accumulator.deinit();
    if (buckets.len != accumulator.sub_accumulations.len)
        return error.InvalidBasePolynomialOutputShape;
    for (buckets, 0..) |maybe_bucket, log_size| {
        const bucket = maybe_bucket orelse continue;
        accumulator.sub_accumulations[log_size] = try bucket.cloneOwned(allocator);
    }
    return accumulator.finalize();
}

/// CPU reference for one complete authenticated partition class. Non-selected
/// constraints still execute and consume their positions, but their powers are
/// zero; selected ranges retain the exact global powers used by Metal.
pub fn referenceForJobs(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    jobs: anytype,
) !SecureColumn {
    if (powers.len != totalConstraints(components))
        return error.InvalidCompositionPowerOrder;
    const masked = try allocator.alloc(QM31, powers.len);
    defer allocator.free(masked);
    @memset(masked, QM31.zero());
    for (jobs) |job| {
        const end = std.math.add(
            usize,
            job.power_start,
            job.constraint_count,
        ) catch return error.InvalidCompositionPowerOrder;
        if (end > powers.len) return error.InvalidCompositionPowerOrder;
        @memcpy(masked[job.power_start..end], powers[job.power_start..end]);
    }

    return referenceForSelectedComponents(
        allocator,
        components,
        masked,
        max_log_size,
        trace,
        jobs,
    );
}

/// CPU reference for the completed host-only workers. The exact global power
/// interval owned by every worker is retained, while accelerated intervals are
/// zero. This makes host/device/merge defects independently attributable.
pub fn referenceForHostWorkers(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    workers: anytype,
) !SecureColumn {
    if (powers.len != totalConstraints(components))
        return error.InvalidCompositionPowerOrder;
    const masked = try allocator.alloc(QM31, powers.len);
    defer allocator.free(masked);
    @memset(masked, QM31.zero());
    for (workers) |worker| {
        const start = worker.expected_next_power_index;
        const end = std.math.add(
            usize,
            start,
            worker.component.nConstraints(),
        ) catch return error.InvalidCompositionPowerOrder;
        if (end > powers.len) return error.InvalidCompositionPowerOrder;
        @memcpy(masked[start..end], powers[start..end]);
    }

    return referenceForSelectedComponents(
        allocator,
        components,
        masked,
        max_log_size,
        trace,
        workers,
    );
}

/// Finalizes exact clones of completed host-worker accumulators. Constants and
/// polynomial-extension buckets are retained; the live proof accumulators are
/// not consumed or mutated by this diagnostic projection.
pub fn finalizeHostWorkerClones(
    allocator: std.mem.Allocator,
    workers: anytype,
    max_log_size: u32,
) !SecureColumn {
    const no_powers = try allocator.alloc(QM31, 0);
    defer allocator.free(no_powers);
    var combined = try Accumulator.initForComponent(
        no_powers,
        allocator,
        max_log_size,
        0,
    );
    defer combined.deinit();
    for (workers) |worker| {
        var cloned = try cloneAccumulator(allocator, &worker.accumulator);
        defer cloned.deinit();
        combined.merge(&cloned);
    }
    return combined.finalize();
}

pub fn finalizeAccumulatorClone(
    allocator: std.mem.Allocator,
    source: *const Accumulator,
) !SecureColumn {
    var cloned = try cloneAccumulator(allocator, source);
    defer cloned.deinit();
    return cloned.finalize();
}

/// CPU reference for one accelerated job, retaining its exact global power
/// subrange while evaluating the owning component only once.
pub fn referenceForJob(
    allocator: std.mem.Allocator,
    components: []const Component,
    powers: []const QM31,
    max_log_size: u32,
    trace: *const Trace,
    target: Component,
    power_start: usize,
    constraint_count: usize,
) !struct { component_index: usize, evaluation: SecureColumn } {
    if (powers.len != totalConstraints(components))
        return error.InvalidCompositionPowerOrder;
    var component_power_end = powers.len;
    for (components, 0..) |component, component_index| {
        const component_count = component.nConstraints();
        if (component_count > component_power_end)
            return error.InvalidCompositionPowerOrder;
        const component_power_start = component_power_end - component_count;
        if (!sameComponent(component, target)) {
            component_power_end = component_power_start;
            continue;
        }

        const range_end = std.math.add(
            usize,
            power_start,
            constraint_count,
        ) catch return error.InvalidCompositionPowerOrder;
        if (power_start < component_power_start or
            range_end > component_power_end or constraint_count == 0)
        {
            return error.InvalidCompositionPowerOrder;
        }
        const local_powers = try allocator.alloc(QM31, component_count);
        defer allocator.free(local_powers);
        @memset(local_powers, QM31.zero());
        const local_start = power_start - component_power_start;
        @memcpy(
            local_powers[local_start..][0..constraint_count],
            powers[power_start..range_end],
        );
        var accumulator = try Accumulator.initForComponent(
            local_powers,
            allocator,
            max_log_size,
            component_count,
        );
        defer accumulator.deinit();
        try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
        if (accumulator.next_power_index != 0)
            return error.InvalidCompositionPowerOrder;
        return .{
            .component_index = component_index,
            .evaluation = try accumulator.finalize(),
        };
    }
    return error.InvalidCompositionComponentIdentity;
}

pub fn identity(column: *const SecureColumn) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("stwo/metal/riscv-composition-partition/v1\x00");
    var encoded: [4]u8 = undefined;
    for (0..column.len()) |row| {
        inline for (0..4) |coordinate| {
            std.mem.writeInt(
                u32,
                &encoded,
                column.columns[coordinate][row].toU32(),
                .little,
            );
            hasher.update(&encoded);
        }
    }
    return hasher.finalResult();
}

fn referenceForSelectedComponents(
    allocator: std.mem.Allocator,
    components: []const Component,
    masked_powers: []QM31,
    max_log_size: u32,
    trace: *const Trace,
    selected: anytype,
) !SecureColumn {
    const no_powers = try allocator.alloc(QM31, 0);
    defer allocator.free(no_powers);
    var combined = try Accumulator.initForComponent(
        no_powers,
        allocator,
        max_log_size,
        0,
    );
    defer combined.deinit();

    var component_power_end = masked_powers.len;
    for (components) |component| {
        const component_count = component.nConstraints();
        if (component_count > component_power_end)
            return error.InvalidCompositionPowerOrder;
        const component_power_start = component_power_end - component_count;
        component_power_end = component_power_start;
        if (!containsComponent(selected, component)) continue;

        var accumulator = try Accumulator.initForComponent(
            masked_powers,
            allocator,
            max_log_size,
            component_power_start + component_count,
        );
        defer accumulator.deinit();
        try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
        if (accumulator.next_power_index != component_power_start)
            return error.InvalidCompositionPowerOrder;
        combined.merge(&accumulator);
    }
    if (component_power_end != 0) return error.InvalidCompositionPowerOrder;
    return combined.finalize();
}

fn containsComponent(selected: anytype, candidate: Component) bool {
    for (selected) |item| {
        if (sameComponent(item.component, candidate)) return true;
    }
    return false;
}

fn cloneAccumulator(
    allocator: std.mem.Allocator,
    source: *const Accumulator,
) !Accumulator {
    const no_powers = try allocator.alloc(QM31, 0);
    var result = Accumulator.initForComponent(
        no_powers,
        allocator,
        source.max_log_size,
        0,
    ) catch |err| {
        allocator.free(no_powers);
        return err;
    };
    result.owns_powers = true;
    errdefer result.deinit();
    if (result.sub_accumulations.len != source.sub_accumulations.len or
        result.constant_accumulations.len != source.constant_accumulations.len)
    {
        return error.InvalidBasePolynomialOutputShape;
    }
    @memcpy(result.constant_accumulations, source.constant_accumulations);
    for (source.sub_accumulations, 0..) |maybe_bucket, index| {
        const bucket = maybe_bucket orelse continue;
        result.sub_accumulations[index] = try bucket.cloneOwned(allocator);
    }
    if (source.polynomial_extension_accumulations) |source_extensions| {
        const extensions = try allocator.alloc(?SecureColumn, source_extensions.len);
        errdefer allocator.free(extensions);
        @memset(extensions, null);
        errdefer for (extensions) |*maybe_bucket| if (maybe_bucket.*) |*bucket|
            bucket.deinit(allocator);
        for (source_extensions, 0..) |maybe_bucket, index| {
            const bucket = maybe_bucket orelse continue;
            extensions[index] = try bucket.cloneOwned(allocator);
        }
        result.polynomial_extension_accumulations = extensions;
    }
    return result;
}

fn sameComponent(lhs: Component, rhs: Component) bool {
    return lhs.ctx == rhs.ctx and lhs.vtable == rhs.vtable;
}

fn totalConstraints(components: []const Component) usize {
    var total: usize = 0;
    for (components) |component| total += component.nConstraints();
    return total;
}

test "Metal composition partition mismatch reports exact row and coordinate" {
    var expected = try SecureColumn.zeros(std.testing.allocator, 8);
    defer expected.deinit(std.testing.allocator);
    var actual = try expected.cloneOwned(std.testing.allocator);
    defer actual.deinit(std.testing.allocator);
    actual.columns[2][5] = core.fields.m31.M31.fromCanonical(19);
    try std.testing.expectEqual(Mismatch{
        .row = 5,
        .coordinate = 2,
        .expected = 0,
        .actual = 19,
    }, firstMismatch(&expected, &actual).?);
    actual.columns[2][5] = core.fields.m31.M31.zero();
    try std.testing.expect(firstMismatch(&expected, &actual) == null);
}
