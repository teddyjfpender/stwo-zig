const std = @import("std");

const subject =
    @import("ethereum_incremental_full_leaf_throughput_execution_v1.zig");
const process_usage = @import("stwo_prover_engine").measurement.process_usage;

test "Stage101 execution policy admits strict worker counts one through eighteen" {
    const host = try subject.HostCapacityV1.init(
        18,
        64 * 1024 * 1024 * 1024,
    );
    inline for (1..19) |worker_count| {
        const policy = try subject.PolicyV1.init(
            worker_count,
            48 * 1024 * 1024 * 1024,
            host,
        );
        const request = try policy.request();
        try std.testing.expectEqual(worker_count, request.worker_count);
        try std.testing.expectEqual(
            @as(usize, 48 * 1024 * 1024 * 1024),
            request.host_byte_budget,
        );
        try std.testing.expectEqual(
            @import("stwo_prover_api").CpuCompositionContentionPolicy.strict,
            request.contention_policy,
        );
        const execution = try policy.executionOptions();
        try std.testing.expect(execution.cpu != null);
        try std.testing.expectEqualDeep(request, execution.cpu.?);
    }
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerCount,
        subject.PolicyV1.init(0, 1, host),
    );
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerCount,
        subject.PolicyV1.init(19, 1, host),
    );
    try std.testing.expectError(
        error.InvalidStage101AutoresearchHostBudget,
        subject.PolicyV1.init(1, 0, host),
    );
    try std.testing.expectError(
        error.InvalidStage101AutoresearchHostBudget,
        subject.PolicyV1.init(
            1,
            host.host_byte_limit + 1,
            host,
        ),
    );
    const synthetic = try subject.HostCapacityV1.init(5, 1024);
    try (try subject.PolicyV1.init(5, 1024, synthetic)).validate();
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerCount,
        subject.PolicyV1.init(6, 1024, synthetic),
    );

    const larger_host = try subject.HostCapacityV1.init(64, 1024);
    try std.testing.expectEqual(
        @as(usize, subject.PROVER_MAX_WORKERS),
        try larger_host.admittedWorkerLimit(),
    );
    try (try subject.PolicyV1.init(
        subject.PROVER_MAX_WORKERS,
        1024,
        larger_host,
    )).validate();
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerCount,
        subject.PolicyV1.init(
            subject.PROVER_MAX_WORKERS + 1,
            1024,
            larger_host,
        ),
    );
}

test "Stage101 resource receipt binds CPU utilization RSS and leaf throughput" {
    const delta = process_usage.Delta{
        .source = .darwin_proc_pid_rusage_v6,
        .lifetime_peak_physical_footprint_bytes = 42 * 1024 * 1024,
        .process_cpu_ns = 36_000_000_000,
        .energy_nj = 17,
        .instructions = 19,
        .cycles = 23,
        .unavailable_reason = null,
    };
    var receipt = try subject.ResourceReceiptV1.fromDelta(
        4_000_000_000,
        2,
        delta,
    );
    try std.testing.expectEqual(@as(u64, 2_000_000_000), receipt.ns_per_leaf);
    try std.testing.expectEqual(
        @as(?u64, 9_000),
        receipt.average_parallelism_milli,
    );
    try receipt.validate();
    receipt.average_parallelism_milli.? += 1;
    try std.testing.expectError(
        error.InvalidStage101ResourceMeasurement,
        receipt.validate(),
    );

    const unsupported = try subject.ResourceReceiptV1.fromDelta(
        1,
        1,
        .{
            .source = .unsupported,
            .lifetime_peak_physical_footprint_bytes = null,
            .process_cpu_ns = null,
            .energy_nj = null,
            .instructions = null,
            .cycles = null,
            .unavailable_reason = "unsupported fixture",
        },
    );
    try unsupported.validate();
}

test "Stage101 worker sweep is host-derived ordered and generic" {
    const host18 = try subject.HostCapacityV1.init(18, 1024);
    try subject.validateWorkerSweep(&.{ 1, 4, 8, 12, 18 }, host18);
    const host5 = try subject.HostCapacityV1.init(5, 1024);
    try subject.validateWorkerSweep(&.{ 1, 2, 5 }, host5);
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerSweep,
        subject.validateWorkerSweep(&.{}, host5),
    );
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerSweep,
        subject.validateWorkerSweep(&.{ 1, 2, 2 }, host5),
    );
    try std.testing.expectError(
        error.InvalidStage101AutoresearchWorkerSweep,
        subject.validateWorkerSweep(&.{ 1, 6 }, host5),
    );
}

test "Stage101 scheduling comparison requires byte-identical q193 cold result" {
    const reference = "canonical-stage101-proof-artifact";
    const candidate = "canonical-stage101-proof-artifact";
    const parity = try subject.ArtifactParityReceiptV1.init(
        reference,
        candidate,
    );
    try parity.validate();
    const resources = try subject.ResourceReceiptV1.fromDelta(
        4_000_000_000,
        1,
        .{
            .source = .unsupported,
            .lifetime_peak_physical_footprint_bytes = null,
            .process_cpu_ns = null,
            .energy_nj = null,
            .instructions = null,
            .cycles = null,
            .unavailable_reason = "fixture",
        },
    );
    var receipt = subject.ThroughputReceiptV1{
        .policy = try subject.PolicyV1.init(
            18,
            48 * 1024 * 1024 * 1024,
            try subject.HostCapacityV1.init(
                18,
                64 * 1024 * 1024 * 1024,
            ),
        ),
        .resources = resources,
        .artifact = parity,
        .fri_query_count = 193,
        .independently_cold_verified = true,
    };
    try receipt.validate();

    try std.testing.expectError(
        error.Stage101SchedulingChangedCanonicalArtifact,
        subject.ArtifactParityReceiptV1.init(reference, "changed"),
    );
    receipt.fri_query_count = 192;
    try std.testing.expectError(
        error.InvalidStage101ThroughputAuthority,
        receipt.validate(),
    );
    receipt.fri_query_count = 193;
    receipt.independently_cold_verified = false;
    try std.testing.expectError(
        error.InvalidStage101ThroughputAuthority,
        receipt.validate(),
    );
}
