//! Process-local execution policy and resource receipts for Stage101 A/B runs.
//!
//! Worker scheduling and host-memory limits are prover implementation inputs,
//! never protocol or transcript fields.  A candidate run is comparable only
//! after its complete canonical artifact bytes equal the reference and an
//! independent cold verifier has retained q193/193-query authority.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prover_api = @import("stwo_prover_api");
const prover_engine = @import("stwo_prover_engine");
const process_usage = prover_engine.measurement.process_usage;
const work_pool = prover_engine.work_pool;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SERIALIZABLE = false;
pub const PROTOCOL_BOUND = false;
pub const TRANSCRIPT_MIXED = false;
pub const PRODUCTION_DEFAULT_ACTIVE = false;

/// Prover storage and defensive process-memory bounds, not protocol constants
/// or a claim about the current host. Actual worker admission intersects the
/// prover capacity with a detected or caller-supplied `HostCapacityV1`.
pub const PROVER_MAX_WORKERS: usize = work_pool.MAX_WORKERS;
pub const MAX_PROCESS_HOST_BYTES: usize = 1024 * 1024 * 1024 * 1024;
pub const Q193_QUERY_COUNT: u32 = 193;

pub const HostCapacityV1 = struct {
    logical_cpu_count: usize,
    host_byte_limit: usize,

    pub fn init(
        logical_cpu_count: usize,
        host_byte_limit: usize,
    ) !HostCapacityV1 {
        const result = HostCapacityV1{
            .logical_cpu_count = logical_cpu_count,
            .host_byte_limit = host_byte_limit,
        };
        try result.validate();
        return result;
    }

    pub fn detect(host_byte_limit: usize) !HostCapacityV1 {
        return init(try std.Thread.getCpuCount(), host_byte_limit);
    }

    pub fn validate(self: HostCapacityV1) !void {
        if (self.logical_cpu_count == 0 or
            self.logical_cpu_count == std.math.maxInt(usize) or
            self.host_byte_limit == 0 or
            self.host_byte_limit > MAX_PROCESS_HOST_BYTES or
            self.host_byte_limit == std.math.maxInt(usize))
        {
            return error.InvalidStage101AutoresearchHostCapacity;
        }
    }

    /// The machine may expose more CPUs than this prover's fixed worker-pool
    /// storage. Admission is the intersection of those two process-local
    /// authorities; neither value is a protocol constant.
    pub fn admittedWorkerLimit(self: HostCapacityV1) !usize {
        try self.validate();
        return @min(self.logical_cpu_count, PROVER_MAX_WORKERS);
    }
};

pub const PolicyV1 = struct {
    worker_count: usize,
    host_byte_budget: usize,
    host: HostCapacityV1,

    pub fn init(
        worker_count: usize,
        host_byte_budget: usize,
        host: HostCapacityV1,
    ) !PolicyV1 {
        const result = PolicyV1{
            .worker_count = worker_count,
            .host_byte_budget = host_byte_budget,
            .host = host,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: PolicyV1) !void {
        try self.host.validate();
        if (self.worker_count == 0 or
            self.worker_count > try self.host.admittedWorkerLimit())
        {
            return error.InvalidStage101AutoresearchWorkerCount;
        }
        if (self.host_byte_budget == 0 or
            self.host_byte_budget > self.host.host_byte_limit or
            self.host_byte_budget == std.math.maxInt(usize))
        {
            return error.InvalidStage101AutoresearchHostBudget;
        }
    }

    pub fn request(
        self: PolicyV1,
    ) !prover_api.CpuCompositionExecutionRequest {
        try self.validate();
        _ = work_pool.WorkerBudget.init(self.worker_count) catch
            return error.InvalidStage101AutoresearchWorkerCount;
        return .{
            .worker_count = self.worker_count,
            .host_byte_budget = self.host_byte_budget,
            .contention_policy = .strict,
        };
    }

    pub fn executionOptions(
        self: PolicyV1,
    ) !frontend.testing.incremental_ethereum_orchestration_v4_internal
        .ExecutionOptions {
        return .{ .cpu = try self.request() };
    }
};

/// Validates a caller-owned benchmark sweep without turning one machine's
/// matrix into a protocol or algorithm limit. Strict ordering also prevents
/// accidental duplicate expensive runs in an automated sweep.
pub fn validateWorkerSweep(
    worker_counts: []const usize,
    host: HostCapacityV1,
) !void {
    const admitted_max = try host.admittedWorkerLimit();
    if (worker_counts.len == 0 or worker_counts.len > admitted_max)
        return error.InvalidStage101AutoresearchWorkerSweep;
    var previous: usize = 0;
    for (worker_counts) |worker_count| {
        if (worker_count == 0 or worker_count > admitted_max or
            worker_count <= previous)
        {
            return error.InvalidStage101AutoresearchWorkerSweep;
        }
        previous = worker_count;
    }
}

pub const ResourceReceiptV1 = struct {
    source: process_usage.Source,
    wall_ns: u64,
    leaf_count: u32,
    ns_per_leaf: u64,
    process_cpu_ns: ?u64,
    average_parallelism_milli: ?u64,
    lifetime_peak_physical_footprint_bytes: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    cycles: ?u64,
    unavailable_reason: ?[]const u8,

    pub fn fromDelta(
        wall_ns: u64,
        leaf_count: u32,
        delta: process_usage.Delta,
    ) !ResourceReceiptV1 {
        if (wall_ns == 0 or leaf_count == 0)
            return error.InvalidStage101ResourceMeasurement;
        const average_parallelism_milli = if (delta.process_cpu_ns) |cpu|
            std.math.cast(
                u64,
                (@as(u128, cpu) * 1000) / wall_ns,
            ) orelse return error.Stage101ResourceMeasurementOverflow
        else
            null;
        const result = ResourceReceiptV1{
            .source = delta.source,
            .wall_ns = wall_ns,
            .leaf_count = leaf_count,
            .ns_per_leaf = wall_ns / @as(u64, leaf_count),
            .process_cpu_ns = delta.process_cpu_ns,
            .average_parallelism_milli = average_parallelism_milli,
            .lifetime_peak_physical_footprint_bytes = delta.lifetime_peak_physical_footprint_bytes,
            .energy_nj = delta.energy_nj,
            .instructions = delta.instructions,
            .cycles = delta.cycles,
            .unavailable_reason = delta.unavailable_reason,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: ResourceReceiptV1) !void {
        if (self.wall_ns == 0 or self.leaf_count == 0 or
            self.ns_per_leaf != self.wall_ns / @as(u64, self.leaf_count))
        {
            return error.InvalidStage101ResourceMeasurement;
        }
        if (self.source == .unsupported) {
            if (self.process_cpu_ns != null or
                self.average_parallelism_milli != null or
                self.lifetime_peak_physical_footprint_bytes != null or
                self.energy_nj != null or self.instructions != null or
                self.cycles != null or self.unavailable_reason == null)
            {
                return error.InvalidStage101ResourceMeasurement;
            }
            return;
        }
        if (self.process_cpu_ns == null or
            self.average_parallelism_milli == null or
            self.lifetime_peak_physical_footprint_bytes == null or
            self.energy_nj == null or self.instructions == null or
            self.cycles == null or self.unavailable_reason != null)
        {
            return error.InvalidStage101ResourceMeasurement;
        }
        const expected_parallelism = std.math.cast(
            u64,
            (@as(u128, self.process_cpu_ns.?) * 1000) / self.wall_ns,
        ) orelse return error.Stage101ResourceMeasurementOverflow;
        if (self.average_parallelism_milli.? != expected_parallelism)
            return error.InvalidStage101ResourceMeasurement;
    }
};

pub const MeasurementV1 = struct {
    timer: std.time.Timer,
    before: process_usage.Snapshot,

    pub fn begin() !MeasurementV1 {
        return .{
            .timer = try std.time.Timer.start(),
            .before = try process_usage.sample(),
        };
    }

    pub fn finish(
        self: *MeasurementV1,
        leaf_count: u32,
    ) !ResourceReceiptV1 {
        const after = try process_usage.sample();
        return ResourceReceiptV1.fromDelta(
            self.timer.read(),
            leaf_count,
            try process_usage.difference(self.before, after),
        );
    }
};

/// Exact artifact equivalence is the only allowed scheduling comparison.
/// These SHA values are diagnostic summaries; `init` first compares every
/// byte, and the receipt cannot grant proof admission by itself.
pub const ArtifactParityReceiptV1 = struct {
    reference_byte_count: u64,
    candidate_byte_count: u64,
    reference_sha256: [32]u8,
    candidate_sha256: [32]u8,
    bytes_equal: bool,

    pub fn init(
        reference: []const u8,
        candidate: []const u8,
    ) !ArtifactParityReceiptV1 {
        const result = ArtifactParityReceiptV1{
            .reference_byte_count = @intCast(reference.len),
            .candidate_byte_count = @intCast(candidate.len),
            .reference_sha256 = sha256(reference),
            .candidate_sha256 = sha256(candidate),
            .bytes_equal = std.mem.eql(u8, reference, candidate),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: ArtifactParityReceiptV1) !void {
        if (!self.bytes_equal or
            self.reference_byte_count != self.candidate_byte_count or
            !std.mem.eql(
                u8,
                &self.reference_sha256,
                &self.candidate_sha256,
            ))
        {
            return error.Stage101SchedulingChangedCanonicalArtifact;
        }
    }
};

pub const ThroughputReceiptV1 = struct {
    policy: PolicyV1,
    resources: ResourceReceiptV1,
    artifact: ArtifactParityReceiptV1,
    fri_query_count: u32,
    independently_cold_verified: bool,

    pub fn validate(self: ThroughputReceiptV1) !void {
        try self.policy.validate();
        try self.resources.validate();
        try self.artifact.validate();
        if (self.fri_query_count != Q193_QUERY_COUNT or
            !self.independently_cold_verified)
        {
            return error.InvalidStage101ThroughputAuthority;
        }
    }
};

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

comptime {
    if (FORMAT_VERSION != 1 or SERIALIZABLE or PROTOCOL_BOUND or
        TRANSCRIPT_MIXED or PRODUCTION_DEFAULT_ACTIVE or
        @hasDecl(PolicyV1, "mixInto") or
        @hasDecl(ThroughputReceiptV1, "encode") or
        @hasDecl(ThroughputReceiptV1, "decode"))
    {
        @compileError("Stage101 throughput execution authority drifted");
    }
}
