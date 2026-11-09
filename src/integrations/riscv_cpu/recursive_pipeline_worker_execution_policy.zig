//! Execution-only parallelism authority for recursive campaign workers.
//!
//! Semantic keys never include these values. A worker must receive the Zig-
//! sealed ExecutionKey and match its worker/memory policy digests before it
//! selects both intra-proof worker count and the number of independent ready
//! nodes admitted at one tree level. This file does not alter the persistent
//! worker wire yet; `EXECUTION_KEY_FORWARDING_REQUIRED` keeps adapters closed
//! until that argument reaches their build callback.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const work_pool = @import("stwo_prover_engine").work_pool;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const EXECUTION_KEY_FORWARDING_REQUIRED = true;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const MAX_PROOF_WORKERS: usize = work_pool.MAX_WORKERS;

const WORKER_DOMAIN =
    "stwo-zig/recursive-pipeline-worker-parallelism/v2\x00";
const MEMORY_DOMAIN =
    "stwo-zig/recursive-pipeline-worker-memory/v2\x00";

pub const Error = error{
    InvalidRecursiveHostExecutionAuthority,
    InvalidRecursiveExecutionPolicy,
    RecursiveExecutionPolicyMismatch,
};

/// Runtime host capacity is execution authority only. It never enters a
/// campaign semantic key or proof transcript. The RSS ceiling is supplied by
/// the launcher because Zig has no portable physical-memory admission API.
pub const HostExecutionAuthorityV2 = struct {
    logical_cpu_count: u16,
    rss_capacity_bytes: u64,
    identity_sha256: [32]u8,

    pub fn init(
        logical_cpu_count: usize,
        rss_capacity_bytes: u64,
    ) !HostExecutionAuthorityV2 {
        var result = HostExecutionAuthorityV2{
            .logical_cpu_count = std.math.cast(
                u16,
                logical_cpu_count,
            ) orelse return error.InvalidRecursiveHostExecutionAuthority,
            .rss_capacity_bytes = rss_capacity_bytes,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = hostIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn detect(rss_capacity_bytes: u64) !HostExecutionAuthorityV2 {
        return init(try std.Thread.getCpuCount(), rss_capacity_bytes);
    }

    pub fn validate(self: *const HostExecutionAuthorityV2) !void {
        if (self.logical_cpu_count == 0 or self.rss_capacity_bytes == 0 or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &hostIdentity(self),
            )) return error.InvalidRecursiveHostExecutionAuthority;
    }
};

pub const PolicyV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    host: HostExecutionAuthorityV2,
    total_cpu_tokens: u16,
    cpu_tokens_per_node: u16,
    proof_worker_count: u16,
    maximum_parallel_nodes: u16,
    total_rss_bytes: u64,
    rss_bytes_per_node: u64,
    worker_policy_identity: [32]u8,
    memory_policy_identity: [32]u8,

    pub fn init(host: HostExecutionAuthorityV2, options: struct {
        total_cpu_tokens: u16,
        cpu_tokens_per_node: u16,
        proof_worker_count: u16,
        maximum_parallel_nodes: u16,
        total_rss_bytes: u64,
        rss_bytes_per_node: u64,
    }) !PolicyV2 {
        var result = PolicyV2{
            .host = host,
            .total_cpu_tokens = options.total_cpu_tokens,
            .cpu_tokens_per_node = options.cpu_tokens_per_node,
            .proof_worker_count = options.proof_worker_count,
            .maximum_parallel_nodes = options.maximum_parallel_nodes,
            .total_rss_bytes = options.total_rss_bytes,
            .rss_bytes_per_node = options.rss_bytes_per_node,
            .worker_policy_identity = undefined,
            .memory_policy_identity = undefined,
        };
        result.worker_policy_identity = workerIdentity(&result);
        result.memory_policy_identity = memoryIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const PolicyV2) !void {
        try self.host.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.total_cpu_tokens == 0 or self.cpu_tokens_per_node == 0 or
            self.proof_worker_count == 0 or self.maximum_parallel_nodes == 0 or
            self.total_cpu_tokens > self.host.logical_cpu_count or
            self.proof_worker_count > self.cpu_tokens_per_node or
            @as(usize, self.proof_worker_count) > MAX_PROOF_WORKERS or
            self.cpu_tokens_per_node > self.total_cpu_tokens or
            self.total_rss_bytes == 0 or self.rss_bytes_per_node == 0 or
            self.rss_bytes_per_node > self.total_rss_bytes or
            self.total_rss_bytes > self.host.rss_capacity_bytes or
            !std.mem.eql(
                u8,
                &self.worker_policy_identity,
                &workerIdentity(self),
            ) or !std.mem.eql(
            u8,
            &self.memory_policy_identity,
            &memoryIdentity(self),
        )) return error.InvalidRecursiveExecutionPolicy;
        if (self.maximum_parallel_nodes > self.tokenCapacity())
            return error.InvalidRecursiveExecutionPolicy;
    }

    pub fn validateAgainstExecution(
        self: *const PolicyV2,
        execution: artifact_store.ExecutionKeyV1,
    ) !void {
        try self.validate();
        try execution.validate();
        if (!std.mem.eql(
            u8,
            &execution.fields.worker_policy_identity,
            &self.worker_policy_identity,
        ) or !std.mem.eql(
            u8,
            &execution.fields.memory_policy_identity,
            &self.memory_policy_identity,
        )) return error.RecursiveExecutionPolicyMismatch;
    }

    pub fn tokenCapacity(self: *const PolicyV2) u16 {
        const cpu = self.total_cpu_tokens / self.cpu_tokens_per_node;
        const rss_u64 = self.total_rss_bytes / self.rss_bytes_per_node;
        const rss: u16 = @intCast(@min(rss_u64, std.math.maxInt(u16)));
        return @min(cpu, rss);
    }

    pub fn readyNodeAdmission(
        self: *const PolicyV2,
        ready_count: usize,
    ) !u16 {
        try self.validate();
        return @intCast(@min(
            ready_count,
            @as(usize, @min(self.maximum_parallel_nodes, self.tokenCapacity())),
        ));
    }

    pub fn engineWorkerCount(self: *const PolicyV2) !usize {
        try self.validate();
        return self.proof_worker_count;
    }
};

fn workerIdentity(value: *const PolicyV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(WORKER_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.host.identity_sha256);
    hashInt(&hash, u16, value.total_cpu_tokens);
    hashInt(&hash, u16, value.cpu_tokens_per_node);
    hashInt(&hash, u16, value.proof_worker_count);
    hashInt(&hash, u16, value.maximum_parallel_nodes);
    return hash.finalResult();
}

fn memoryIdentity(value: *const PolicyV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(MEMORY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.host.identity_sha256);
    hashInt(&hash, u64, value.total_rss_bytes);
    hashInt(&hash, u64, value.rss_bytes_per_node);
    return hash.finalResult();
}

fn hostIdentity(value: *const HostExecutionAuthorityV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/recursive-pipeline-host-execution/v2\x00");
    hashInt(&hash, u16, value.logical_cpu_count);
    hashInt(&hash, u64, value.rss_capacity_bytes);
    hashInt(&hash, u16, @intCast(MAX_PROOF_WORKERS));
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or !EXECUTION_KEY_FORWARDING_REQUIRED or
        SERIALIZABLE_FRESH_CAPABILITY or MAX_PROOF_WORKERS != 32)
    {
        @compileError("recursive worker execution policy drifted");
    }
}
