//! Non-production execution authority for matched Ethereum leaf A/B proofs.
//!
//! This policy is deliberately outside the Fiat-Shamir transcript: worker
//! scheduling cannot change a proof statement or accepted proof bytes.  It
//! exists so the unoptimized and candidate leaf entrypoints consume one exact
//! memory/concurrency authority after the eight-worker baseline exceeded host
//! memory.  Existing entrypoints and their default execution policy remain
//! untouched; callers must opt in by passing this authority explicitly.

const std = @import("std");
const prover_api = @import("stwo_prover_api");

pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;
pub const production_active = false;
pub const proof_semantics_unchanged = true;

pub const leaf_worker_count: u16 = 4;
pub const leaf_host_byte_budget: u64 = 48 * 1024 * 1024 * 1024;
pub const provider_concurrent_owner_limit: u16 = 1;
pub const provider_engine_worker_cap: u16 = 4;

pub const Digest = [32]u8;

const identity_domain =
    "stwo.ethereum.leaf-matched-ab-execution-profile.v1\x00";

pub const ProviderExecutionRequest = struct {
    concurrent_owners: u16,
    engine_workers_per_owner: u16,
};

pub const Authority = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    leaf_workers: u16 = leaf_worker_count,
    leaf_host_budget_bytes: u64 = leaf_host_byte_budget,
    leaf_contention_policy: prover_api.CpuCompositionContentionPolicy = .strict,
    provider_owner_limit: u16 = provider_concurrent_owner_limit,
    provider_worker_cap: u16 = provider_engine_worker_cap,
    production_eligible: bool = production_active,
    proof_semantics_unchanged: bool = proof_semantics_unchanged,
    identity: Digest,

    pub fn canonical() Authority {
        var result = Authority{ .identity = undefined };
        result.identity = authorityIdentity(result);
        return result;
    }

    pub fn validate(self: Authority) !void {
        if (self.format != format_version or
            self.schema != schema_version or
            self.leaf_workers != leaf_worker_count or
            self.leaf_host_budget_bytes != leaf_host_byte_budget or
            self.leaf_contention_policy != .strict or
            self.provider_owner_limit != provider_concurrent_owner_limit or
            self.provider_worker_cap != provider_engine_worker_cap or
            self.production_eligible or
            !self.proof_semantics_unchanged or
            !std.mem.eql(u8, &self.identity, &authorityIdentity(self)))
        {
            return error.InvalidEthereumLeafMatchedAbExecutionAuthority;
        }
    }

    pub fn leafCpuRequest(
        self: Authority,
    ) !prover_api.CpuCompositionExecutionRequest {
        try self.validate();
        const host_byte_budget = std.math.cast(
            usize,
            self.leaf_host_budget_bytes,
        ) orelse return error.EthereumLeafMatchedAbHostBudgetOutOfRange;
        return .{
            .worker_count = self.leaf_workers,
            .host_byte_budget = host_byte_budget,
            .contention_policy = self.leaf_contention_policy,
        };
    }

    pub fn validateLeafCpuRequest(
        self: Authority,
        request: prover_api.CpuCompositionExecutionRequest,
    ) !void {
        const expected = try self.leafCpuRequest();
        if (!std.meta.eql(request, expected))
            return error.EthereumLeafMatchedAbExecutionRequestMismatch;
    }

    /// Admits only serial provider ownership. A provider may use fewer than
    /// four Engine workers under pressure, but it may never exceed the common
    /// A/B cap or overlap another provider owner.
    pub fn validateProviderExecution(
        self: Authority,
        request: ProviderExecutionRequest,
    ) !void {
        try self.validate();
        if (request.concurrent_owners != 1 or
            request.concurrent_owners > self.provider_owner_limit or
            request.engine_workers_per_owner == 0 or
            request.engine_workers_per_owner > self.provider_worker_cap)
        {
            return error.EthereumLeafMatchedAbProviderExecutionRejected;
        }
    }
};

pub fn authorityIdentity(value: Authority) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(identity_domain);
    hashInt(&hash, u16, value.format);
    hashInt(&hash, u16, value.schema);
    hashInt(&hash, u16, value.leaf_workers);
    hashInt(&hash, u64, value.leaf_host_budget_bytes);
    hashInt(
        &hash,
        u8,
        @intFromEnum(value.leaf_contention_policy),
    );
    hashInt(&hash, u16, value.provider_owner_limit);
    hashInt(&hash, u16, value.provider_worker_cap);
    hash.update(&.{@intFromBool(value.production_eligible)});
    hash.update(&.{@intFromBool(value.proof_semantics_unchanged)});
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

test "matched A/B leaf authority pins strict four-worker execution and serial providers" {
    const authority = Authority.canonical();
    try authority.validate();
    const cpu = try authority.leafCpuRequest();
    try std.testing.expectEqual(@as(usize, 4), cpu.worker_count);
    try std.testing.expectEqual(
        @as(usize, 48 * 1024 * 1024 * 1024),
        cpu.host_byte_budget,
    );
    try std.testing.expectEqual(
        prover_api.CpuCompositionContentionPolicy.strict,
        cpu.contention_policy,
    );
    try authority.validateLeafCpuRequest(cpu);
    try authority.validateProviderExecution(.{
        .concurrent_owners = 1,
        .engine_workers_per_owner = 4,
    });
    try authority.validateProviderExecution(.{
        .concurrent_owners = 1,
        .engine_workers_per_owner = 1,
    });
    try std.testing.expectError(
        error.EthereumLeafMatchedAbProviderExecutionRejected,
        authority.validateProviderExecution(.{
            .concurrent_owners = 2,
            .engine_workers_per_owner = 2,
        }),
    );
    try std.testing.expectError(
        error.EthereumLeafMatchedAbProviderExecutionRejected,
        authority.validateProviderExecution(.{
            .concurrent_owners = 1,
            .engine_workers_per_owner = 5,
        }),
    );

    var mutated = authority;
    mutated.leaf_workers = 8;
    try std.testing.expectError(
        error.InvalidEthereumLeafMatchedAbExecutionAuthority,
        mutated.validate(),
    );
}
