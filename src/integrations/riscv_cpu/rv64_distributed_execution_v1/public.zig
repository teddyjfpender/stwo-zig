//! Experimental register-only BINARY execution, exactly two shards. Public
//! boundaries are NOT sufficient for acceptance: every leaf must later pass
//! its physical CPU/local-provider proof and shared FUNCTION closure.
const std = @import("std");
const air = @import("stwo_riscv_frontend").rv64_air;
const D = @import("../rv64_distributed_v1/manifest.zig");
const Thin = air.word16_cpu;
pub const MAX_STEPS: u64 = 1 << 20;
pub const Shard = struct {
    first_step: u64,
    cpu_log: u32,
    public: Thin.public.Public,
};
pub const Boundaries = [2]Shard;
/// Independently expected whole-execution authority. In this first profile all
/// final register values are expected; no host-computed RAM claim is accepted.
pub const Expected = struct {
    request_id: u64,
    request_digest: [32]u8,
    instance: [32]u8,
    relation_epoch: u64,
    program_identity: [32]u8,
    worker_jobs: [3][32]u8,
    cpu_logs: [2]u32,
    total_steps: u64,
    initial_pc: u64,
    final_pc: u64,
    initial_registers: [32]u64,
    final_registers: [32]u64,

    pub fn validate(self: Expected, program: *const Thin.rom.Setup, shards: Boundaries) !void {
        if (self.total_steps < 2 or self.total_steps > MAX_STEPS or self.relation_epoch == 0 or
            !std.mem.eql(u8, &self.program_identity, &program.identity) or self.initial_pc & 3 != 0 or self.final_pc & 3 != 0 or
            self.initial_registers[0] != 0 or self.final_registers[0] != 0) return error.InvalidDistributedBinaryExecution;
        var next: u64 = 0;
        for (shards, self.cpu_logs) |shard, expected_log| {
            if (shard.cpu_log != expected_log) return error.InvalidDistributedCpuGeometry;
            try shard.public.validate(shard.cpu_log);
            if (shard.first_step != next) return error.DistributedExecutionCoverageGap;
            next = std.math.add(u64, next, shard.public.steps) catch return error.InvalidDistributedBinaryExecution;
        }
        if (next != self.total_steps) return error.DistributedExecutionCoverageGap;
        if (shards[0].public.initial_pc != self.initial_pc or
            !std.mem.eql(u64, &shards[0].public.initial_registers, &self.initial_registers)) return error.DistributedExecutionGenesisMismatch;
        if (shards[0].public.final_pc != shards[1].public.initial_pc or
            !std.mem.eql(u64, &shards[0].public.final_registers, &shards[1].public.initial_registers)) return error.DistributedExecutionAdjacencyMismatch;
        if (shards[1].public.final_pc != self.final_pc or
            !std.mem.eql(u64, &shards[1].public.final_registers, &self.final_registers)) return error.DistributedExecutionTerminalMismatch;
        // Clocks deliberately reset to zero INSIDE each leaf's physical REG
        // endpoint authority. Public.validate bounds local terminal clocks.
        // Never compare an earlier terminal clock with the next leaf's reset.
        _ = try program.lookup(self.initial_pc);
    }
    pub fn context(self: Expected) D.T.Context {
        return .{
            .request_id = self.request_id,
            .request_digest = self.request_digest,
            .instance = self.instance,
            .program_key = self.program_identity,
            .input = endpointDigest("genesis", self.initial_pc, self.initial_registers),
            .terminal = endpointDigest("terminal", self.final_pc, self.final_registers),
            .policy = policyIdentity(),
            .opcode_map = D.T.opcodeMapIdentity(),
            .relation_epoch = self.relation_epoch,
        };
    }
};
pub fn policyIdentity() [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64.distributed.binary-register-only.reset-v1.two-shards.no-ram", &digest, .{});
    return digest;
}
/// CPU public coefficients use the SAME canonical serialization authority as
/// the local physical-proof coordinator. first_step is separately bound by
/// Spec.first_request and exact aggregate coverage validation.
pub fn shardDigest(shard: Shard) ![32]u8 {
    return @import("../word16/cpu.zig").publicDigest(shard.public, shard.cpu_log);
}
fn endpointDigest(tag: []const u8, pc: u64, registers: [32]u64) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.distributed.binary-register-only.reset-v1.endpoint");
    hash.update(tag);
    int(&hash, u64, pc);
    for (registers) |value| int(&hash, u64, value);
    return hash.finalResult();
}
fn int(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}
