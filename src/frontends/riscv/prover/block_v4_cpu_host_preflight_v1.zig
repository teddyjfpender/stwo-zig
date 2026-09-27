//! Host-only endpoint preflight for an independently pinned exact schedule.
//! Its chunk size is unrelated to proof leaf budgets: the explicit schedule
//! is admitted later against total cycles and terminal-publication suffix.
const std = @import("std");
const preflight = @import("blake3_execution_preflight.zig");

pub const HOST_CHUNK_CYCLES: u32 = 1 << 18;

pub fn run(a: std.mem.Allocator, elf: []const u8, input: []const u8, oracle: []const u8, proof_maximum: u32) !preflight.Planned {
    const host_limit = @min(proof_maximum, HOST_CHUNK_CYCLES);
    return preflight.runEthereumForProfile(.rv32im_zkvm_ethereum_sha_v1, a, elf, input, oracle, host_limit) catch |err| {
        // Some jobs publish output over more than one host chunk. Retry only
        // that known schedule-construction error at the original proof cap.
        if (err != error.TerminalPublicationExceedsSegmentBudget or host_limit == proof_maximum)
            return err;
        return preflight.runEthereumForProfile(.rv32im_zkvm_ethereum_sha_v1, a, elf, input, oracle, proof_maximum);
    };
}
