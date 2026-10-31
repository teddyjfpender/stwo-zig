//! Restore a durable proof prefix. Native replay supplies advice only; every
//! root, register, PC, coverage and typed counter must match a fresh receiver.
const std = @import("std");
const Request = @import("rv64_ethereum_request.zig");
const A = @import("rv64_authenticated_execution.zig");
const rv = A.frontend.rv64;
const Chain = @import("rv64_ethereum_chain.zig");
const Receiver = @import("rv64_ethereum_verify_chain.zig");
pub const Restored = struct { cursor: Chain.Cursor, proof_bytes: u64 };
pub fn restore(a: std.mem.Allocator, request: *Request.Request, config: Request.Config, session: *rv.ethereum_services.Session) !Restored {
    const accepted = try Receiver.verify(a, config, false);
    const cpu = &session.keccak.base.cpu;
    if (cpu.retired != 0) return error.InvalidEthereumResumeSeed;
    while (cpu.retired < accepted.instructions) {
        var event: rv.ethereum_services.Event = undefined;
        _ = try session.step(&event);
    }
    const calls = [_]u64{ session.keccak.calls, session.add_calls, session.double_calls };
    if (cpu.retired != accepted.instructions or cpu.pc != accepted.final_pc or !std.mem.eql(u64, &cpu.regs, &accepted.final_registers) or !std.mem.eql(u64, &calls, &accepted.calls)) return error.EthereumReplayStateMismatch;
    var observed = try A.R.values.Cache.fromMemory(a, .chunk512, &request.loaded.memory);
    errdefer observed.deinit();
    if (!std.mem.eql(u32, &observed.root(), &accepted.final_root)) return error.EthereumReplayRamMismatch;
    if (cpu.pc == config.terminal_pc) return error.EthereumPrefixAlreadyAtTerminal;
    request.initial_cache.deinit();
    request.initial_cache = observed;
    return .{ .cursor = .{ .root = accepted.final_root, .pc = cpu.pc, .registers = cpu.regs, .steps = cpu.retired, .batches = accepted.batches, .calls = calls, .expected_state_policy = config.state_policy }, .proof_bytes = accepted.proof_bytes };
}
