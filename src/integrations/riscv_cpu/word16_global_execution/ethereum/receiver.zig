//! Complete Ethereum acceptance: all native proofs and global obligations,
//! followed by the independently pinned terminal PC and ABI output in RAM.
const std = @import("std");
const Image = @import("../../word16_execution/expected_image.zig");
const Driver = @import("../../word16_execution/driver.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const E = @import("../services/execution.zig");
const P = @import("../services/protocol.zig");
const Keys = @import("keys.zig");
const Terminal = @import("terminal.zig");
pub fn expected(image: *const Image.Owner, program_identity: [32]u8, bundle: *const E.Bundle, max_steps: u64, batch_steps: u32, completed: bool) !P.Expected {
    return expectedRows(image, program_identity, .{ .legacy = bundle.cpus }, max_steps, batch_steps, completed);
}
/// The wide receiver shares exactly the legacy genesis, adjacency, coverage and
/// terminal admission. Only the request storage differs; proof/config authority
/// remains with the selected protocol's independent receiver.
pub fn expectedFromRequests(image: *const Image.Owner, program_identity: [32]u8, requests: []const P.Request, max_steps: u64, batch_steps: u32, completed: bool) !P.Expected {
    return expectedRows(image, program_identity, .{ .wide = requests }, max_steps, batch_steps, completed);
}
const Requests = union(enum) {
    legacy: []const E.CpuEncoded,
    wide: []const P.Request,
    fn len(self: Requests) usize {
        return switch (self) {
            .legacy => |v| v.len,
            .wide => |v| v.len,
        };
    }
    fn at(self: Requests, index: usize) P.Request {
        return switch (self) {
            .legacy => |v| v[index].request,
            .wide => |v| v[index],
        };
    }
};
fn expectedRows(image: *const Image.Owner, program_identity: [32]u8, rows: Requests, max_steps: u64, batch_steps: u32, completed: bool) !P.Expected {
    if (rows.len() == 0 or batch_steps == 0) return error.InvalidEthereumCpuRoster;
    const genesis = rows.at(0).base.cpu;
    if (genesis.initial_pc != image.initial_pc or !std.mem.eql(u64, &genesis.initial_registers, &image.initial_registers)) return error.UntrustedEthereumGenesis;
    var total: u64 = 0;
    var previous_pc = image.initial_pc;
    var previous_registers = image.initial_registers;
    for (0..rows.len()) |i| {
        const base = rows.at(i).base;
        if (base.epoch != i + 1 or base.memory.epoch != base.epoch or base.cpu.initial_pc != previous_pc or !std.mem.eql(u64, &base.cpu.initial_registers, &previous_registers)) return error.NonAdjacentEthereumCpu;
        previous_pc = base.cpu.final_pc;
        previous_registers = base.cpu.final_registers;
        const steps = base.cpu.steps;
        if (steps == 0 or steps > batch_steps or (i + 1 < rows.len() and steps != batch_steps)) return error.InvalidEthereumBatchSteps;
        total = try std.math.add(u64, total, steps);
    }
    if (total > max_steps) return error.EthereumStepBudgetExceeded;
    const last = rows.at(rows.len() - 1).base.cpu;
    if (completed and last.final_pc != image.terminal_pc) return error.EthereumTerminalPcMismatch;
    return .{ .admission = Driver.admission(image), .program_identity = program_identity, .total_steps = total, .max_total_steps = max_steps, .final_pc = if (completed) image.terminal_pc else last.final_pc, .final_registers = last.final_registers };
}
pub fn verify(a: std.mem.Allocator, image: *const Image.Owner, keys: *const Keys.Owner, bundle: *const E.Bundle, max_steps: u64, batch_steps: u32, completed: bool) !?[43]u8 {
    // Derive software identity from the pristine image, not any proof key,
    // packet, transport digest, or producer-reported final register state.
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const statement = try expected(image, program.identity, bundle, max_steps, batch_steps, completed);
    try E.verify(a, keys.cpus, keys.truths, statement, bundle);
    if (!completed) return null;
    const last = bundle.cpus[bundle.cpus.len - 1].request.base;
    return try Terminal.require(image, last.cpu, last.memory.terminal);
}
