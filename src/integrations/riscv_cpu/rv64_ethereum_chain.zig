//! Receiver-owned adjacency/coverage state. Advance only AFTER accepting a
//! physical batch proof against independently derived immutable setup.
const std = @import("std");
const A = @import("rv64_authenticated_execution.zig");
pub const Cursor = struct {
    root: A.R.values.Digest,
    pc: u64,
    registers: [32]u64,
    steps: u64 = 0,
    batches: u32 = 0,
    calls: [3]u64 = @splat(0),
    expected_state_policy: A.rv.state_policy.Policy = .cyclic_v2,
    pub fn check(self: Cursor, public: A.Public, index: u32, first: u64, max_steps: u64) !void {
        const cpu = public.cpu;
        if (index != self.batches or first != self.steps or cpu.statement.steps > max_steps or self.steps > max_steps - cpu.statement.steps or public.geometry != .chunk512 or cpu.execution_profile != .ethereum_services_v2 or cpu.state_policy != self.expected_state_policy or cpu.arithmetic_policy != .division_multiplication_services_v3 or cpu.statement.initial_pc != self.pc or !std.mem.eql(u64, &cpu.statement.initial_registers, &self.registers) or !std.mem.eql(u32, &public.before, &self.root)) return error.InvalidEthereumBatchAdjacency;
        const ids = [_]u64{ cpu.first_call_id, cpu.secp.add.first_id, cpu.secp.double.first_id };
        for (ids, self.calls) |id, count| if (id != count + 1) return error.InvalidEthereumServiceCoverage;
    }
    pub fn advanceVerified(self: *Cursor, public: A.Public) !void {
        self.steps = try std.math.add(u64, self.steps, public.cpu.statement.steps);
        self.batches = try std.math.add(u32, self.batches, 1);
        self.calls[0] += public.cpu.keccak_calls;
        self.calls[1] += public.cpu.secp.add.calls;
        self.calls[2] += public.cpu.secp.double.calls;
        self.pc = public.cpu.statement.final_pc;
        self.registers = public.cpu.statement.final_registers;
        self.root = public.after;
    }
};
