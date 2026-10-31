//! Independently pinned worker authority. Temporary ELF/input image and value
//! cache are destroyed during initialization; no VM/cache reaches proof work.
const std = @import("std");
const Request = @import("rv64_ethereum_request.zig");
const A = @import("rv64_authenticated_execution.zig");
pub const Owner = struct {
    authority: A.Full.ProgramAuthority,
    policy: A.R.policy.Policy,
    initial_root: A.R.values.Digest,
    initial_pc: u64,
    initial_registers: [32]u64,
    output: [43]u8,
    pub fn init(a: std.mem.Allocator, config: Request.Config) !Owner {
        var request = try Request.Request.init(a, config);
        // No fallible operation follows the ownership move. Authority and policy
        // own copies of all expected program/permission material, not image views.
        const cpu = A.frontend.rv64.machine.Cpu.init(request.loaded.info.entry, config.symbols.stack_top);
        const result = Owner{ .authority = request.authority, .policy = request.policy, .initial_root = request.initial_cache.root(), .initial_pc = cpu.pc, .initial_registers = cpu.regs, .output = request.expected_output };
        request.initial_cache.deinit();
        request.loaded.deinit();
        return result;
    }
    pub fn context(self: *const Owner) @import("rv64_ethereum_verify_chain.zig").ExpectedContext {
        return .{ .authority = &self.authority, .policy = &self.policy, .initial_root = self.initial_root, .initial_pc = self.initial_pc, .initial_registers = self.initial_registers, .output = self.output };
    }
    pub fn deinit(self: *Owner) void {
        self.policy.deinit();
        self.authority.deinit();
        self.* = undefined;
    }
};
