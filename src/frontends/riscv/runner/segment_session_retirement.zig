//! Instruction retirement for the canonical session; lifecycle and publication
//! remain with ExecutionSession. Observers retain their pre/post commit order.
const custom0 = @import("../isa/custom0.zig");
const isa_profile = @import("../isa/profile.zig");
const access_clock = @import("../access_clock.zig");
const ExecutionProfile = @import("../isa/execution_profile.zig").ExecutionProfile;
const generated_retirement = @import("generated_retirement.zig");
const guest_precompile = @import("guest_precompile/mod.zig");
const trace = @import("trace.zig");
const state_chain = @import("state_chain.zig");
const result_mod = @import("result.zig");
const access_witness = @import("access_witness.zig");

pub const StepOutcome = struct {
    retired: bool,
    completion_reason: ?result_mod.CompletionReason = null,
    exit_code: ?u32 = null,
};

pub fn For(
    comptime profile: ExecutionProfile,
    comptime ethereum_stack_swap_candidate: bool,
    comptime ethereum_bulk_memcpy_candidate: bool,
    comptime ExtensionState: type,
) type {
    return struct {
        pub fn retireOne(
            self: anytype,
            execution_clock: u32,
            exec_trace: *trace.Trace,
            chain_tracker: *state_chain.StateChainTracker,
            extension: *ExtensionState,
        ) !StepOutcome {
            const pc_before = self.cpu.pc;
            isa_profile.requireInstructionAligned(pc_before) catch
                return error.InstructionAddressMisaligned;
            const inst_word = self.memory.readU32(pc_before);
            if (self.strict_completion and
                (inst_word == 0x00000073 or inst_word == 0x00100073))
            {
                return error.InvalidInstruction;
            }
            if (comptime profile != .rv32im_zkvm_v1) {
                if (@as(u7, @truncate(inst_word)) == custom0.major_opcode) {
                    if (comptime ethereum_stack_swap_candidate or
                        ethereum_bulk_memcpy_candidate)
                    {
                        try extension.executeWithRecordedClock(
                            inst_word,
                            execution_clock,
                            &self.cpu,
                            &self.memory,
                            self.elf_info.memory_layout,
                            chain_tracker,
                            exec_trace,
                        );
                    } else if (comptime profile == .rv32im_zkvm_poseidon2_v1) {
                        try guest_precompile.poseidon2_v1.executeWithRecordedClock(
                            profile,
                            inst_word,
                            execution_clock,
                            extension.external_step_origin,
                            &self.cpu,
                            &self.memory,
                            self.elf_info.memory_layout,
                            chain_tracker,
                            exec_trace,
                            &extension.calls,
                            &extension.rows,
                        );
                    } else if (comptime profile == .rv32im_zkvm_keccakf_v1) {
                        try guest_precompile.keccakf_v1.executeWithRecordedClock(
                            profile,
                            inst_word,
                            execution_clock,
                            extension.external_step_origin,
                            &self.cpu,
                            &self.memory,
                            self.elf_info.memory_layout,
                            chain_tracker,
                            exec_trace,
                            &extension.calls,
                            &extension.rows,
                        );
                    } else {
                        try guest_precompile.ethereum_v1.executeWithRecordedClock(
                            profile,
                            inst_word,
                            execution_clock,
                            &self.cpu,
                            &self.memory,
                            self.elf_info.memory_layout,
                            chain_tracker,
                            exec_trace,
                            extension,
                        );
                    }
                    return .{ .retired = true };
                }
            }
            const inst = self.instruction_cache.decode(inst_word) catch {
                if (self.strict_completion) return error.InvalidInstruction;
                return .{ .retired = false, .completion_reason = .invalid_instruction };
            };

            const rs1_val = self.cpu.readReg(inst.rs1);
            const is_self_loop = switch (inst.opcode) {
                .JAL => inst.rd == 0 and inst.imm == 0,
                .JALR => inst.rd == 0 and
                    ((rs1_val +% @as(u32, @bitCast(inst.imm))) & ~@as(u32, 1)) == pc_before,
                else => false,
            };
            if (is_self_loop)
                return .{ .retired = false, .completion_reason = .self_loop };

            if (self.pre_retirement_boundary_observer) |observer| {
                try observer.observe(.{
                    .execution_clock = execution_clock,
                    .cpu = &self.cpu,
                    .memory = &self.memory,
                    .memory_layout = self.elf_info.memory_layout,
                    .state_chain_tracker = chain_tracker,
                });
            }

            if (try generated_retirement.retireAtomic(
                &self.cpu,
                &self.memory,
                exec_trace,
                chain_tracker,
                inst,
                inst_word,
                execution_clock,
            )) {
                try observeLastCoreRow(self, exec_trace);
                return .{ .retired = true };
            }
            if (!exec_trace.expectsNextCoreRetirement(execution_clock))
                return error.InstructionClockMismatch;

            const rs2_val = self.cpu.readReg(inst.rs2);
            const rd_prev_val = self.cpu.readReg(inst.rd);
            const access = access_witness.capture(chain_tracker, inst, execution_clock);
            const memory_access_clock = access_clock.encode(execution_clock, .third);
            var halted = false;
            var completion_reason: ?result_mod.CompletionReason = null;
            var exit_code: ?u32 = null;
            // Ordinary instructions must have retired through typed authority above.
            switch (inst.opcode) {
                .ECALL => {
                    if (self.host) |host| {
                        const host_result = host.handleSyscall(&self.cpu, &self.memory);
                        for (host.lastMemoryWrites()) |write| {
                            try chain_tracker.recordMemTransition(
                                write.addr,
                                memory_access_clock,
                                write.previous_value,
                                write.value,
                            );
                        }
                        switch (host_result) {
                            .Halt => |code| {
                                exit_code = code;
                                completion_reason = .host_halt;
                                halted = true;
                            },
                            .Continue => self.cpu.pc +%= 4,
                        }
                    } else {
                        completion_reason = .ecall;
                        halted = true;
                    }
                },
                .EBREAK => {
                    completion_reason = .ebreak;
                    halted = true;
                },
                else => return error.GeneratedRetirementRequired,
            }

            const rd_val = self.cpu.readReg(inst.rd);
            try exec_trace.append(.{
                .clk = execution_clock,
                .pc = pc_before,
                .opcode = inst.opcode,
                .rd = inst.rd,
                .rs1 = inst.rs1,
                .rs2 = inst.rs2,
                .imm = inst.imm,
                .rs1_val = rs1_val,
                .rs2_val = rs2_val,
                .rs1_prev_clk = access.rs1_prev_clock,
                .rs2_prev_clk = access.rs2_prev_clock,
                .rd_prev_val = rd_prev_val,
                .rd_prev_clk = access.rd_prev_clock,
                .rd_val = rd_val,
                .mem_addr = 0,
                .mem_val = 0,
                .mem_prev_word = 0,
                .mem_next_word = 0,
                .mem_prev_clk = 0,
                .is_load = false,
                .is_store = false,
                .branch_taken = self.cpu.pc != pc_before +% 4,
                .next_pc = self.cpu.pc,
                .inst_word = inst_word,
            });
            try access.recordRegisters(
                chain_tracker,
                inst,
                rs1_val,
                rs2_val,
                rd_prev_val,
                rd_val,
            );
            try observeLastCoreRow(self, exec_trace);
            if (halted) return .{
                .retired = true,
                .completion_reason = completion_reason,
                .exit_code = exit_code,
            };
            if (self.cpu.pc == pc_before)
                return .{ .retired = true, .completion_reason = .stalled_pc };
            return .{ .retired = true };
        }

        fn observeLastCoreRow(self: anytype, exec_trace: *trace.Trace) !void {
            const observer = self.retirement_observer orelse return;
            if (exec_trace.rows.items.len == 0)
                return error.InvalidRetirementObserverState;
            try observer.observeCoreRow(
                exec_trace.rows.items[exec_trace.rows.items.len - 1],
            );
        }
    };
}
