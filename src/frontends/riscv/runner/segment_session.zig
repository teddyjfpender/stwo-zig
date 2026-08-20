//! Resumable RV32IM execution with owned, proof-oriented segment boundaries.
//!
//! The architectural state, sparse memory, and decoded-instruction cache live
//! for the whole session.  Trace and state-chain logs are owned per segment,
//! while their clocks remain global across resumes.  This is intentionally a
//! runner substrate: V1 public data assumes zero predecessor clocks and must
//! not admit a non-first segment; V2 must authenticate the exposed entry clock
//! boundary together with the sparse-memory root derived from `rw_memory`.

const std = @import("std");
const custom0 = @import("../isa/custom0.zig");
const execution_profile = @import("../isa/execution_profile.zig");
const isa_profile = @import("../isa/profile.zig");
const access_clock = @import("../access_clock.zig");
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const decode = @import("decode.zig");
const decode_cache = @import("decode_cache.zig");
const elf_loader = @import("elf_loader.zig");
const execute_mod = @import("execute.zig");
const generated_retirement = @import("generated_retirement.zig");
const guest_precompile = @import("guest_precompile/mod.zig");
const host_mod = @import("../host/mod.zig");
const trace = @import("trace.zig");
const state_chain = @import("state_chain.zig");
const memory_state = @import("memory_state.zig");
const result_mod = @import("result.zig");
const access_witness = @import("access_witness.zig");
const session_support = @import("segment_session_support.zig");

pub const ExecutionProfile = execution_profile.ExecutionProfile;
pub const HostInterface = host_mod.HostInterface;
pub const SessionOptions = struct {
    host: ?HostInterface = null,
    input: []const u8 = &.{},
    stop_on_halt_flag: bool = false,
    strict_completion: bool = false,
};

pub fn ConfiguredSegmentResult(comptime profile: ExecutionProfile) type {
    return if (profile == .rv32im_zkvm_v1)
        result_mod.SegmentResult
    else
        result_mod.Poseidon2SegmentResult;
}

fn ConfiguredRunResult(comptime profile: ExecutionProfile) type {
    return if (profile == .rv32im_zkvm_v1)
        result_mod.RunResult
    else
        result_mod.Poseidon2RunResult;
}

const SessionStatus = enum { active, complete, poisoned };
const ExhaustionPolicy = enum { yield, legacy_terminal };

const Poseidon2ExecutionState = struct {
    calls: guest_precompile.call_buffer.Builder,
    rows: guest_precompile.poseidon2_v1.ExecutionRowsBuilder,

    fn init(allocator: std.mem.Allocator, step_budget: usize) !Poseidon2ExecutionState {
        const limit = @min(step_budget, guest_precompile.call_buffer.max_calls);
        return .{
            .calls = try .init(allocator, limit),
            .rows = try .init(allocator, limit),
        };
    }

    fn deinit(self: *Poseidon2ExecutionState) void {
        self.calls.deinit();
        self.rows.deinit();
        self.* = undefined;
    }
};

const EmptyExtensionState = struct {
    fn init(_: std.mem.Allocator, _: usize) !EmptyExtensionState {
        return .{};
    }
    fn deinit(_: *EmptyExtensionState) void {}
};

fn ExtensionState(comptime profile: ExecutionProfile) type {
    return if (profile == .rv32im_zkvm_poseidon2_v1)
        Poseidon2ExecutionState
    else
        EmptyExtensionState;
}

const StepOutcome = struct {
    retired: bool,
    completion_reason: ?result_mod.CompletionReason = null,
    exit_code: ?u32 = null,
};

pub fn ExecutionSession(comptime profile: ExecutionProfile) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        memory: Memory,
        elf_info: elf_loader.ElfInfo,
        cpu: Cpu,
        instruction_cache: decode_cache.Cache,
        /// Authority-facing trace stays cumulative so retirement transactions
        /// retain their global-clock/row-index invariant across segments.
        /// Segment results receive an owned copy of only their appended range.
        execution_trace: trace.Trace,
        host: ?HostInterface,
        stop_on_halt_flag: bool,
        strict_completion: bool,
        input: ?[]u8,
        global_steps: u64 = 0,
        next_segment_index: u32 = 0,
        register_clocks: [32]u32 = .{0} ** 32,
        memory_clocks: std.AutoHashMap(u32, u32),
        /// Whole-execution first-access values required by typed retirement's
        /// state-chain invariants.  Segment snapshots use a separate boundary
        /// baseline and therefore never confuse these with segment entry.
        memory_initials: std.AutoHashMap(u32, u32),
        pending_continuation: ?result_mod.ContinuationToken = null,
        session_tag: u64,
        continuation_enabled: bool,
        status: SessionStatus = .active,

        pub fn init(
            allocator: std.mem.Allocator,
            elf_bytes: []const u8,
            options: SessionOptions,
        ) !Self {
            return initInternal(allocator, elf_bytes, options, true);
        }

        /// One-shot construction avoids the continuation-tag ELF scan.  This
        /// is intentionally separate from `init`: a resumable caller can never
        /// accidentally create untagged continuation capabilities.
        pub fn initLegacy(
            allocator: std.mem.Allocator,
            elf_bytes: []const u8,
            options: SessionOptions,
        ) !Self {
            return initInternal(allocator, elf_bytes, options, false);
        }

        fn initInternal(
            allocator: std.mem.Allocator,
            elf_bytes: []const u8,
            options: SessionOptions,
            build_continuation_tag: bool,
        ) !Self {
            var mem = try Memory.initFallible(allocator);
            errdefer mem.deinit();
            const elf_info = try elf_loader.loadElfForProfile(elf_bytes, &mem, profile);
            if (options.input.len > elf_info.input_end -| elf_info.input_start)
                return error.InputTooLarge;
            if (options.input.len != 0)
                mem.writeSlice(elf_info.input_start, options.input);

            const owned_input = try allocator.dupe(u8, options.input);
            errdefer allocator.free(owned_input);
            var instruction_cache = try decode_cache.Cache.init(allocator);
            errdefer instruction_cache.deinit();
            var execution_trace = trace.Trace.init(allocator);
            execution_trace.initial_pc = elf_info.entry_point;
            errdefer execution_trace.deinit();

            var rv_cpu = Cpu.init(elf_info.entry_point, elf_info.stack_pointer);
            rv_cpu.writeReg(3, elf_info.global_pointer);
            return .{
                .allocator = allocator,
                .memory = mem,
                .elf_info = elf_info,
                .cpu = rv_cpu,
                .instruction_cache = instruction_cache,
                .execution_trace = execution_trace,
                .host = options.host,
                .stop_on_halt_flag = options.stop_on_halt_flag,
                .strict_completion = options.strict_completion,
                .input = owned_input,
                .memory_clocks = std.AutoHashMap(u32, u32).init(allocator),
                .memory_initials = std.AutoHashMap(u32, u32).init(allocator),
                .session_tag = if (build_continuation_tag)
                    sessionTag(elf_bytes, options.input, profile)
                else
                    0,
                .continuation_enabled = build_continuation_tag,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.input) |input| self.allocator.free(input);
            self.memory_initials.deinit();
            self.memory_clocks.deinit();
            self.execution_trace.deinit();
            self.instruction_cache.deinit();
            self.memory.deinit();
            self.* = undefined;
        }

        /// Execute the first bounded segment.  Budget exhaustion yields an
        /// explicit continuation rather than manufacturing a completion.
        pub fn startSegment(
            self: *Self,
            step_budget: usize,
        ) !ConfiguredSegmentResult(profile) {
            if (!self.continuation_enabled) return error.ContinuationUnavailable;
            if (self.status == .poisoned) return error.SessionPoisoned;
            if (self.status == .complete) return error.SessionComplete;
            if (self.next_segment_index != 0 or self.pending_continuation != null)
                return error.SessionAlreadyStarted;
            if (step_budget == 0) return error.ZeroSegmentStepBudget;
            return self.executeSegment(step_budget, .yield) catch |err| {
                self.status = .poisoned;
                return err;
            };
        }

        /// Resume after validating the caller's exact copy of the previous
        /// continuation.  A mismatch is rejected before allocating a trace or
        /// mutating CPU, memory, clocks, cache, or session generation.
        pub fn resumeSegment(
            self: *Self,
            continuation: result_mod.ContinuationToken,
            step_budget: usize,
        ) !ConfiguredSegmentResult(profile) {
            if (!self.continuation_enabled) return error.ContinuationUnavailable;
            if (self.status == .poisoned) return error.SessionPoisoned;
            if (self.status == .complete) return error.SessionComplete;
            const expected = self.pending_continuation orelse
                return error.ContinuationRequired;
            if (!std.meta.eql(expected, continuation))
                return error.ContinuationMismatch;
            if (step_budget == 0) return error.ZeroSegmentStepBudget;
            return self.executeSegment(step_budget, .yield) catch |err| {
                self.status = .poisoned;
                return err;
            };
        }

        /// Backwards-compatible terminal execution used by every legacy
        /// one-shot wrapper.  It shares the segmented instruction loop exactly.
        pub fn runLegacy(
            self: *Self,
            max_steps: usize,
        ) !ConfiguredRunResult(profile) {
            if (self.status == .poisoned) return error.SessionPoisoned;
            if (self.status == .complete) return error.SessionComplete;
            if (self.next_segment_index != 0 or self.pending_continuation != null)
                return error.SessionAlreadyStarted;
            var segment = self.executeSegment(max_steps, .legacy_terminal) catch |err| {
                self.status = .poisoned;
                return err;
            };
            if (comptime profile == .rv32im_zkvm_poseidon2_v1) {
                errdefer segment.deinit();
                const base = segmentToRunResult(&segment.base);
                const result = result_mod.Poseidon2RunResult{
                    .base = base,
                    .calls = segment.calls,
                    .execution_rows = segment.execution_rows,
                };
                segment = undefined;
                return result;
            } else {
                errdefer segment.deinit();
                return segmentToRunResult(&segment);
            }
        }

        fn executeSegment(
            self: *Self,
            step_budget: usize,
            exhaustion_policy: ExhaustionPolicy,
        ) !ConfiguredSegmentResult(profile) {
            if (step_budget == 0 and exhaustion_policy == .yield)
                return error.ZeroSegmentStepBudget;
            if (self.next_segment_index == std.math.maxInt(u32))
                return error.SegmentIndexOverflow;

            const segment_index = self.next_segment_index;
            const entry_cpu = self.cpu;
            const trace_start = self.execution_trace.rows.items.len;
            const first_cycle = std.math.add(u64, self.global_steps, 1) catch
                return error.ExecutionClockOutOfRange;

            // Every allocation needed to seed the next trace occurs before the
            // first instruction, keeping a rejected continuation and setup OOM
            // free of architectural side effects.
            var chain_tracker = try self.seedTracker();
            errdefer chain_tracker.deinit();
            var memory_baseline: ?memory_state.SegmentBaseline = null;
            if (exhaustion_policy == .yield) {
                memory_baseline = try memory_state.captureSegmentBaseline(
                    self.allocator,
                    &self.memory,
                    &chain_tracker,
                    self.elf_info.memory_layout,
                );
            }
            defer if (memory_baseline) |*baseline| baseline.deinit(self.allocator);
            var entry_access_clocks = if (exhaustion_policy == .yield)
                try captureAccessClockBoundary(
                    self.allocator,
                    self.register_clocks,
                    &self.memory_clocks,
                )
            else
                emptyAccessClockBoundary();
            errdefer entry_access_clocks.deinit(self.allocator);
            var extension = try ExtensionState(profile).init(self.allocator, step_budget);
            defer extension.deinit();

            var local_steps: usize = 0;
            var completion_reason: ?result_mod.CompletionReason = null;
            var exit_code: ?u32 = null;
            while (completion_reason == null) {
                if (self.stop_on_halt_flag and
                    self.memory.readU32(self.elf_info.halt_flag) != 0)
                {
                    completion_reason = .halt_flag;
                    break;
                }
                if (local_steps >= step_budget) {
                    if (exhaustion_policy == .yield) break;
                    if (self.strict_completion) return error.MaxStepsExceeded;
                    completion_reason = .max_steps;
                    break;
                }

                const next_clock = std.math.add(u64, self.global_steps, 1) catch
                    return error.ExecutionClockOutOfRange;
                if (next_clock > std.math.maxInt(u32) or
                    access_clock.maximum(@intCast(next_clock)) > std.math.maxInt(u32))
                {
                    return error.ExecutionClockOutOfRange;
                }
                const outcome = try self.retireOne(
                    @intCast(next_clock),
                    &self.execution_trace,
                    &chain_tracker,
                    &extension,
                );
                if (outcome.retired) {
                    self.global_steps = next_clock;
                    local_steps += 1;
                }
                completion_reason = outcome.completion_reason;
                exit_code = outcome.exit_code;
            }
            self.execution_trace.final_pc = self.cpu.pc;

            // Extract this segment only after execution.  Retirement keeps one
            // cumulative trace for its global clock/index invariant, while the
            // proof boundary owns a compact independent range.
            var segment_trace = if (exhaustion_policy == .legacy_terminal) blk: {
                const owned = self.execution_trace;
                self.execution_trace = trace.Trace.init(self.allocator);
                break :blk owned;
            } else blk: {
                var owned = trace.Trace.init(self.allocator);
                errdefer owned.deinit();
                owned.initial_pc = entry_cpu.pc;
                owned.final_pc = self.cpu.pc;
                try owned.rows.appendSlice(
                    self.allocator,
                    self.execution_trace.rows.items[trace_start..],
                );
                owned.step_count = owned.rows.items.len;
                break :blk owned;
            };
            errdefer segment_trace.deinit();

            const completed = completion_reason != null;
            const captured_output = if (completed)
                try captureOutput(
                    self.allocator,
                    &self.memory,
                    &chain_tracker,
                    self.elf_info,
                    self.strict_completion,
                )
            else
                CapturedOutput.empty();
            errdefer {
                if (captured_output.bytes) |output| self.allocator.free(output);
                self.allocator.free(captured_output.words);
            }
            const completion_address: u32 = if (completion_reason) |reason|
                switch (reason) {
                    .halt_flag => self.elf_info.halt_flag,
                    .self_loop => self.cpu.pc,
                    else => 0,
                }
            else
                0;
            const completion_value: u32 = if (completion_reason) |reason|
                switch (reason) {
                    .halt_flag => self.memory.readU32(self.elf_info.halt_flag),
                    .self_loop => self.memory.readU32(self.cpu.pc),
                    else => 0,
                }
            else
                0;
            const completion_clock: u32 = if (completion_reason == .halt_flag)
                chain_tracker.mem_last_clk.get(self.elf_info.halt_flag & ~@as(u32, 3)) orelse 0
            else
                0;
            const role = memory_state.SegmentRole{
                .is_first = segment_index == 0,
                .is_last = completed,
            };
            var rw_memory = if (memory_baseline) |baseline|
                try memory_state.captureSegment(
                    self.allocator,
                    &self.memory,
                    &chain_tracker,
                    self.elf_info.memory_layout,
                    role,
                    captured_output.len,
                    if (completion_reason == .halt_flag)
                        self.elf_info.halt_flag & ~@as(u32, 3)
                    else
                        null,
                    baseline,
                )
            else
                try memory_state.capture(
                    self.allocator,
                    &self.memory,
                    &chain_tracker,
                    self.elf_info.memory_layout,
                    role,
                    captured_output.len,
                    if (completion_reason == .halt_flag)
                        self.elf_info.halt_flag & ~@as(u32, 3)
                    else
                        null,
                );
            errdefer rw_memory.deinit(self.allocator);
            var exit_access_clocks = if (exhaustion_policy == .yield)
                try captureAccessClockBoundary(
                    self.allocator,
                    chain_tracker.reg_last_clk,
                    &chain_tracker.mem_last_clk,
                )
            else
                emptyAccessClockBoundary();
            errdefer exit_access_clocks.deinit(self.allocator);

            if (exhaustion_policy == .yield) {
                // Clone the final maps for the owned segment tracker, then
                // transfer their originals to the session.  Exactly one
                // full-map copy is paid per proof boundary; legacy one-shot
                // execution follows the zero-copy branch below.
                var result_memory_clocks = try cloneClockMap(
                    self.allocator,
                    &chain_tracker.mem_last_clk,
                );
                errdefer result_memory_clocks.deinit();
                self.memory_clocks.deinit();
                self.memory_clocks = chain_tracker.mem_last_clk;
                chain_tracker.mem_last_clk = result_memory_clocks;
                result_memory_clocks = std.AutoHashMap(u32, u32).init(self.allocator);

                // The compact snapshot now owns the segment-entry words and
                // StateChainTracker deliberately releases its baselines before
                // publication, so transfer the cumulative map directly rather
                // than cloning data the result would immediately discard.
                self.memory_initials.deinit();
                self.memory_initials = chain_tracker.mem_initial;
                chain_tracker.mem_initial = std.AutoHashMap(u32, u32).init(self.allocator);
                self.register_clocks = chain_tracker.reg_last_clk;
            }
            chain_tracker.releaseMemoryBaselines();

            const continuation: ?result_mod.ContinuationToken = if (completed)
                null
            else
                .{
                    .session_tag = self.session_tag,
                    .next_segment_index = segment_index + 1,
                    .next_cycle = self.global_steps + 1,
                    .cpu = self.cpu,
                    .rw_memory = rw_memory.exitIdentity(),
                    .access_clocks = exit_access_clocks.identity(),
                };

            const owned_input = if (segment_index == 0) self.input else null;
            if (segment_index == 0) self.input = null;
            const base_result = result_mod.SegmentResult{
                .segment_index = segment_index,
                .segment_role = role,
                .global_first_cycle = first_cycle,
                .cycle_count = local_steps,
                .entry_cpu = entry_cpu,
                .exit_cpu = self.cpu,
                .completion_reason = completion_reason,
                .completion_address = completion_address,
                .completion_value = completion_value,
                .completion_clock = completion_clock,
                .continuation = continuation,
                .input = owned_input,
                .input_start = self.elf_info.input_start,
                .input_end = self.elf_info.input_end,
                .output = captured_output.bytes,
                .output_len = captured_output.len,
                .output_len_addr = self.elf_info.output_len,
                .output_data_addr = self.elf_info.output_data,
                .output_end_addr = self.elf_info.output_end,
                .output_words = captured_output.words,
                .execution_trace = segment_trace,
                .state_chain_tracker = chain_tracker,
                .entry_access_clocks = entry_access_clocks,
                .exit_access_clocks = exit_access_clocks,
                .rw_memory = rw_memory,
                .exit_code = exit_code,
                .allocator = self.allocator,
            };
            self.next_segment_index = segment_index + 1;
            self.pending_continuation = continuation;
            self.status = if (completed) .complete else .active;

            if (comptime profile == .rv32im_zkvm_poseidon2_v1) {
                return .{
                    .base = base_result,
                    .calls = extension.calls.freeze(),
                    .execution_rows = extension.rows.freeze(),
                };
            }
            return base_result;
        }

        fn seedTracker(self: *const Self) !state_chain.StateChainTracker {
            var tracker = state_chain.StateChainTracker.init(self.allocator);
            errdefer tracker.deinit();
            tracker.reg_last_clk = self.register_clocks;
            tracker.mem_last_clk = try cloneClockMap(self.allocator, &self.memory_clocks);
            tracker.mem_initial = try cloneClockMap(self.allocator, &self.memory_initials);
            return tracker;
        }

        fn retireOne(
            self: *Self,
            execution_clock: u32,
            exec_trace: *trace.Trace,
            chain_tracker: *state_chain.StateChainTracker,
            extension: *ExtensionState(profile),
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
            if (comptime profile == .rv32im_zkvm_poseidon2_v1) {
                if (@as(u7, @truncate(inst_word)) == custom0.major_opcode) {
                    try guest_precompile.poseidon2_v1.execute(
                        profile,
                        inst_word,
                        execution_clock,
                        &self.cpu,
                        &self.memory,
                        self.elf_info.memory_layout,
                        chain_tracker,
                        &extension.calls,
                        &extension.rows,
                    );
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

            if (try generated_retirement.retireAtomic(
                &self.cpu,
                &self.memory,
                exec_trace,
                chain_tracker,
                inst,
                inst_word,
                execution_clock,
            )) return .{ .retired = true };

            const rs2_val = self.cpu.readReg(inst.rs2);
            const rd_prev_val = self.cpu.readReg(inst.rd);
            const access = access_witness.capture(chain_tracker, inst, execution_clock);
            const memory_access_clock = access_clock.encode(execution_clock, .third);
            var mem_addr: u32 = 0;
            var mem_val: u32 = 0;
            var mem_prev_word: u32 = 0;
            var mem_prev_clk: u32 = 0;
            const is_load = decode.isLoad(inst.opcode);
            const is_store = decode.isStore(inst.opcode);
            if (is_load or is_store) {
                mem_addr = rs1_val +% @as(u32, @bitCast(inst.imm));
                const aligned_addr = mem_addr & ~@as(u32, 3);
                mem_prev_word = self.memory.readU32(aligned_addr);
                mem_prev_clk = state_chain.StateChainTracker.effectivePreviousClock(
                    chain_tracker.mem_last_clk.get(aligned_addr) orelse 0,
                    memory_access_clock,
                );
                if (is_load) {
                    mem_val = switch (inst.opcode) {
                        .LB, .LBU => @as(u32, self.memory.readByte(mem_addr)),
                        .LH, .LHU => @as(u32, self.memory.readU16(mem_addr)),
                        .LW => self.memory.readU32(mem_addr),
                        else => 0,
                    };
                } else {
                    mem_val = rs2_val;
                }
            }

            var halted = false;
            var completion_reason: ?result_mod.CompletionReason = null;
            var exit_code: ?u32 = null;
            execute_mod.execute(&self.cpu, &self.memory, inst) catch |err| switch (err) {
                error.Ecall => {
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
                error.Ebreak => {
                    completion_reason = .ebreak;
                    halted = true;
                },
                error.GeneratedRetirementRequired => return error.GeneratedRetirementRequired,
                error.MisalignedMemoryAccess => return error.MisalignedMemoryAccess,
                error.InstructionAddressMisaligned => return error.InstructionAddressMisaligned,
            };

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
                .mem_addr = mem_addr,
                .mem_val = mem_val,
                .mem_prev_word = mem_prev_word,
                .mem_next_word = if (is_load or is_store)
                    self.memory.readU32(mem_addr & ~@as(u32, 3))
                else
                    0,
                .mem_prev_clk = mem_prev_clk,
                .is_load = is_load,
                .is_store = is_store,
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
            if (is_load or is_store) {
                const aligned_addr = mem_addr & ~@as(u32, 3);
                try chain_tracker.recordMemTransition(
                    aligned_addr,
                    memory_access_clock,
                    mem_prev_word,
                    self.memory.readU32(aligned_addr),
                );
            }
            if (halted) return .{
                .retired = true,
                .completion_reason = completion_reason,
                .exit_code = exit_code,
            };
            if (self.cpu.pc == pc_before)
                return .{ .retired = true, .completion_reason = .stalled_pc };
            return .{ .retired = true };
        }
    };
}

const segmentToRunResult = session_support.segmentToRunResult;
const captureAccessClockBoundary = session_support.captureAccessClockBoundary;
const emptyAccessClockBoundary = session_support.emptyAccessClockBoundary;
const cloneClockMap = session_support.cloneClockMap;
const CapturedOutput = session_support.CapturedOutput;
const captureOutput = session_support.captureOutput;
const sessionTag = session_support.sessionTag;
