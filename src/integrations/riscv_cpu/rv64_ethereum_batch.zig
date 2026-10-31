//! Bounded native batch bookkeeping. Advice and first/last RAM transitions are
//! captured by the caller in the same execution walk. No replay or RAM snapshot.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const air = frontend.rv64_air;
const Full = @import("rv64_full.zig");
const CPU = @import("rv64_keccak_cpu.zig");
const Secp = @import("rv64_ethereum_secp_context.zig");
const R = air.memory;
const PublicCell = @import("rv64_full_statement.zig").Cell;
const Modulus = @import("stwo_core").fields.m31.Modulus;

/// The same capture walk serves complete execution and retained-batch reproving.
/// A failed append aborts the batch; callers never continue a partial capture.
pub fn captureNext(session: *rv.ethereum_services.Session, tape: *rv.compact_tape.Tape, capture: *rv.boundary_capture.Capture, batch: *Batch) !void {
    if (batch.tape != tape or batch.capture != capture) return error.InvalidEthereumBatchSeed;
    var event: rv.ethereum_services.Event = undefined;
    const record = if (try session.step(&event)) |row| blk: {
        try tape.append(row);
        try capture.append(row, session.keccak.base.memory);
        break :blk row;
    } else blk: {
        try tape.appendEvent(event);
        try capture.appendEvent(event, session.keccak.base.memory);
        break :blk event.retirement();
    };
    try batch.observe(record);
}

pub const Batch = struct {
    authority: *const Full.ProgramAuthority,
    tape: *const rv.compact_tape.Tape,
    capture: *const rv.boundary_capture.Capture,
    initial_registers: [32]u64,
    initial_pc: u64,
    initial_clock: u64,
    first_ids: [3]u32,
    register_clocks: [32]u32 = @splat(0),
    steps: u32 = 0,
    next_pc: u64,
    division_requests: u32 = 0,
    multiplication_requests: u32 = 0,
    calls: [3]u32 = @splat(0),
    state_policy: air.state_policy.Policy = .cyclic_v2,

    pub fn init(authority: *const Full.ProgramAuthority, tape: *const rv.compact_tape.Tape, capture: *const rv.boundary_capture.Capture, initial_registers: [32]u64, first_ids: [3]u32) !Batch {
        if (authority.profile != .ethereum_services_v1 and authority.profile != .ethereum_services_v2) return error.InvalidEthereumBatchProfile;
        if (tape.execution_profile != authority.profile or tape.len != 0 or capture.steps != 0 or tape.initial_clock != capture.initial_clock or initial_registers[0] != 0) return error.InvalidEthereumBatchSeed;
        _ = try authority.program.lookup(tape.initial_pc);
        for (first_ids) |id| if (id == 0 or id >= Modulus) return error.InvalidEthereumBatchSeed;
        return .{ .authority = authority, .tape = tape, .capture = capture, .initial_registers = initial_registers, .initial_pc = tape.initial_pc, .initial_clock = tape.initial_clock, .first_ids = first_ids, .next_pc = tape.initial_pc };
    }
    /// Call once per retirement, including Event.retirement() for services.
    /// Fallible tape/capture appends stay with the caller; on any failure abort
    /// this native batch instead of advancing execution with partial advice.
    pub fn observe(self: *Batch, record: rv.machine.Retirement) !void {
        if (self.tape.execution_profile != self.authority.profile or self.tape.initial_pc != self.initial_pc or self.tape.initial_clock != self.initial_clock or self.capture.initial_clock != self.initial_clock) return error.InvalidEthereumBatchSeed;
        if (self.steps >= rv.compact_tape.MAX_STEPS or record.clock != self.initial_clock + self.steps + 1 or record.pc.toInt() != self.next_pc) return error.InvalidEthereumBatchClock;
        const row = try self.authority.program.lookup(record.pc.toInt());
        const decoded = self.authority.program.decoded[row];
        if (record.instruction != decoded.raw or record.opcode != decoded.instruction.opcode) return error.InvalidEthereumBatchInstruction;
        const inst = decoded.instruction;
        const effects = rv.execution_profile.effects(self.authority.profile, inst.opcode);
        var kind: ?usize = null;
        if (inst.opcode == .ECALL) {
            const tag = record.rhs.toInt();
            kind = if (tag == rv.execution_profile.KECCAK_TAG) 0 else switch (self.authority.profile) {
                .ethereum_services_v1 => if (tag == rv.execution_profile.SECP_ADD_TAG) 1 else if (tag == rv.execution_profile.SECP_DOUBLE_TAG) 2 else return error.InvalidEthereumBatchService,
                .ethereum_services_v2 => if (tag == rv.execution_profile.SECP_ADD_WORD_TAG) 1 else if (tag == rv.execution_profile.SECP_DOUBLE_WORD_TAG) 2 else return error.InvalidEthereumBatchService,
                else => unreachable,
            };
            const k = kind.?;
            if (@as(u64, self.first_ids[k]) + self.calls[k] >= Modulus) return error.InvalidEthereumBatchService;
        }
        const tick = 4 * self.steps;
        if (effects.reads_rs1 and inst.rs1 != 0) self.register_clocks[inst.rs1] = tick + 1;
        if (effects.reads_rs2 and inst.rs2 != 0) self.register_clocks[inst.rs2] = tick + 2;
        if (effects.writes_rd and inst.rd != 0) self.register_clocks[inst.rd] = tick + 3;
        switch (inst.opcode) {
            .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW => self.division_requests += 1,
            .MUL, .MULH, .MULHSU, .MULHU, .MULW => self.multiplication_requests += 1,
            else => {},
        }
        if (kind) |k| self.calls[k] += 1;
        self.steps += 1;
        self.next_pc = record.next_pc.toInt();
    }
    /// Must run while final_memory still holds this batch's final image. Reads
    /// touched chunks once and reconstructs their before words from capture.
    pub fn finish(self: *const Batch, a: std.mem.Allocator, final_cpu: *const rv.machine.Cpu, final_memory: *const rv.memory.Memory, policy: *const R.policy.Policy, geometry: R.values.Geometry) !Finished {
        if (self.tape.execution_profile != self.authority.profile or self.tape.initial_pc != self.initial_pc or self.tape.initial_clock != self.initial_clock or self.capture.initial_clock != self.initial_clock) return error.InvalidEthereumBatchSeed;
        if (self.steps == 0 or self.steps != self.tape.len or self.steps != self.capture.steps or final_cpu.retired != self.initial_clock + self.steps or final_cpu.pc != self.next_pc or final_cpu.regs[0] != 0 or self.tape.service_calls.items.len != self.calls[0] or self.tape.secp_calls.items.len != @as(u64, self.calls[1]) + self.calls[2]) return error.InvalidEthereumBatchBoundary;
        var actual: [3]u32 = @splat(0);
        for (self.tape.service_calls.items) |call| {
            if (call.call_id != @as(u64, self.first_ids[0]) + actual[0]) return error.InvalidEthereumBatchService;
            actual[0] += 1;
        }
        for (self.tape.secp_calls.items) |call| {
            const k: usize = if (call.kind == .add) 1 else 2;
            if (call.call_id != @as(u64, self.first_ids[k]) + actual[k]) return error.InvalidEthereumBatchService;
            actual[k] += 1;
        }
        if (!std.mem.eql(u32, &actual, &self.calls)) return error.InvalidEthereumBatchService;
        const captured = try self.capture.sorted(a);
        errdefer a.free(captured);
        const cells = try a.alloc(PublicCell, captured.len);
        errdefer a.free(cells);
        const clocks = try a.alloc(u32, captured.len);
        errdefer a.free(clocks);
        for (captured, cells, clocks) |native, *cell, *clock| {
            cell.* = .{ .address = native.address, .initial = native.initial, .final = native.final, .readable = native.rights & 1 != 0, .writable = native.rights & 2 != 0 };
            clock.* = native.terminal_clock;
        }
        var public = CPU.Public{ .control_policy = self.authority.control_policy, .execution_profile = self.authority.profile, .arithmetic_policy = .division_multiplication_services_v3, .state_policy = self.state_policy, .division_requests = self.division_requests, .multiplication_requests = self.multiplication_requests, .division_log = requestLog(self.division_requests), .multiplication_log = requestLog(self.multiplication_requests), .keccak_calls = self.calls[0], .first_call_id = self.first_ids[0], .roster = if (self.calls[0] == 0) .none else .paired, .statement = .{ .program = self.authority.expectedProgram(), .steps = self.steps, .initial_pc = self.initial_pc, .final_pc = final_cpu.pc, .initial_registers = self.initial_registers, .final_registers = final_cpu.regs, .register_clocks = self.register_clocks, .cells = &.{}, .memory_clocks = &.{}, .opcodes = self.authority.opcodes } };
        if (self.division_requests == 0) public.division_roster = .none;
        if (self.multiplication_requests == 0) public.multiplication_roster = .none;
        if (self.calls[0] != 0) {
            public.keccak_log = try air.crypto.keccak.layout.logSize(self.calls[0]);
            public.bridge_log = try air.crypto.keccak.bridge.trace.logSize(self.calls[0]);
        }
        var groups: [2]Secp.Group = .{ .{}, .{} };
        for (&groups, self.calls[1..], self.first_ids[1..], 0..) |*group, count, first, k| {
            group.first_id = first;
            if (count != 0) group.* = .{ .roster = .present, .calls = count, .first_id = first, .geometry = try Secp.Source.Geometry.minimal(if (k == 0) .add else .double, count) };
        }
        public.secp = .{ .add = groups[0], .double = groups[1] };
        try public.validate();
        const openings: ?R.openings.Owned = if (captured.len == 0) null else try R.openings.Owned.init(a, geometry, policy, final_memory, captured);
        return .{ .allocator = a, .public = public, .captured = captured, .cells = cells, .memory_clocks = clocks, .openings = openings };
    }
};
fn requestLog(count: u32) u32 {
    return @max(5, std.math.log2_int_ceil(u32, @max(1, count)));
}
pub const Finished = struct {
    allocator: std.mem.Allocator,
    public: CPU.Public,
    captured: []rv.boundary_capture.Cell,
    cells: []PublicCell,
    memory_clocks: []u32,
    openings: ?R.openings.Owned,
    pub fn takeOpenings(self: *Finished) ?R.openings.Owned {
        const value = self.openings;
        self.openings = null;
        return value;
    }
    pub fn deinit(self: *Finished) void {
        if (self.openings) |*value| value.deinit();
        self.allocator.free(self.memory_clocks);
        self.allocator.free(self.cells);
        self.allocator.free(self.captured);
        self.* = undefined;
    }
};
