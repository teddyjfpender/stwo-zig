//! Pure original-execution relation closure. This module verifies no proof and
//! grants no authority: callers supply only freshly authenticated source exports
//! after independently admitting the ELF, windows, exact roster and providers.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Native = @import("block_v7_native_source_v1.zig");
const Caller = @import("block_v7_caller_joint_source_v1.zig");
const Memory = @import("block_v7_memory_claim_closure_v1.zig");
pub const Totals = struct { events: u64, fetches: u64 };
pub const Accumulator = struct {
    allocator: std.mem.Allocator,
    states: []Q,
    registers: []Q,
    native_seen: []bool,
    caller_seen: []bool,
    expected_callers: usize,
    callers: usize = 0,
    program: Q,
    transition: Q,
    tables: [6]Q,
    expected_fetches: u64,
    expected_events: u64,
    fetches: u64 = 0,
    events: u64 = 0,
    pub fn init(a: std.mem.Allocator, windows: usize, callers: usize, program: Q, fetches: u64, tables: [6]Q, memory: Memory.Open) !Accumulator {
        if (windows == 0 or callers > windows) return error.InvalidV7ExecutionRoster;
        const states = try a.alloc(Q, windows);
        errdefer a.free(states);
        const registers = try a.alloc(Q, windows);
        errdefer a.free(registers);
        const native_seen = try a.alloc(bool, windows);
        errdefer a.free(native_seen);
        const caller_seen = try a.alloc(bool, windows);
        @memset(states, Q.zero());
        @memset(registers, Q.zero());
        @memset(native_seen, false);
        @memset(caller_seen, false);
        return .{ .allocator = a, .states = states, .registers = registers, .native_seen = native_seen, .caller_seen = caller_seen, .expected_callers = callers, .program = program, .transition = memory.transition, .tables = tables, .expected_fetches = fetches, .expected_events = memory.event_count };
    }
    pub fn deinit(self: *Accumulator) void {
        self.allocator.free(self.states);
        self.allocator.free(self.registers);
        self.allocator.free(self.native_seen);
        self.allocator.free(self.caller_seen);
        self.* = undefined;
    }
    pub fn addNative(self: *Accumulator, index: usize, source: Native.Exports) !void {
        if (index >= self.states.len or self.native_seen[index]) return error.InvalidV7ExecutionRoster;
        if (!source.ordinary_memory_residual.isZero() or !source.auxiliary_clock_memory.isZero()) return error.UnclosedV7NativeRelations;
        self.native_seen[index] = true;
        self.states[index] = self.states[index].add(source.state_residual);
        self.registers[index] = self.registers[index].add(source.register_residual);
        try self.add(source.program_sum, source.transition_sum, source.fetch_count, source.event_count, source.table_requests, source.byte_requests);
    }
    pub fn addCaller(self: *Accumulator, index: usize, source: Caller.Exports) !void {
        if (index >= self.states.len or self.caller_seen[index] or self.callers >= self.expected_callers) return error.InvalidV7CallerRoster;
        if (!source.internal_residual.isZero() or !source.auxiliary_clock_memory.isZero()) return error.UnclosedV7CallerRelations;
        self.caller_seen[index] = true;
        self.callers += 1;
        self.states[index] = self.states[index].add(source.state_sum);
        self.registers[index] = self.registers[index].add(source.register_sum);
        try self.add(source.program_sum, source.transition_sum, source.fetch_count, source.event_count, source.table_requests, source.byte_requests);
    }
    fn add(self: *Accumulator, program: Q, transition: Q, fetches: u64, events: u64, tables: [6]Q, bytes: Q) !void {
        self.program = self.program.add(program);
        self.transition = self.transition.add(transition);
        self.fetches = try std.math.add(u64, self.fetches, fetches);
        self.events = try std.math.add(u64, self.events, events);
        for (&self.tables, tables) |*sum, request| sum.* = sum.add(request);
        const range = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_8_8);
        self.tables[range] = self.tables[range].add(bytes);
    }
    pub fn finish(self: *const Accumulator) !Totals {
        for (self.native_seen) |seen| if (!seen) return error.InvalidV7ExecutionRoster;
        if (self.callers != self.expected_callers) return error.InvalidV7CallerRoster;
        for (self.states, self.registers) |state, register| if (!state.isZero() or !register.isZero()) return error.UnclosedV7WindowRelations;
        if (!self.program.isZero() or !self.transition.isZero() or self.fetches != self.expected_fetches or self.events != self.expected_events) return error.UnclosedV7ExecutionRelations;
        for (self.tables) |sum| if (!sum.isZero()) return error.UnclosedV7LookupRelations;
        return .{ .events = self.events, .fetches = self.fetches };
    }
};
