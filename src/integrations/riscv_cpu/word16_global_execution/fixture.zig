//! Split one native capture; no VM re-execution, only advice projection.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const Native = @import("../word16_execution/prepared.zig").Prepared;
const Program = @import("../word16_execution/program.zig").Program;
const Setup = @import("../word16_execution/setup.zig").Setup;
const Full = @import("../tests/rv64_word16_execution_fixture.zig").Fixture;
const Execution = @import("execution.zig");
const P = @import("protocol.zig");
const Memory = @import("../word16_execution/memory/statement.zig");
pub const Case = struct {
    allocator: std.mem.Allocator,
    fixture: Full,
    setups: [2]Setup,
    bundle: Execution.Bundle,
    program_identity: [32]u8,
    pub fn expected(self: *const Case) P.Expected {
        return expectedOf(&self.fixture, self.program_identity);
    }
    pub fn keys(self: *const Case) [2]*const Setup {
        return .{ &self.setups[0], &self.setups[1] };
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        for (&self.setups) |*s| s.deinit();
        self.fixture.deinit();
    }
    pub fn init(a: std.mem.Allocator) !Case {
        var fixture = try Full.init(a);
        errdefer fixture.deinit();
        var program = try Program.initWithAuthority(a, &fixture.image.authority);
        defer program.deinit();
        const cut: usize = 11;
        var tapes: [2]front.rv64.compact_tape.Tape = undefined;
        tapes[0] = try front.rv64.compact_tape.Tape.init(a, @intCast(cut), fixture.tape.initial_pc, 0, .ethereum_services_v2);
        defer tapes[0].deinit();
        const split_pc = fixture.tape.storage[cut - 1].next_pc;
        tapes[1] = try front.rv64.compact_tape.Tape.init(a, @intCast(fixture.tape.len - cut), split_pc, cut, .ethereum_services_v2);
        defer tapes[1].deinit();
        var boundaries: [2]X.types.Boundary = undefined;
        var registers = fixture.boundary.initial_registers;
        var pc = fixture.boundary.initial_pc;
        for (&tapes, 0..) |*tape, shard| {
            const begin: usize = if (shard == 0) 0 else cut;
            const end: usize = if (shard == 0) cut else fixture.tape.len;
            const initial = registers;
            var clocks: [32]u32 = @splat(0);
            for (begin..end) |index| {
                const entry = program.entries[try program.lookup(pc)];
                const record = try fixture.tape.restore(index, .{ .raw = entry.raw, .instruction = entry.instruction }, .global);
                try tape.append(record);
                const tick: u32 = @intCast(4 * (index - begin));
                if (record.rs1 != 0) clocks[record.rs1] = tick + 1;
                if (record.rs2 != 0) clocks[record.rs2] = tick + 2;
                if (record.writes_rd) {
                    clocks[record.rd] = tick + 3;
                    registers[record.rd] = record.result.toInt();
                }
                pc = record.next_pc.toInt();
            }
            boundaries[shard] = .{ .steps = @intCast(end - begin), .initial_pc = tape.initial_pc, .final_pc = pc, .initial_registers = initial, .final_registers = registers, .register_clocks = clocks };
        }
        var native0 = try Native.init(a, &program, boundaries[0], 1, 5, &tapes[0], .{});
        defer native0.deinit();
        var native1 = try Native.init(a, &program, boundaries[1], 2, 5, &tapes[1], .{});
        defer native1.deinit();
        var advice = try Execution.collectAdvice(a, &.{ &native0, &native1 }, Memory.fromOwner(&fixture.image));
        defer advice.deinit();
        if (advice.events[1][0].before.epoch != 1 or advice.events[1][0].after.epoch != 2) return error.MissingCrossShardPredecessor;
        var g0 = try native0.geometry();
        var g1 = try native1.geometry();
        g0.boundary_log = try @import("../word16_execution/coverage.zig").minimalPrefixLog(@intCast(advice.initial.len));
        g1.boundary_log = g0.boundary_log;
        var setup0 = try Setup.initWithAuthority(a, &fixture.image.authority, g0);
        errdefer setup0.deinit();
        var setup1 = try Setup.initWithAuthority(a, &fixture.image.authority, g1);
        errdefer setup1.deinit();
        const bundle = try Execution.produceWithAdvice(a, &.{ &setup0, &setup1 }, &.{ &native0, &native1 }, &advice, expectedOf(&fixture, program.identity));
        return .{ .allocator = a, .fixture = fixture, .setups = .{ setup0, setup1 }, .bundle = bundle, .program_identity = program.identity };
    }
};
fn expectedOf(fixture: *const Full, program_identity: [32]u8) P.Expected {
    return .{ .program_identity = program_identity, .admission = .{ .image = Memory.fromOwner(&fixture.image), .image_identity = fixture.image.identity, .initial_pc = fixture.image.initial_pc, .initial_registers = fixture.image.initial_registers }, .total_steps = fixture.boundary.steps, .max_total_steps = fixture.boundary.steps, .final_pc = fixture.boundary.final_pc, .final_registers = fixture.boundary.final_registers };
}
