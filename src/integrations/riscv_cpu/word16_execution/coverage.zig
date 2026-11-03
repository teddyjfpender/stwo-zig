//! Exact semantic-family census from immutable ROM and captured PC advice.
//! This is transport/planning metadata, never a substitute for physical buses.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const Program = @import("program.zig").Program;
pub const Counts = struct {
    alu: u32 = 0,
    binary: u32 = 0,
    shift: u32 = 0,
    jalr: u32 = 0,
    division: u32 = 0,
    multiplication: u32 = 0,
    memory: u32 = 0,
    service: u32 = 0,
    pub fn fromTape(program: *const Program, tape: *const rv.compact_tape.Tape) !Counts {
        if (tape.len == 0 or tape.len > tape.storage.len or !@import("../rv64_ethereum_batch.zig").tapeMatches(tape.execution_profile, program.profile)) return error.InvalidExecutionTape;
        var result: Counts = .{};
        var pc = tape.initial_pc;
        for (tape.storage[0..tape.len]) |step| {
            const entry = program.entries[try program.lookup(pc)];
            if (entry.function) switch (entry.operation) {
                0...9 => result.alu += 1,
                10 => {
                    result.jalr += 1;
                    result.alu += 1;
                    result.binary += 1;
                },
                16...18 => result.binary += 1,
                32...37 => result.shift += 1,
                49...52, 57 => result.multiplication += 1,
                53...56, 58...61 => result.division += 1,
                else => return error.UnsupportedExecutionFunction,
            };
            switch (entry.instruction.opcode) {
                .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU, .SB, .SH, .SW, .SD => result.memory += 1,
                .ECALL => result.service += 1,
                else => {},
            }
            pc = step.next_pc;
        }
        return result;
    }
};
pub fn minimalLog(count: u32) !u32 {
    if (count > 1 << 22) {
        std.debug.print("RV64_CAPACITY role=fact count={d} max={d}\n", .{ count, @as(u32, 1) << 22 });
        return error.ExecutionCapacityExceeded;
    }
    return @intCast(@max(5, std.math.log2_int_ceil(u32, @max(1, count))));
}
/// CPU MUL requests plus two unsigned support requests per DIV.
pub fn minimalMultiplicationLog(count: u32) !u32 {
    const max_log = @import("stwo_riscv_frontend").rv64_air.arithmetic.multiplication.degree3_layout.MAX_LOG;
    if (count > @as(u32, 1) << @intCast(max_log)) {
        std.debug.print("RV64_CAPACITY role=multiplication count={d} max_log={d}\n", .{ count, max_log });
        return error.ExecutionCapacityExceeded;
    }
    return @intCast(@max(5, std.math.log2_int_ceil(u32, @max(1, count))));
}
/// Prefix authorities require at least one inactive row; pure truth-fact
/// providers instead admit a completely occupied capacity via minimalLog.
pub fn minimalPrefixLog(count: u32) !u32 {
    if (count >= 1 << 22) {
        std.debug.print("RV64_CAPACITY role=prefix count={d} max_exclusive={d}\n", .{ count, @as(u32, 1) << 22 });
        return error.ExecutionCapacityExceeded;
    }
    return minimalLog(count + 1);
}

/// Public INIT/TEARDOWN rows carry canonical receiver-owned RAM tuples, not
/// CPU clocks. Their independently admitted prefix can therefore use log 23.
pub fn minimalBoundaryLog(count: u32) !u32 {
    if (count >= @as(u32, 1) << 23) return error.ExecutionCapacityExceeded;
    return @intCast(@max(5, std.math.log2_int_ceil(u32, count + 1)));
}

/// Planning only: exact unique aligned words from captured addresses, without
/// restoring instructions, constructing state transitions or running the VM.
pub fn memoryWords(a: std.mem.Allocator, program: *const Program, tape: *const rv.compact_tape.Tape) !u32 {
    if (tape.len == 0 or tape.len > tape.storage.len or !@import("../rv64_ethereum_batch.zig").tapeMatches(tape.execution_profile, program.profile)) return error.InvalidExecutionTape;
    var words: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer words.deinit(a);
    var pc = tape.initial_pc;
    for (tape.storage[0..tape.len]) |step| {
        const entry = program.entries[try program.lookup(pc)];
        if (rv.decode.effects(entry.instruction.opcode).memory_width != 0) {
            const address = step.lhs +% @as(u64, @bitCast(entry.instruction.imm));
            try words.put(a, address & ~@as(u64, 7), {});
        }
        pc = step.next_pc;
    }
    return @intCast(words.count());
}
/// CPU prefix log: up to the structural CPU cap (log 23 selects the
/// wide-clock CPU encoding); every other prefix authority stays at 2^22.
pub fn minimalCpuLog(count: u32) !u32 {
    const max_log = @import("stwo_riscv_frontend").rv64_air.word16_execution.layout.MAX_LOG;
    if (count >= @as(u32, 1) << max_log) {
        std.debug.print("RV64_CAPACITY role=cpu count={d} max_log={d}\n", .{ count, max_log });
        return error.ExecutionCapacityExceeded;
    }
    return @intCast(@max(5, std.math.log2_int_ceil(u32, count + 1)));
}

test "public boundary log23 capacity is independent of CPU and LS clocks" {
    try std.testing.expectEqual(@as(u32, 22), try minimalBoundaryLog((1 << 22) - 1));
    try std.testing.expectEqual(@as(u32, 23), try minimalBoundaryLog(1 << 22));
    try std.testing.expectEqual(@as(u32, 23), try minimalBoundaryLog((1 << 23) - 1));
    try std.testing.expectError(error.ExecutionCapacityExceeded, minimalBoundaryLog(1 << 23));
    try std.testing.expectError(error.ExecutionCapacityExceeded, minimalPrefixLog(1 << 22));
    try std.testing.expectEqual(@as(u32, 22), try minimalCpuLog((1 << 22) - 1));
}

test "public boundary log23 AIR and sidecar reject forged extents" {
    const Boundary = @import("../word16_global_execution/services/gkr_local/boundary_role.zig");
    var component = Boundary.Component{ .origin = .{ .core = .initial }, .log = 23, .count = 4_407_202, .offsets = .{ 0, 0 }, .inter_offset = 0, .shared = std.mem.zeroes(@import("../word16_global_execution/services/gkr_local/manifest.zig").Shared), .claim = @import("stwo_core").fields.om31.OM31.zero() };
    try component.validate();
    component.count = 1 << 23;
    try std.testing.expectError(error.InvalidWideBoundaryGeometry, component.validate());
    component.count = 4_407_202;
    component.origin = .{ .core = .ls };
    try std.testing.expectError(error.InvalidWideBoundaryGeometry, component.validate());
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var file = try temporary.dir.createFile("cells.bin", .{});
    file.close();
    const Cells = @import("cells_wire.zig");
    try std.testing.expectError(error.InvalidMemorySidecarSize, Cells.read(std.testing.allocator, temporary.dir, (1 << 22) + 1));
    try std.testing.expectError(error.InvalidMemorySidecarCount, Cells.read(std.testing.allocator, temporary.dir, 1 << 23));
}

test "public boundary log23 scratch admission never widens ordinary globals" {
    const C = @import("../word16_global_execution/services/gkr_local/classic_witness.zig");
    const P = @import("../word16_global_execution/services/gkr_local/classic_witness_parallel.zig");
    try std.testing.expectError(error.InvalidClassicWitnessShape, C.scratchByteUpperBound(23, 1));
    try std.testing.expectError(error.InvalidClassicWitnessShape, C.publicBoundaryScratchByteUpperBound(23, 2));
    try std.testing.expectEqual(try C.scratchByteUpperBound(22, 1), try C.publicBoundaryScratchByteUpperBound(23, 1));
    try std.testing.expectError(error.InvalidClassicWitnessShape, P.Plan.init(23, &.{.{ .inverses = 1 }}, 1 << 30, 4));
    const plan = try P.Plan.initWithLogBound(23, 23, &.{.{ .inverses = 1 }}, 1 << 30, 4);
    try std.testing.expectEqual(@as(usize, 16) * (1 << 23) * 4, plan.output_bytes);
    try std.testing.expectError(error.InvalidClassicWitnessShape, P.Plan.initWithLogBound(23, 23, &.{.{ .inverses = 2 }}, 1 << 30, 4));
}

test "public boundary log23 producer entry preserves original small-domain bytes" {
    const core = @import("stwo_core");
    const C = @import("../word16_global_execution/services/gkr_local/classic_witness.zig");
    const O = core.fields.om31.OM31;
    const Provider = struct {
        pub const PARALLEL_SAFE = true;
        pub fn fill(_: @This(), logical: usize, denominators: []O, numerators: []C.Numerator) !void {
            denominators[0] = O.fromBase(core.fields.m31.M31.fromCanonical(@intCast(logical + 2)));
            numerators[0] = .{ .base = core.fields.m31.M31.one().neg() };
        }
    };
    var old = try C.Witness.init(std.testing.allocator, 5, &.{.{ .inverses = 1 }}, Provider{}, 1 << 20);
    defer old.deinit();
    var boundary = try C.Witness.initPublicBoundary(std.testing.allocator, 5, &.{.{ .inverses = 1 }}, Provider{}, 1 << 20);
    defer boundary.deinit();
    try std.testing.expectEqualSlices(core.fields.m31.M31, old.data, boundary.data);
    try std.testing.expect(old.claims[0].eql(boundary.claims[0]));
}
