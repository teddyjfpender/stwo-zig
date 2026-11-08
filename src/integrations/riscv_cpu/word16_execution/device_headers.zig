//! Valid empty CPU owners for a device witness factory. Geometry, public state
//! and lifetimes survive; no field-column witness or histogram is constructed.
//! Only DeviceSourceStage's complete, scoped device MAIN can admit these headers.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const B = A.word16_v1;
const Mat = @import("setup.zig");
const Prepared = @import("prepared.zig").Prepared;
const Tail = @import("provider_tails.zig");
pub const Source = @import("sources.zig").Source;
const Memory = @import("memory/prepared.zig");
const Statement = @import("memory/statement.zig").Statement;
fn mass(count: usize, weights: ?[]const u32) !u32 {
    if (weights) |input| if (input.len != count) return error.InvalidProviderWeights;
    var total: u64 = if (weights == null) count else 0;
    if (weights) |input| for (input) |value| {
        if (value >= @import("stwo_core").fields.m31.Modulus) return error.InvalidProviderWeights;
        total = try std.math.add(u64, total, value);
    };
    if (total >= @import("stwo_core").fields.m31.Modulus) return error.ProviderMultiplicityMassExceeded;
    return @intCast(total);
}
fn alu(a: std.mem.Allocator, count: usize, weights: []const u32, log: u32, fused: bool) !B.alu_experiment.source.Source {
    _ = try B.alu_experiment.source.massForLog(log);
    return .{ .allocator = a, .log_size = log, .fact_count = count, .function_mass = try mass(count, weights), .fixed = &.{}, .main = &.{}, .owns_main = true, .range16_counts = &.{}, .metadata = &.{}, .fused = fused };
}
fn binary(a: std.mem.Allocator, count: usize, weights: []const u32, log: u32) !B.binary_source.Source {
    _ = try B.binary_source.massForLog(log);
    return .{ .allocator = a, .log_size = log, .fact_count = count, .function_mass = try mass(count, weights), .fixed = &.{}, .main = &.{}, .owns_main = true, .and_counts = &.{}, .metadata = &.{} };
}
fn shift(a: std.mem.Allocator, count: usize, weights: ?[]const u32, log: u32) !B.shift_word_packed_experiment.source.Source {
    _ = try B.shift_word_packed_experiment.source.massForLog(log);
    return .{ .allocator = a, .log_size = log, .fact_count = count, .function_mass = try mass(count, weights), .fixed = &.{}, .main = &.{}, .owns_main = true, .shift_counts = &.{}, .range16_counts = &.{}, .metadata = &.{} };
}
fn ls(a: std.mem.Allocator, count: u32, log: u32) A.memory.load_store_v2.source.Source {
    return .{ .allocator = a, .log_size = log, .rows = count, .fixed = &.{}, .main = &.{}, .owns_main = true, .metadata = &.{}, .counts16 = &.{}, .counts8 = &.{}, .selection_counts = &.{} };
}
fn boundary(a: std.mem.Allocator, count: usize, log: u32, initial: bool) !A.memory.load_store_v2.boundary_source.Source {
    if (count >= @as(usize, 1) << @intCast(log)) return error.BoundaryCapacityExceeded;
    return .{ .allocator = a, .kind = if (initial) .initial else .terminal, .log_size = log, .rows = @intCast(count), .fixed = &.{}, .main = &.{}, .owns_main = true, .metadata = &.{} };
}
/// Consumes CPU/JALR on success; the input's grouped compact facts stay borrowed
/// until the device has joined their uploads and explicitly retires them.
pub fn take(a: std.mem.Allocator, materials: *const Mat.Materials, prepared: *Prepared, statement: Statement) !Source {
    const g = materials.geometry;
    try g.validate();
    const splits = try Tail.validate(g, prepared);
    const ls_counts = try g.lsCounts(statement.ls_count);
    if (g.omit_empty_division and prepared.division.len != 0) return error.OmittedDivisionRequests;
    if (prepared.division.len > @as(usize, 1) << @intCast(g.division_log) or prepared.multiplication.len > @as(usize, 1) << @intCast(g.multiplication_log)) return error.ArithmeticRequestCapacity;
    const main_alu = try alu(a, splits.alu.head, prepared.alu.weights[0..splits.alu.head], g.alu_log, g.alu_fused_tail);
    const main_binary = try binary(a, splits.binary.head, prepared.binary.weights[0..splits.binary.head], g.binary_log);
    const main_shift = try shift(a, splits.shift.head, if (prepared.shift_weights.len != 0) prepared.shift_weights[0..splits.shift.head] else null, g.shift_log);
    var tails = Tail.Tails{};
    if (g.alu_tail_log) |log| tails.alu = try alu(a, splits.alu.tail, prepared.alu.weights[splits.alu.head..], log, g.alu_fused_tail);
    if (g.binary_tail_log) |log| tails.binary = try binary(a, splits.binary.tail, prepared.binary.weights[splits.binary.head..], log);
    if (g.shift_tail_log) |log| tails.shift = try shift(a, splits.shift.tail, if (prepared.shift_weights.len != 0) prepared.shift_weights[splits.shift.head..] else null, log);
    // Public boundary lists remain independently owned receiver-facing data.
    const initial = try a.dupe(Memory.public.Cell, statement.initial);
    errdefer a.free(initial);
    const terminal = try a.dupe(Memory.public.Cell, statement.terminal);
    errdefer a.free(terminal);
    var memory = Memory.Prepared{
        .allocator = a,
        .statement = .{ .initial = initial, .terminal = terminal, .epoch = statement.epoch, .ls_count = statement.ls_count },
        .ls = ls(a, ls_counts.head, g.ls_log),
        .initial = try boundary(a, initial.len, g.initialLog(), true),
        .terminal = try boundary(a, terminal.len, g.terminalLog(), false),
        .selection = .{ .allocator = a, .fixed = &.{}, .main = &.{}, .counts = &.{} },
        .counts16 = &.{},
        .counts8 = &.{},
    };
    if (g.ls_tail_log) |log| memory.ls_tail = ls(a, ls_counts.tail, log);
    var cpu = try prepared.takeCpu(&materials.program, g.cpu_log);
    errdefer cpu.deinit();
    if (cpu.main.len != 0) return error.DeviceCaptureAlreadyMaterialized;
    if (cpu.compact != g.cpu_compact_decode or cpu.epoch != statement.epoch) return error.PreparedGeometryMismatch;
    cpu.fused_tail = g.cpu_fused_tail;
    cpu.u8_pairs = g.cpu_u8_pairs;
    var jalr = try prepared.takeJalr(g.jalr_log);
    errdefer jalr.deinit();
    if (jalr.main.len != 0 or jalr.fixed.len != 0) return error.DeviceCaptureAlreadyMaterialized;
    return .{
        .allocator = a,
        .materials = materials,
        .cpu = cpu,
        .jalr = jalr,
        .rom = .{ .allocator = a, .program = &materials.program, .counts = &.{}, .main = &.{} },
        .alu = main_alu,
        .binary = main_binary,
        .shift = main_shift,
        .tails = tails,
        .division = .{ .allocator = a, .count = prepared.division.len, .log_size = g.division_log, .fixed = &.{}, .main = &.{}, .metadata = &.{}, .counts16 = &.{} },
        .multiplication = .{ .allocator = a, .count = @intCast(prepared.multiplication.len), .log_size = g.multiplication_log, .fixed = &.{}, .main = &.{}, .request_metadata = &.{}, .byte_counts = @splat(0) },
        .memory = memory,
        .and_table = .{ .allocator = a, .kind = .byte_and, .main = &.{}, .pairs = g.cpu_u8_pairs },
        .shift_table = .{ .allocator = a, .fixed = &.{}, .main = &.{} },
        .range16 = .{ .allocator = a, .kind = .range16, .log_size = 16, .fixed = &.{}, .counts = &.{}, .main = &.{} },
        .range8 = .{ .allocator = a, .kind = .range8, .log_size = 8, .fixed = &.{}, .counts = &.{}, .main = &.{} },
        .counts16 = &.{},
        .counts8 = &.{},
    };
}

test "device family witness header mass rejects noncanonical split multiplicities" {
    try std.testing.expectEqual(@as(u32, 7), try mass(2, &.{ 3, 4 }));
    try std.testing.expectError(error.ProviderMultiplicityMassExceeded, mass(2, &.{ 2147483646, 1 }));
    try std.testing.expectError(error.InvalidProviderWeights, mass(3, &.{1}));
}

test "device family witness header constructor is fully typed" {
    std.mem.doNotOptimizeAway(&take);
}
