//! One immutable, complete packet/DAG schedule. Every call has exactly64 rows:
//!20 frontier writers,32 arithmetic writers,12 fixed idle rows. No producer
//! chooses opcode, edge, fanout, sign or multiplicity. Admission remains closed.
const std = @import("std");
const D = @import("dag.zig");
const Micro = @import("micro.zig");
const B = @import("../curves/spec.zig");
pub const ROWS_PER_CALL = 64;
pub const PROGRAM_VERSION = 1;
pub const MIN_LOG = 8;
pub const MAX_LOG = 24;
pub const Role = enum { frontier, arithmetic, idle };
pub const Slot = struct {
    role: Role,
    writer: u8 = 0,
    writer_weight: u8 = 0,
    global_label: u8 = 0,
    global_weight: i8 = 0,
    readers: [7]u8 = @splat(D.ZERO),
    reader_weights: [7]u1 = @splat(0),
};
pub fn slot(index: usize) Slot {
    std.debug.assert(index < ROWS_PER_CALL);
    if (index < D.INPUTS) return .{ .role = .frontier, .writer = @intCast(index), .writer_weight = D.FANOUT[index], .global_label = @intCast(index), .global_weight = -1 };
    if (index >= D.INPUTS + D.STEPS) return .{ .role = .idle };
    const instruction = D.PROGRAM[index - D.INPUTS];
    var out = Slot{ .role = .arithmetic, .writer = instruction.output, .writer_weight = D.FANOUT[instruction.output], .readers = instruction.operands() };
    for (out.readers, &out.reader_weights) |id, *weight| weight.* = @intFromBool(id < D.VALUES);
    if (instruction.output >= 34 and instruction.output < 46) {
        out.global_label = 20 + instruction.output - 34;
        out.global_weight = 1;
    }
    return out;
}
pub const Mass = struct {
    /// Absolute weighted message counts, BOTH sides included. These bounds are
    /// characteristic bounds, not extension-field collision estimates.
    local_ssa: u64,
    local_range: u64,
    global_wire: u64,
    pub fn validate(self: Mass) error{TowerMassBound}!void {
        if (self.local_ssa >= B.M31 or self.local_range >= B.M31 or self.global_wire >= B.M31) return error.TowerMassBound;
    }
};
pub fn mass(calls: u64) error{TowerMassBound}!Mass {
    // Avoid multiplication wrap before testing characteristic authority.
    const range_per_call = 2 * D.STEPS * Micro.RANGE_QUERIES;
    const max_factor = @max(range_per_call, @max(2 * D.READS, 2 * (D.INPUTS + 12)));
    if (calls == 0 or calls > (B.M31 - 1) / max_factor) return error.TowerMassBound;
    const out = Mass{ .local_ssa = calls * (2 * D.READS), .local_range = calls * range_per_call, .global_wire = calls * 64 };
    try out.validate();
    return out;
}
pub fn validateGeometry(calls: u64, first_id: u64, log: u32) error{ TowerGeometry, TowerMassBound }!void {
    _ = try mass(calls);
    if (first_id == 0 or first_id >= B.M31 or calls > B.M31 - first_id) return error.TowerGeometry;
    if (log < MIN_LOG or log > MAX_LOG or calls > ((@as(u64, 1) << @intCast(log)) - 1) / ROWS_PER_CALL) return error.TowerGeometry;
}
pub const Advice = struct { input: [D.INPUTS]u256 };
pub fn row(advice: *const Advice, index: usize) Micro.Row {
    const selected = slot(index);
    if (selected.role == .idle) {
        var out: Micro.Row = @splat(0);
        out[Micro.ACTIVE] = 1;
        return out;
    }
    if (selected.role == .frontier) {
        var out: Micro.Row = @splat(0);
        out[Micro.ACTIVE] = 1;
        const value = advice.input[index];
        for (0..32) |byte| out[Micro.RESULT + byte] = @truncate(value >> @intCast(8 * byte));
        return out;
    }
    const values = D.evaluate(&advice.input);
    return Micro.fill(index - D.INPUTS, &values);
}
/// Fixed-source authority exposes every edge, unit read weight, exact writer
/// fanout, literal and external Wire35 label. Receiver rebuilds this schedule
/// from source, never from an incoming manifest or row advice.
pub fn checkSchedule() void {
    var written: [D.VALUES]bool = @splat(false);
    var readers: [D.VALUES]u16 = @splat(0);
    var weighted_writers: [D.VALUES]u16 = @splat(0);
    var inputs: usize = 0;
    var outputs: usize = 0;
    for (0..ROWS_PER_CALL) |i| {
        const current = slot(i);
        for (current.readers, current.reader_weights) |id, weight| {
            if (weight != 0) {
                std.debug.assert(id < D.VALUES and written[id]);
                readers[id] += weight;
            }
        }
        if (current.role != .idle) {
            std.debug.assert(!written[current.writer]);
            written[current.writer] = true;
            weighted_writers[current.writer] = current.writer_weight;
        }
        if (current.global_weight == -1) inputs += 1;
        if (current.global_weight == 1) outputs += 1;
    }
    std.debug.assert(inputs == D.INPUTS and outputs == 12);
    for (readers, weighted_writers, written) |reads, writes, exists| std.debug.assert(exists and reads == writes);
}
