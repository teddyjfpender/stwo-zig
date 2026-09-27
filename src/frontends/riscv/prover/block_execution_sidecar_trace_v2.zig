//! Sidecar byte witness over the exact bit-reversed opcode main columns.
//! These columns are committed in a separate tree of the same-root PCS proof;
//! the quotient replays the typed access builder at native main-tree openings.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const opcode = @import("../runner/trace.zig");
const event = @import("../air/block/memory_event.zig");
const source = @import("block_execution_access_bridge_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const framework = @import("../recursion/air/framework_interaction.zig");

pub const Trace = struct {
    allocator: std.mem.Allocator,
    family: opcode.OpcodeFamily,
    main: *const opcode.TraceColumns,
    slot: usize,
    log_size: u32,
    frame: event.Frame,
    base_clock: u64,
    register_custody_mode: u32 = 0,
    storage: []M,
    witness: [integer.COLUMN_COUNT][]M,

    pub fn init(a: std.mem.Allocator, family: opcode.OpcodeFamily, main: *const opcode.TraceColumns, slot: usize, log_size: u32, frame: event.Frame) !Trace {
        return initForMode(a, family, main, slot, log_size, frame, 0);
    }
    pub fn initForMode(a: std.mem.Allocator, family: opcode.OpcodeFamily, main: *const opcode.TraceColumns, slot: usize, log_size: u32, frame: event.Frame, mode: u32) !Trace {
        if (mode > 1) return error.InvalidV5RegisterCustodyMode;
        const old_width = opcode.nColumnsForFamily(family);
        const local_width = try @import("../air/x0_native_envelope_v1.zig").mainColumnCount(family);
        if (log_size == 0 or log_size > 24 or (main.n_columns != old_width and (mode != 1 or main.n_columns != local_width))) return error.InvalidExecutionSidecarGeometry;
        const size: usize = @as(usize, 1) << @intCast(log_size);
        if (main.n_real_rows > size) return error.InvalidExecutionSidecarGeometry;
        for (main.columns[0..main.n_columns]) |column| if (column.len != size) return error.InvalidExecutionSidecarGeometry;
        const base_clock = try integer.baseClockFromPublicFrame(frame);
        const zero_main: [opcode.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
        const family_pairs = try source.fromCommittedMain(Q, family, zero_main[0..old_width]);
        if (slot >= family_pairs.len) return error.InvalidExecutionSidecarSlot;
        const storage = try a.alloc(M, integer.COLUMN_COUNT * size);
        errdefer a.free(storage);
        var result = Trace{ .register_custody_mode = mode, .allocator = a, .family = family, .main = main, .slot = slot, .log_size = log_size, .frame = frame, .base_clock = base_clock, .storage = storage, .witness = undefined };
        for (&result.witness, 0..) |*column, index| column.* = storage[index * size ..][0..size];
        for (0..size) |logical| {
            const pair = try result.pairAt(logical);
            const converted = (try integer.Witness.fromPair(pair, base_clock)).columns();
            const physical = framework.committedRow(logical, log_size);
            for (converted, &result.witness) |value, *column| column.*[physical] = try secureBase(value);
        }
        return result;
    }

    pub fn deinit(self: *Trace) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn domainSize(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }

    pub fn pairAt(self: *const Trace, logical: usize) !source.Pair(Q) {
        if (logical >= self.domainSize()) return error.InvalidExecutionSidecarRow;
        const physical = framework.committedRow(logical, self.log_size);
        var main: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        for (self.main.columns[0..self.main.n_columns], 0..) |column, index| main[index] = Q.fromBase(column[physical]);
        const pairs = try source.fromCommittedMain(Q, self.family, main[0..opcode.nColumnsForFamily(self.family)]);
        if (self.slot >= pairs.len) return error.InvalidExecutionSidecarSlot;
        return source.rwPairForMode(Q, self.family, self.slot, pairs.items[self.slot], self.register_custody_mode);
    }

    pub fn witnessAt(self: *const Trace, logical: usize) !integer.Witness {
        if (logical >= self.domainSize()) return error.InvalidExecutionSidecarRow;
        const physical = framework.committedRow(logical, self.log_size);
        var values: [integer.COLUMN_COUNT]Q = undefined;
        for (self.witness, &values) |column, *value| value.* = Q.fromBase(column[physical]);
        return integer.Witness.fromColumns(values);
    }

    pub fn row(self: *const Trace, logical: usize) !transition.Row {
        const pair = try self.pairAt(logical);
        const decoded = try source.decodePair(pair);
        if (!decoded.active) return .{ .active = false, .tuple = @splat(M.zero()) };
        const witness = try self.witnessAt(logical);
        const secure = integer.transitionAtPoint(pair, witness);
        var tuple: bus.TransitionTuple = undefined;
        for (secure, &tuple) |value, *limb| limb.* = try secureBase(value);
        _ = try bus.decodeTransitionTuple(tuple);
        return .{ .active = true, .tuple = tuple };
    }
};

fn secureBase(value: Q) !M {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseExecutionSidecarWitness;
    return limbs[0];
}

test "block-v2 sidecar trace borrows exact typed opcode main columns" {
    const a = std.testing.allocator;
    const family: opcode.OpcodeFamily = .base_alu_imm;
    var main: opcode.TraceColumns = undefined;
    main.n_columns = opcode.nColumnsForFamily(family);
    main.n_real_rows = 0;
    for (main.columns[0..main.n_columns]) |*column| {
        column.* = try a.alloc(M, 2);
        @memset(column.*, M.zero());
    }
    defer main.deinit(a);
    var sidecar = try Trace.init(a, family, &main, 0, 1, .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 });
    defer sidecar.deinit();
    const row = try sidecar.row(0);
    try std.testing.expect(!row.active);
    try std.testing.expectEqual(@as(usize, 2), sidecar.domainSize());
}
