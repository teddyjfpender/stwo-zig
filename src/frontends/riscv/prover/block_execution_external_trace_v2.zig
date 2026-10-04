//! Byte witness for committed SHA/Keccak caller accesses. Native column
//! placements are verifier-derived; this trace only borrows their evaluations.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const frame_mod = @import("../air/block/memory_event.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const keccak_trace = @import("../air/guest_precompile/keccakf_trace.zig");
const keccak_witness = @import("../air/guest_precompile/keccakf_witness.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
const source = @import("block_execution_external_access_bridge_v2.zig");
const pair_source = @import("block_execution_access_bridge_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");

pub const Kind = enum(u8) { sha, keccak, signer };
pub const Descriptor = struct {
    kind: Kind,
    slot: usize,
    log_size: u32,
    fixed_offset: usize,
    main_offset: usize,
    frame: frame_mod.Frame,
    x0_local_custody_version: u32 = 0,

    pub fn count(self: Descriptor) usize {
        return switch (self.kind) {
            .sha => source.SHA_ACCESS_COUNT,
            .keccak => source.KECCAK_ACCESS_COUNT,
            .signer => source.SIGNER_ACCESS_COUNT,
        };
    }
    pub fn mainWidth(self: Descriptor) usize {
        return (switch (self.kind) {
            .sha => sha.PHYSICAL_MAIN_COLUMN_COUNT,
            .keccak => keccak_trace.Layout.main_columns,
            .signer => signer.Layout.main_columns,
        }) + @as(usize, if (self.x0_local_custody_version == 1) (if (self.kind == .sha) 4 else 2) else 0);
    }
    pub fn validate(self: Descriptor, fixed: []const Column, main: []const Column) !void {
        if (self.x0_local_custody_version > 1 or self.slot >= self.count() or self.log_size == 0 or self.log_size > 24 or
            self.main_offset + self.mainWidth() > main.len or
            self.fixed_offset + (switch (self.kind) {
                .sha => sha.PREPROCESSED_COLUMN_COUNT,
                .keccak => keccak_trace.Layout.preprocessed_columns,
                .signer => 0,
            }) > fixed.len)
            return error.InvalidExternalAccessDescriptor;
        for (main[self.main_offset..][0..self.mainWidth()]) |column|
            if (column.log_size != self.log_size) return error.InvalidExternalAccessDescriptor;
        if (self.kind == .sha and fixed[self.fixed_offset].log_size != self.log_size)
            return error.InvalidExternalAccessDescriptor;
    }
};

/// Verifier-derived ordered external roster. The native prepared key fixes
/// total column logs and the extension statement fixes every component width.
pub fn descriptorsFromStatement(a: std.mem.Allocator, statement: *const Profile.admission.Statement, fixed_logs: []const u32, main_logs: []const u32, frame: frame_mod.Frame) ![]Descriptor {
    return descriptorsFromStatementForMode(a, statement, fixed_logs, main_logs, frame, 0);
}
pub fn descriptorsFromStatementForMode(a: std.mem.Allocator, statement: *const Profile.admission.Statement, fixed_logs: []const u32, main_logs: []const u32, frame: frame_mod.Frame, mode: u32) ![]Descriptor {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    const components = Profile.descriptors(statement);
    var fixed_width: usize = 0;
    var main_width: usize = 0;
    for (components) |component| {
        fixed_width = try std.math.add(usize, fixed_width, component.preprocessed_columns);
        main_width = try std.math.add(usize, main_width, component.main_columns);
    }
    if (fixed_width > fixed_logs.len or main_width > main_logs.len) return error.InvalidExternalAccessRoster;
    var fixed_offset = fixed_logs.len - fixed_width;
    var main_offset = main_logs.len - main_width;
    var result: std.ArrayList(Descriptor) = .empty;
    errdefer result.deinit(a);
    for (components, 0..) |component, i| {
        const kind: ?Kind = if (i == 0 and statement.ethereum.counts.keccak_calls != 0) .keccak else if (i == 13 and statement.ethereum.counts.signer_calls != 0) .signer else if (i == 18 and statement.sha.call_count != 0) .sha else null;
        if (kind) |chosen| {
            const count: usize = switch (chosen) {
                .sha => source.SHA_ACCESS_COUNT,
                .keccak => source.KECCAK_ACCESS_COUNT,
                .signer => source.SIGNER_ACCESS_COUNT,
            };
            const first_slot: usize = if (mode == 0) 0 else if (chosen == .sha) 2 else 1;
            for (first_slot..count) |slot| try result.append(a, .{
                .kind = chosen,
                .slot = slot,
                .log_size = component.log_size,
                .fixed_offset = fixed_offset,
                .main_offset = main_offset,
                .frame = frame,
                .x0_local_custody_version = @intFromBool(statement.ethereum.localZeroCustody()),
            });
        }
        fixed_offset += component.preprocessed_columns;
        main_offset += component.main_columns;
    }
    return result.toOwnedSlice(a);
}

pub fn expectedEventCount(statement: *const Profile.admission.Statement) !u64 {
    return expectedEventCountForMode(statement, 0);
}
pub fn expectedEventCountForMode(statement: *const Profile.admission.Statement, mode: u32) !u64 {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    return try std.math.add(u64, try std.math.add(u64, try std.math.mul(u64, statement.ethereum.counts.keccak_calls, source.KECCAK_ACCESS_COUNT - mode), try std.math.mul(u64, statement.sha.call_count, source.SHA_ACCESS_COUNT - 2 * mode)), try std.math.mul(u64, statement.ethereum.counts.signer_calls, source.SIGNER_ACCESS_COUNT - mode));
}
pub fn requireRwDescriptors(slots: []const Descriptor, mode: u32) !void {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    if (mode == 0) return;
    for (slots) |slot| if (slot.slot < (if (slot.kind == .sha) @as(usize, 2) else 1) or slot.slot >= slot.count()) return error.MixedV5ExternalMemoryScope;
}

pub const Trace = struct {
    allocator: std.mem.Allocator,
    descriptor: Descriptor,
    fixed: []const Column,
    main: []const Column,
    log_size: u32,
    base_clock: u64,
    storage: []M,
    witness: [integer.COLUMN_COUNT][]M,

    pub fn init(a: std.mem.Allocator, descriptor: Descriptor, fixed: []const Column, main: []const Column) !Trace {
        return initColumns(a, descriptor, fixed, main, false);
    }
    /// Warm PCS projections recover only the columns pairAt actually reads.
    /// Geometry is still validated for the complete independent descriptor.
    pub fn initSelected(a: std.mem.Allocator, descriptor: Descriptor, fixed: []const Column, main: []const Column) !Trace {
        return initColumns(a, descriptor, fixed, main, true);
    }
    fn initColumns(a: std.mem.Allocator, descriptor: Descriptor, fixed: []const Column, main: []const Column, selected: bool) !Trace {
        try descriptor.validate(fixed, main);
        const size: usize = @as(usize, 1) << @intCast(descriptor.log_size);
        if (selected and descriptor.kind == .keccak) {
            const caller_width = @import("../air/guest_precompile/keccakf_caller.zig").Layout.main_columns;
            try requireValues(main[descriptor.main_offset + keccak_trace.Layout.caller ..][0..caller_width], size);
            try requireValues(main[descriptor.main_offset + keccak_trace.Layout.state ..][0..keccak_witness.state_cell_count], size);
        } else try requireValues(main[descriptor.main_offset..][0..descriptor.mainWidth()], size);
        if (descriptor.kind == .sha) try requireValues(fixed[descriptor.fixed_offset..][0..1], size);
        const base_clock = try integer.baseClockFromPublicFrame(descriptor.frame);
        const storage = try a.alloc(M, integer.COLUMN_COUNT * size);
        errdefer a.free(storage);
        var result = Trace{ .allocator = a, .descriptor = descriptor, .fixed = fixed, .main = main, .log_size = descriptor.log_size, .base_clock = base_clock, .storage = storage, .witness = undefined };
        for (&result.witness, 0..) |*column, i| column.* = storage[i * size ..][0..size];
        for (0..size) |logical| {
            const pair = try result.pairAt(logical);
            const values = (try integer.Witness.fromPair(pair, base_clock)).columns();
            const physical = framework.committedRow(logical, descriptor.log_size);
            for (values, &result.witness) |value, *column| column.*[physical] = try secureBase(value);
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
    pub fn pairAt(self: *const Trace, logical: usize) !pair_source.Pair(Q) {
        if (logical >= self.domainSize()) return error.InvalidExternalAccessRow;
        const d = self.descriptor;
        const physical = framework.committedRow(logical, d.log_size);
        if (d.kind == .sha) {
            const selector = Q.fromBase(self.fixed[d.fixed_offset].values[physical]);
            if (selector.isZero()) return zeroPair();
            var caller: [sha.PHYSICAL_MAIN_COLUMN_COUNT]Q = undefined;
            for (&caller, 0..) |*value, i| value.* = Q.fromBase(self.main[d.main_offset + i].values[physical]);
            return source.shaPair(Q, &caller, selector, d.slot);
        }
        if (d.kind == .signer) {
            if (self.main[d.main_offset + signer.Layout.is_active].values[physical].isZero()) return zeroPair();
            var caller: [signer.Layout.main_columns]Q = undefined;
            for (&caller, 0..) |*value, i| value.* = Q.fromBase(self.main[d.main_offset + i].values[physical]);
            return source.signerPair(Q, &caller, d.slot);
        }
        if (d.slot >= source.KECCAK_ACCESS_COUNT) return error.InvalidKeccakAccessSlot;
        if (self.main[d.main_offset + keccak_trace.Layout.caller + keccak.Layout.enabler].values[physical].isZero()) return zeroPair();
        var caller: [keccak.Layout.main_columns]Q = undefined;
        for (&caller, 0..) |*value, i| value.* = Q.fromBase(self.main[d.main_offset + keccak_trace.Layout.caller + i].values[physical]);
        if (d.slot == 0) return source.keccakPairFromBytes(Q, &caller, @splat(Q.zero()), @splat(Q.zero()), 0);
        // The native caller relation reads its input from the caller row's
        // own state cells; only the output is shifted by 27 rows.
        const input_row = physical;
        const output_row = framework.committedRow((logical + 27) % self.domainSize(), d.log_size);
        var input: [4]Q = @splat(Q.zero());
        var output: [4]Q = @splat(Q.zero());
        for (0..32) |bit| {
            const cell = (d.slot - 1) * 32 + bit;
            const column = self.main[d.main_offset + keccak_trace.Layout.state + cell].values;
            const weight = M.fromCanonical(@as(u32, 1) << @intCast(bit % 8));
            input[bit / 8] = input[bit / 8].add(Q.fromBase(column[input_row].mul(weight)));
            output[bit / 8] = output[bit / 8].add(Q.fromBase(column[output_row].mul(weight)));
        }
        return source.keccakPairFromBytes(Q, &caller, input, output, d.slot);
    }
    pub fn witnessAt(self: *const Trace, logical: usize) !integer.Witness {
        if (logical >= self.domainSize()) return error.InvalidExternalAccessRow;
        const physical = framework.committedRow(logical, self.log_size);
        var values: [integer.COLUMN_COUNT]Q = undefined;
        for (self.witness, &values) |column, *value| value.* = Q.fromBase(column[physical]);
        return integer.Witness.fromColumns(values);
    }
    pub fn row(self: *const Trace, logical: usize) !transition.Row {
        const pair = try self.pairAt(logical);
        const decoded = try pair_source.decodePair(pair);
        if (!decoded.active) return .{ .active = false, .tuple = @splat(M.zero()) };
        const secure = integer.transitionAtPoint(pair, try self.witnessAt(logical));
        var tuple: bus.TransitionTuple = undefined;
        for (secure, &tuple) |value, *limb| limb.* = try secureBase(value);
        _ = try bus.decodeTransitionTuple(tuple);
        return .{ .active = true, .tuple = tuple };
    }
};

// Base-domain witness construction only. The algebraic tuple evaluators and
// OODS/quotient paths always retain their full field expressions.
fn zeroPair() pair_source.Pair(Q) {
    return .{ .active = Q.zero(), .space = Q.zero(), .source_address = Q.zero(), .local_clock = Q.zero(), .consume_clock = Q.zero(), .before = @splat(Q.zero()), .after = @splat(Q.zero()), .pair_residuals = @splat(Q.zero()), .access_ordinal = null };
}

test {
    _ = @import("tests/block_execution_external_trace_parity_test.zig");
}

fn requireValues(columns: []const Column, size: usize) !void {
    for (columns) |column| if (column.values.len != size) return error.InvalidExternalAccessTrace;
}

fn secureBase(value: Q) !M {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseExternalAccess;
    return limbs[0];
}

test "Keccak caller A and B use current input state and row plus 27 output" {
    const a = std.testing.allocator;
    const count = keccak_trace.Layout.main_columns;
    const columns = try a.alloc(Column, count);
    defer a.free(columns);
    for (columns) |*column| {
        const values = try a.alloc(M, 32);
        @memset(values, M.zero());
        column.* = .{ .log_size = 5, .values = values };
    }
    defer for (columns) |column| a.free(column.values);
    const caller = @import("../air/guest_precompile/keccakf_caller.zig");
    for (0..2) |logical| {
        const physical = framework.committedRow(logical, 5);
        @constCast(columns[keccak_trace.Layout.caller + caller.Layout.enabler].values)[physical] = M.one();
        @constCast(columns[keccak_trace.Layout.caller + caller.Layout.execution_clock].values)[physical] = M.fromCanonical(@intCast(logical + 1));
    }
    @constCast(columns[keccak_trace.Layout.state].values)[framework.committedRow(0, 5)] = M.one();
    @constCast(columns[keccak_trace.Layout.state].values)[framework.committedRow(28, 5)] = M.one();
    const descriptor = Descriptor{ .kind = .keccak, .slot = 1, .log_size = 5, .fixed_offset = 0, .main_offset = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 } };
    const trace = Trace{ .allocator = a, .descriptor = descriptor, .fixed = &.{}, .main = columns, .log_size = 5, .base_clock = 0, .storage = undefined, .witness = undefined };
    const first = try trace.pairAt(0);
    const second = try trace.pairAt(1);
    try std.testing.expectEqual(@as(u32, 1), first.before[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), first.after[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), second.before[0].toM31Array()[0].toU32());
    try std.testing.expectEqual(@as(u32, 1), second.after[0].toM31Array()[0].toU32());
}
