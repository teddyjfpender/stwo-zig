//! One shared byte witness per Keccak RAM word, independent of window count.
//! This constructs witnesses only. The original Keccak AIR, fixed owner clock
//! columns, integer/access AIR and full global memory closure are mandatory.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Shard = @import("../air/guest_precompile/keccakf_trace.zig");
const Caller = @import("../air/guest_precompile/keccakf_caller.zig");
const Local = @import("../air/guest_precompile/keccakf_caller_local_zero_v1.zig");
const Placement = @import("block_v7_keccak_window_layout_v1.zig");
const Source = @import("block_v7_keccak_window_source_v1.zig");
const Matrix = @import("block_v7_memory_trace_v1.zig").Matrix;
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Access = @import("block_execution_access_bridge_v2.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Transition = @import("block_execution_transition_interaction_v2.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const WordTransition = @import("block_v5_word_execution_transition_v1.zig");
const UniversalMemory = @import("block_v5_opcode_memory_interaction_v1.zig");
pub const Claim = @import("block_v5_external_memory_sidecar_proof_v1.zig").Claim;
pub const SLOT_COUNT = Caller.word_count;
pub const INTERACTION_COUNT = WordTransition.COLUMN_COUNT + Range.COLUMN_COUNT + UniversalMemory.COLUMN_COUNT;
pub const Limits = struct { max_witness_bytes: usize = 512 << 20, max_interaction_bytes: usize = 512 << 20 };
pub const Generated = struct {
    matrix: Matrix,
    claims: [SLOT_COUNT]Claim,
    pub fn deinit(self: *Generated) void {
        self.matrix.deinit();
        self.* = undefined;
    }
};
pub const Prepared = struct {
    shard: *const Shard.Shard,
    layout: *const Placement.Owned,
    witnesses: [SLOT_COUNT]Matrix,
    witness_bytes: usize,
    pub fn init(a: std.mem.Allocator, shard: *const Shard.Shard, layout: *const Placement.Owned, limits: Limits) !Prepared {
        const geometry = @import("../air/guest_precompile/keccakf_authority.zig").geometry;
        const expected_rows = try std.math.mul(usize, try std.math.divCeil(usize, layout.calls, geometry.operations_per_slot), geometry.rows_per_slot);
        if (shard.first_call_index != 0 or shard.call_count != layout.calls or shard.n_rows != expected_rows or shard.log_size != layout.log_size or shard.x0_local_custody_version > 1) return error.InvalidKeccakBatchMemoryGeometry;
        const count = try std.math.mul(usize, SLOT_COUNT * Integer.COLUMN_COUNT, shard.domainSize());
        const bytes = try std.math.mul(usize, count, @sizeOf(M));
        if (bytes > limits.max_witness_bytes) return error.KeccakMemoryWitnessLimit;
        var self = Prepared{ .shard = shard, .layout = layout, .witnesses = undefined, .witness_bytes = bytes };
        var ready: usize = 0;
        errdefer for (self.witnesses[0..ready]) |*matrix| matrix.deinit();
        for (&self.witnesses) |*matrix| {
            matrix.* = try Matrix.init(a, shard.log_size, Integer.COLUMN_COUNT, limits.max_witness_bytes);
            ready += 1;
        }
        var active_calls: usize = 0;
        for (0..shard.domainSize()) |logical| {
            const active = shard.mainAt(Shard.Layout.caller + Caller.Layout.enabler, logical);
            if (active.isZero()) continue;
            if (!active.eql(M.one())) return error.InvalidKeccakBatchCaller;
            var owners: usize = 0;
            for (layout.windows, 0..) |_, i| owners += @intFromBool(layout.selected(i, logical));
            if (owners != 1) return error.InvalidKeccakBatchCaller;
            active_calls += 1;
            const clock = try layout.clockAt(logical);
            for (&self.witnesses, 0..) |*matrix, index| {
                const selected = try self.view(index + 1);
                const witness = try Integer.Witness.fromPair(try selected.pairAt(logical), clock);
                for (witness.columns(), 0..) |value, column| matrix.set(column, logical, try secureBase(value));
            }
        }
        if (active_calls != layout.calls) return error.InvalidKeccakBatchCaller;
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (&self.witnesses) |*matrix| matrix.deinit();
        self.* = undefined;
    }
    pub fn view(self: *const Prepared, slot: usize) !View {
        if (slot == 0 or slot > SLOT_COUNT) return error.InvalidKeccakAccessSlot;
        return .{ .shard = self.shard, .layout = self.layout, .witness = &self.witnesses[slot - 1], .slot = slot, .log_size = self.shard.log_size };
    }
    /// Headers borrow the owned witness storage; free only the returned slice.
    pub fn columns(self: *const Prepared, a: std.mem.Allocator) ![]Column {
        const out = try a.alloc(Column, SLOT_COUNT * Integer.COLUMN_COUNT);
        for (self.witnesses, 0..) |matrix, i| @memcpy(out[i * Integer.COLUMN_COUNT ..][0..Integer.COLUMN_COUNT], matrix.columns);
        return out;
    }
    pub fn collectCounter(self: *const Prepared, a: std.mem.Allocator, counter: *Counter) ![SLOT_COUNT]Range.SNAPSHOT {
        var out: [SLOT_COUNT]Range.SNAPSHOT = undefined;
        for (&out, 0..) |*snapshot, i| {
            const source = try self.view(i + 1);
            snapshot.* = try Range.collectCounter(a, &source, counter);
        }
        return out;
    }
    /// Exact original transition, range and opposite-memory generators. These
    /// are physical open claims, requiring the shared STARK and global closure.
    pub fn generate(self: *const Prepared, a: std.mem.Allocator, word: *const Word.Challenges, snapshots: [SLOT_COUNT]Range.SNAPSHOT, limits: Limits) !Generated {
        var out = Generated{ .matrix = try Matrix.init(a, self.shard.log_size, SLOT_COUNT * INTERACTION_COUNT, limits.max_interaction_bytes), .claims = undefined };
        errdefer out.deinit();
        const rows = try a.alloc(Transition.Row, self.shard.domainSize());
        defer a.free(rows);
        const memory_rows = try a.alloc(UniversalMemory.Row, self.shard.domainSize());
        defer a.free(memory_rows);
        for (&out.claims, snapshots, 0..) |*claim, snapshot, index| {
            const source = try self.view(index + 1);
            for (rows, memory_rows, 0..) |*row, *memory_row, logical| {
                row.* = try source.row(logical);
                memory_row.* = try UniversalMemory.rowFromPair(try source.pairAt(logical));
            }
            var transition = try WordTransition.generate(a, word, rows, source.log_size);
            defer transition.deinit(a);
            var bytes = try Range.generate(a, &source, word.universal_prefix.get(.range_check_8_8), snapshot);
            defer bytes.deinit(a);
            var opposite = try UniversalMemory.generate(a, word.universal_prefix.get(.memory_access), memory_rows, source.log_size);
            defer opposite.deinit(a);
            claim.* = .{ .transition_sum = transition.claim, .range_claims = bytes.claims, .universal_sum = opposite.claim, .active_count = transition.count };
            var column: usize = index * INTERACTION_COUNT;
            inline for (.{ transition.columns, bytes.columns, opposite.columns }) |batch_columns| for (batch_columns) |values| {
                @memcpy(@constCast(out.matrix.columns[column].values), values);
                column += 1;
            };
        }
        return out;
    }
};
pub const View = struct {
    shard: *const Shard.Shard,
    layout: *const Placement.Owned,
    witness: *const Matrix,
    slot: usize,
    log_size: u32,
    pub fn domainSize(self: *const View) usize {
        return self.shard.domainSize();
    }
    pub fn pairAt(self: *const View, logical: usize) !Access.Pair(Q) {
        if (logical >= self.domainSize() or self.slot == 0 or self.slot > SLOT_COUNT) return error.InvalidExternalAccessRow;
        const active = self.shard.mainAt(Shard.Layout.caller + Caller.Layout.enabler, logical);
        if (active.isZero()) return .{ .active = Q.zero(), .space = Q.zero(), .source_address = Q.zero(), .local_clock = Q.zero(), .consume_clock = Q.zero(), .before = @splat(Q.zero()), .after = @splat(Q.zero()), .pair_residuals = @splat(Q.zero()), .access_ordinal = null };
        var input: [32]Q = undefined;
        var output: [32]Q = undefined;
        for (&input, &output, 0..) |*before, *after, bit| {
            const column = Shard.Layout.state + (self.slot - 1) * 32 + bit;
            before.* = Q.fromBase(self.shard.mainAt(column, logical));
            after.* = Q.fromBase(self.shard.mainAt(column, (logical + 27) % self.domainSize()));
        }
        if (self.shard.x0_local_custody_version == 1) {
            var caller: [Local.Layout.main_columns]Q = undefined;
            for (&caller, 0..) |*value, i| value.* = Q.fromBase(self.shard.mainAt(Shard.Layout.caller + i, logical));
            return Source.For(true).memoryPair(Q, Q.one(), &caller, input, output, self.slot);
        }
        var caller: [Caller.Layout.main_columns]Q = undefined;
        for (&caller, 0..) |*value, i| value.* = Q.fromBase(self.shard.mainAt(Shard.Layout.caller + i, logical));
        return Source.For(false).memoryPair(Q, Q.one(), &caller, input, output, self.slot);
    }
    pub fn witnessAt(self: *const View, logical: usize) !Integer.Witness {
        if (logical >= self.domainSize()) return error.InvalidExternalAccessRow;
        return Integer.Witness.fromColumns(self.witness.row(Integer.COLUMN_COUNT, 0, logical));
    }
    pub fn row(self: *const View, logical: usize) !Transition.Row {
        const pair = try self.pairAt(logical);
        if (!(try Access.decodePair(pair)).active) return .{ .active = false, .tuple = @splat(M.zero()) };
        const secure = Integer.transitionAtPoint(pair, try self.witnessAt(logical));
        var tuple: Bus.TransitionTuple = undefined;
        for (&tuple, secure) |*out, value| out.* = try secureBase(value);
        _ = try Bus.decodeTransitionTuple(tuple);
        return .{ .active = true, .tuple = tuple };
    }
};
fn secureBase(value: Q) !M {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseExternalAccess;
    return limbs[0];
}
