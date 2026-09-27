//! Universal 8x8 byte requests for one typed opcode access slot. The same
//! sidecar witness supplies transition bytes and these AIR-checked requests.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const counter_mod = @import("../air/lookups/tables/counter.zig");
const snapshot_mod = @import("../air/block/memory_range_interaction_v2.zig");
const source = @import("block_execution_access_bridge_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const Element = @import("../recursion/air/universal_challenges.zig").Elements;

pub const BYTE_COUNT: usize = 28;
pub const REQUEST_COUNT: usize = BYTE_COUNT / 2;
pub const BATCH_COUNT: usize = REQUEST_COUNT / 2;
pub const COLUMN_COUNT: usize = BATCH_COUNT * 4;
pub const Claims = [BATCH_COUNT]Q;
pub const SNAPSHOT = snapshot_mod.CounterSnapshot;
pub const TAG: u32 = 0x42324552; // B2ER

pub fn bytesAtPoint(pair: source.Pair(Q), witness: integer.Witness) [BYTE_COUNT]Q {
    const algebra = @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q);
    return algebra.bytesAtPoint(pair, algebra.Integers.Witness.fromColumns(witness.columns()));
}
pub fn constraints(challenge: *const Element, active: Q, bytes: [BYTE_COUNT]Q, current: Claims, previous: Claims, claims: Claims, trace_size: u32) !Claims {
    if (challenge.arity != 2 or trace_size == 0) return error.InvalidExecutionRangeChallenge;
    var normalized: Claims = undefined;
    for (&normalized, claims) |*out, claim| out.* = try claim.divM31(M.fromCanonical(trace_size));
    return @import("block_v5_native_fused_algebra_v1.zig").Algebra(Q).rangeConstraints(challenge, active, bytes, current, previous, normalized);
}

pub fn collectCounter(a: std.mem.Allocator, trace: anytype, global: *counter_mod.Counter) !SNAPSHOT {
    var local = try counter_mod.Counter.init(a, .range_check_8_8);
    defer local.deinit(a);
    for (0..trace.domainSize()) |logical| {
        const row = try trace.row(logical);
        if (!row.active) continue;
        const pair = try trace.pairAt(logical);
        const witness = try trace.witnessAt(logical);
        const bytes = bytesAtPoint(pair, witness);
        for (0..REQUEST_COUNT) |request| try local.registerBase(M.one(), &.{ try secureBase(bytes[2 * request]), try secureBase(bytes[2 * request + 1]) });
    }
    const snapshot = snapshot_mod.counterSnapshot(&local);
    for (global.values, local.values) |*dst, src| dst.* = dst.add(src);
    return snapshot;
}

pub const Result = struct {
    columns: [COLUMN_COUNT][]M,
    storage: []M,
    claims: Claims,
    pub fn deinit(self: *Result, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};

pub fn generate(a: std.mem.Allocator, trace: anytype, challenge: *const Element, expected_snapshot: SNAPSHOT) !Result {
    if (challenge.arity != 2) return error.InvalidExecutionRangeChallenge;
    const size = trace.domainSize();
    const storage = try a.alloc(M, size * COLUMN_COUNT);
    errdefer a.free(storage);
    var columns: [COLUMN_COUNT][]M = undefined;
    for (&columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
    var local = try counter_mod.Counter.init(a, .range_check_8_8);
    defer local.deinit(a);
    var claims: Claims = @splat(Q.zero());
    for (0..size) |logical| {
        const row = try trace.row(logical);
        const physical = framework.committedRow(logical, trace.log_size);
        if (!row.active) {
            for (0..BATCH_COUNT) |batch| write(&columns, batch, physical, Q.zero());
            continue;
        }
        const pair = try trace.pairAt(logical);
        const witness = try trace.witnessAt(logical);
        const bytes = bytesAtPoint(pair, witness);
        for (0..BATCH_COUNT) |batch| {
            var term = Q.zero();
            for (0..2) |side| {
                const request = 2 * batch + side;
                const tuple = [2]M{ try secureBase(bytes[2 * request]), try secureBase(bytes[2 * request + 1]) };
                try local.registerBase(M.one(), &tuple);
                term = term.add(try (try challenge.combineBase(&tuple)).inv());
            }
            claims[batch] = claims[batch].add(term);
            write(&columns, batch, physical, term);
        }
    }
    if (!std.mem.eql(u8, &snapshot_mod.counterSnapshot(&local), &expected_snapshot))
        return error.ExecutionRangeCounterChangedAfterSeal;
    var prefixes: Claims = @splat(Q.zero());
    for (0..size) |logical| {
        const physical = framework.committedRow(logical, trace.log_size);
        for (0..BATCH_COUNT) |batch| {
            prefixes[batch] = prefixes[batch].add(read(&columns, batch, physical))
                .sub(try claims[batch].divM31(M.fromU64(size)));
            write(&columns, batch, physical, prefixes[batch]);
        }
    }
    for (prefixes) |prefix| if (!prefix.isZero()) return error.InvalidExecutionRangePrefix;
    return .{ .columns = columns, .storage = storage, .claims = claims };
}

pub fn mixClaims(claims: Claims, instance_index: u32, family: @import("../runner/trace.zig").OpcodeFamily, slot: usize, channel: anytype) !void {
    channel.mixU32s(&.{ TAG, 2, instance_index, @intFromEnum(family), @intCast(slot) });
    for (claims) |claim| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim)) return error.InvalidExecutionRangeClaim;
        for (claim.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    }
}

fn secureBase(value: Q) !M {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseExecutionRangeByte;
    if (limbs[0].toU32() >= 256) return error.InvalidExecutionRangeByte;
    return limbs[0];
}
fn write(columns: *[COLUMN_COUNT][]M, batch: usize, row: usize, value: Q) void {
    for (value.toM31Array(), 0..) |limb, index| columns[4 * batch + index][row] = limb;
}
pub fn read(columns: *const [COLUMN_COUNT][]M, batch: usize, row: usize) Q {
    return Q.fromM31Array(.{ columns[4 * batch][row], columns[4 * batch + 1][row], columns[4 * batch + 2][row], columns[4 * batch + 3][row] });
}

test "block-v2 execution byte requests close on inactive typed rows" {
    const a = std.testing.allocator;
    const opcode = @import("../runner/trace.zig");
    const family: opcode.OpcodeFamily = .base_alu_imm;
    var main: opcode.TraceColumns = undefined;
    main.n_columns = opcode.nColumnsForFamily(family);
    main.n_real_rows = 0;
    for (main.columns[0..main.n_columns]) |*column| {
        column.* = try a.alloc(M, 2);
        @memset(column.*, M.zero());
    }
    defer main.deinit(a);
    var trace = try @import("block_execution_sidecar_trace_v2.zig").Trace.init(a, family, &main, 0, 1, .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 });
    defer trace.deinit();
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const snapshot = try collectCounter(a, &trace, &counter);
    const sealed = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(72), .instance_count = 1 };
    const challenges = try @import("block_memory_relation_v2.zig").Challenges.draw(a, sealed);
    var result = try generate(a, &trace, challenges.universal_prefix.get(.range_check_8_8), snapshot);
    defer result.deinit(a);
    for (result.claims) |claim| try std.testing.expect(claim.isZero());
    const previous: Claims = @splat(Q.zero());
    const residuals = try constraints(challenges.universal_prefix.get(.range_check_8_8), Q.zero(), @splat(Q.zero()), previous, previous, result.claims, 2);
    for (residuals) |residual| try std.testing.expect(residual.isZero());
}
