//! Bounded cumulative BYTE/Wire interaction publication from immutable advice.
//! No MAIN retention/reconstruction: one original native row is replayed.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const R = @import("../roster.zig");
const C = @import("truth_v3_catalog.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Physical = A.memory.closed_ram.trace.physical;
const Wire = A.crypto.sha256.equations.WireFor(O);
pub const Witness = struct {
    allocator: std.mem.Allocator,
    log: u32,
    width: usize,
    data: []M,
    claim: O,
    pub fn deinit(s: *@This()) void {
        s.allocator.free(s.data);
        s.* = undefined;
    }
    pub fn take(s: *@This(), a: std.mem.Allocator) !@import("../../../word16_execution/main_ownership.zig").Commit {
        const cols = try a.alloc(engine.pcs.ColumnEvaluation, s.width);
        errdefer a.free(cols);
        const backings = try a.alloc([]M, 1);
        const n = @as(usize, 1) << @intCast(s.log);
        for (cols, 0..) |*v, c| v.* = .{ .log_size = s.log, .values = s.data[c * n ..][0..n] };
        backings[0] = s.data;
        s.data = &.{};
        return .{ .columns = cols, .backings = backings };
    }
};
fn store(out: []M, n: usize, p: usize, group: usize, value: O) void {
    for (value.toM31Array(), 0..) |v, c| out[(8 * group + c) * n + p] = v;
}
fn typed(comptime T: type, a: std.mem.Allocator, s: anytype, wire: Wire, bytes: O, budget: usize) !Witness {
    try s.validateMetadata();
    const n = s.size();
    const width = 8 * (T.byte_batches + T.wire_batches);
    const count = try std.math.mul(usize, width, n);
    const output = try std.math.mul(usize, count, @sizeOf(M));
    const scratch = @sizeOf(T.N.Row) + 256 * @sizeOf(O);
    if (try std.math.add(usize, output, scratch) > budget) return error.V3TruthBudgetExceeded;
    const out = try a.alloc(M, count);
    errdefer a.free(out);
    const row = try a.create(T.N.Row);
    defer a.destroy(row);
    var table: [256]O = undefined;
    if (comptime T.bytes != 0) {
        for (&table, 0..) |*v, i| v.* = try bytes.sub(O.fromBase(M.fromCanonical(@intCast(i)))).inv();
    }
    var bt = O.zero();
    var wt = O.zero();
    const V = struct {
        s: @TypeOf(s),
        row: *const T.N.Row,
        p: usize,
        pub fn fixed(v: *const @This(), c: usize) O {
            return O.fromBase(v.s.fixed[c * v.s.size() + v.p]);
        }
        pub fn main(v: *const @This(), c: usize) O {
            return O.fromBase(M.fromCanonical(v.row[c]));
        }
    };
    for (0..n) |r| {
        const p = Physical(r, s.log_size);
        if (comptime T == C.Sha()) {
            _ = T.N.fill(row, if (r < s.inputs.len) s.inputs[r] else T.N.PADDING);
            row[T.L.ACTIVE] = @intFromBool(r < s.inputs.len);
        } else if (comptime T == C.Arith()) {
            A.crypto.arith256.trace.nativeRow(row, s.inputs, &s.counts, r);
        } else {
            try A.crypto.curves.Trace(T.L.OP).nativeRow(row, s.packets, &s.counts, r);
        }
        var v = V{ .s = s, .row = row, .p = p };
        if (comptime T.bytes != 0) {
            for (0..T.byte_batches) |b| {
                for (0..T.batch) |j| {
                    const i = T.batch * b + j;
                    if (i < T.bytes) {
                        const q = if (comptime T == C.Arith()) T.L.query(i) else T.L.QUERIES[i];
                        bt = bt.add(table[row[q.column] + q.addend]);
                    } else if (i == T.bytes) {
                        bt = bt.sub(table[r & 255].mulM31(M.fromCanonical(row[T.L.MULT])));
                    }
                }
                store(out, n, p, b, bt);
            }
        }
        for (0..T.wire_batches) |b| {
            for (0..T.batch) |j| {
                const id = T.batch * b + j;
                if (id >= T.wires) continue;
                const tuple = if (comptime T == C.Sha()) T.Eq.tuple(O, &v, .{ .calls = @intCast(s.inputs.len), .first_id = s.first_id }, @intCast(id)) else if (comptime T == C.Arith()) T.Eq.tuple(O, &v, .{ .calls = @intCast(s.inputs.len), .first_id = s.first_id }, @intCast(id)) else T.Eq.tuple(O, &v, .{ .calls = @intCast(s.packets.len), .first_id = s.first_id }, id);
                // Poles are rejected on padded rows too; zero activity never masks a pole.
                const inv = try wire.denominator(&tuple).inv();
                const active = row[T.L.ACTIVE];
                const positive = if (comptime T == C.Sha()) id == T.L.OUTPUT_WIRE else if (comptime T == C.Arith()) id == T.L.OUTPUT_WIRE else id >= T.L.COORDS;
                const weighted = inv.mulM31(M.fromCanonical(active));
                wt = if (positive) wt.add(weighted) else wt.sub(weighted);
            }
            store(out, n, p, T.byte_batches + b, wt);
        }
    }
    if (!bt.isZero()) return error.V3TruthByteClosure;
    for (0..T.wire_batches) |b| for (0..n) |p| {
        var x: [8]M = undefined;
        for (&x, 0..) |*v, c| v.* = out[(8 * (T.byte_batches + b) + c) * n + p];
        store(out, n, p, T.byte_batches + b, O.fromM31Array(x).sub(wt));
    };
    return .{ .allocator = a, .log = s.log_size, .width = width, .data = out, .claim = wt };
}
pub fn generate(a: std.mem.Allocator, source: *const R.TruthSource, wire: Wire, bytes: O, budget: usize) !Witness {
    return switch (source.*) {
        .sha256 => |*s| typed(C.Sha(), a, &s.source, wire, bytes, budget),
        .arith256_mod => |*s| typed(C.Arith(), a, &s.source, wire, bytes, budget),
        .curve => |*u| switch (u.*) {
            inline else => |*s| typed(C.Curve(@TypeOf(s.*).OP), a, s, wire, bytes, budget),
        },
        .secp_row => |*u| switch (u.*) {
            inline else => |*s| typed(C.Curve(@TypeOf(s.*).OP), a, s, wire, bytes, budget),
        },
        else => error.NotV3Truth,
    };
}
