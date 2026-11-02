//! Column layout of one curve/field truth operation: one call per row.
//!
//! MAIN (in order):
//!   ACTIVE                         Boolean activity prefix
//!   PACKET   32 * coords bytes     the packet before the call (Wire35 inputs)
//!   OUT      outputs * L bytes     the written values (Wire35 outputs)
//!   WIT      witnesses * L bytes   private slope (local BYTE)
//!   per relation: QUOTIENT q_bytes, CARRY carries * carry_bytes (local BYTE)
//!   per canonical check: D (L bytes, local BYTE), BORROW (L/2 - 1 Boolean)
//!   SEL (L/2 Boolean), INV         nonzero proof (one-hot chunk and inverse)
//!   HALF                           variable modulus: m_0 = 2 HALF + 1, HALF < 128
//!   MULT                           local BYTE table multiplicity
//! FIXED: ROW, FIRST, LAST, BYTE = row mod 256 (log-size material only).
//! INTERACTION: one cumulative QM31 per two fractions, BYTE chain (closes to
//! zero around the trace) then Wire35 chain (closes to the public claim).
const std = @import("std");
const core = @import("stwo_core");
pub const spec = @import("spec.zig");
pub const Op = spec.Op;
pub const Vec = spec.Vec;

pub const WIRE_ARITY = 35;
pub const MIN_LOG = 8; // the BYTE table needs 256 rows
pub const MAX_LOG = 22;
pub const ROW = 0;
pub const FIRST = 1;
pub const LAST = 2;
pub const BYTE = 3;
pub const FIXED = 4;
const ACTIVE_COLUMN = 0;
const PACKET_COLUMN = 1;

pub const Query = struct { column: usize, addend: u32 };
/// One `x < modulus` check: x is an operand; the modulus is the op's.
pub const Check = struct { x: Vec };

/// `op` is a curve/field `Op` or a secp `SecpKind` (`spec.checkKey`).
pub fn Layout(comptime op: anytype) type {
    if (@TypeOf(op) == @TypeOf(.enum_literal)) return Layout(@as(spec.Op, op));
    @setEvalBranchQuota(100_000_000);
    const d = comptime spec.defOf(op);
    const R = d.relations.len;
    const geo = comptime blk: {
        var out: [R]spec.RelationGeometry = undefined;
        for (d.relations, &out) |terms, *g| g.* = spec.deriveRelation(d, terms);
        break :blk out;
    };
    const checks = comptime blk: {
        var out: [d.canonical_inputs.len + d.outputs]Check = undefined;
        for (d.canonical_inputs, 0..) |i, k| out[k] = .{ .x = .{ .in = i } };
        for (0..d.outputs) |j| out[d.canonical_inputs.len + j] = .{ .x = .{ .out = @intCast(j) } };
        break :blk out;
    };
    return struct {
        pub const OP = op;
        pub const ACTIVE = ACTIVE_COLUMN;
        pub const PACKET = PACKET_COLUMN;
        pub const DEF = d;
        pub const PROGRAM_KIND: u32 = spec.kindOf(op);
        pub const TAG: u32 = spec.tagOf(op);
        /// Wire35 ID carried by fraction `id` (`spec.wireLabel`).
        pub fn wireLabel(id: usize) u32 {
            return spec.wireLabel(op, id);
        }
        pub const LIMBS = d.limbs;
        pub const CHUNKS = d.limbs / 2;
        pub const COORDS = d.coords;
        pub const WRITTEN = d.written;
        pub const PACKET_BYTES = 32 * d.coords;
        pub const OUT_BYTES = d.outputs * d.limbs;
        pub const RELATIONS = R;
        pub const GEOMETRY = geo;
        pub const CHECKS = checks;
        /// Wire35 IDs 0..coords-1 are the packet coordinates before the call
        /// (consumed); coords + c is written coordinate c after (produced).
        pub const WIRE_FRACTIONS = d.coords + d.written;
        /// Fractions cleared per cumulative batch: 2 (degree 3, native 2n
        /// composition) for the curve/field ops; 3 (degree 4, native 4n) for
        /// the secp row truths, a third fewer interaction columns.
        pub const BATCH: usize = if (@TypeOf(op) == spec.SecpKind) 3 else 2;
        pub const DEGREE: u8 = BATCH + 1;
        /// log2 of the constraint evaluation blowup (degree - 1).
        pub const LOG_EXTENSION: u32 = BATCH - 1;
        pub const WIRE_BATCHES = (WIRE_FRACTIONS + BATCH - 1) / BATCH;

        pub const OUT = PACKET + PACKET_BYTES;
        pub const WIT = OUT + OUT_BYTES;
        pub const QUOTIENT: [R]usize = blk: {
            @setEvalBranchQuota(100_000_000);
            var out: [R]usize = undefined;
            var at: usize = WIT + d.witnesses * d.limbs;
            for (&out, geo) |*o, g| {
                o.* = at;
                at += g.q_bytes + g.carries * g.carry_bytes;
            }
            break :blk out;
        };
        pub const CARRY: [R]usize = blk: {
            var out: [R]usize = undefined;
            for (&out, QUOTIENT, geo) |*o, q, g| o.* = q + g.q_bytes;
            break :blk out;
        };
        const RELATION_END = CARRY[R - 1] + geo[R - 1].carries * geo[R - 1].carry_bytes;
        pub const D: [checks.len]usize = blk: {
            @setEvalBranchQuota(100_000_000);
            var out: [checks.len]usize = undefined;
            for (&out, 0..) |*o, k| o.* = RELATION_END + k * (d.limbs + CHUNKS - 1);
            break :blk out;
        };
        pub const BORROW: [checks.len]usize = blk: {
            var out: [checks.len]usize = undefined;
            for (&out, D) |*o, x| o.* = x + d.limbs;
            break :blk out;
        };
        const CHECK_END = RELATION_END + checks.len * (d.limbs + CHUNKS - 1);
        pub const HAS_NONZERO = d.nonzero != null;
        pub const SEL = CHECK_END;
        pub const INV = SEL + (if (HAS_NONZERO) CHUNKS else 0);
        pub const HALF = INV + @intFromBool(HAS_NONZERO);
        pub const MULT = HALF + @intFromBool(d.odd_modulus);
        pub const MAIN = MULT + 1;

        pub fn column(v: Vec) usize {
            return switch (v) {
                .in => |i| PACKET + @as(usize, i) * d.limbs,
                .out => |j| OUT + @as(usize, j) * d.limbs,
                .wit => |w| WIT + @as(usize, w) * d.limbs,
            };
        }
        /// Column of byte b of written coordinate `coord` after the call: OUT
        /// inside the output range, else the unchanged packet byte.
        pub fn afterColumn(coord: usize, b: usize) usize {
            const at = 32 * coord + b;
            return if (at < OUT_BYTES) OUT + at else PACKET + at;
        }

        /// Local BYTE queries in emission order: witnesses, then per relation
        /// q bytes, carry bytes and (top_bits < 8) the shifted top byte, then
        /// the D bytes of every check, then HALF and HALF + 128.
        const QUERY_ARRAY = blk: {
            @setEvalBranchQuota(100_000_000);
            var list: [4096]Query = undefined;
            var n: usize = 0;
            for (0..d.witnesses * d.limbs) |i| {
                list[n] = .{ .column = WIT + i, .addend = 0 };
                n += 1;
            }
            for (geo, QUOTIENT, CARRY) |g, q, c| {
                for (0..g.q_bytes) |i| {
                    list[n] = .{ .column = q + i, .addend = 0 };
                    n += 1;
                }
                for (0..g.carries) |j| {
                    for (0..g.carry_bytes) |b| {
                        list[n] = .{ .column = c + g.carry_bytes * j + b, .addend = 0 };
                        n += 1;
                    }
                    if (g.top_bits < 8) {
                        list[n] = .{ .column = c + g.carry_bytes * j + g.carry_bytes - 1, .addend = 256 - (@as(u32, 1) << @intCast(g.top_bits)) };
                        n += 1;
                    }
                }
            }
            for (D) |base| for (0..d.limbs) |i| {
                list[n] = .{ .column = base + i, .addend = 0 };
                n += 1;
            };
            if (d.odd_modulus) {
                list[n] = .{ .column = HALF, .addend = 0 };
                list[n + 1] = .{ .column = HALF, .addend = 128 };
                n += 2;
            }
            var exact: [n]Query = undefined;
            @memcpy(&exact, list[0..n]);
            const final = exact;
            break :blk final;
        };
        pub const QUERIES: []const Query = &QUERY_ARRAY;
        pub const BYTE_QUERIES = QUERIES.len;
        pub const BYTE_FRACTIONS = BYTE_QUERIES + 1;
        pub const BYTE_BATCHES = (BYTE_FRACTIONS + BATCH - 1) / BATCH;
        pub const BATCHES = BYTE_BATCHES + WIRE_BATCHES;
        pub const INTERACTION = 4 * BATCHES;
        pub const BYTE_LAST = 4 * (BYTE_BATCHES - 1);
        pub const WIRE_FIRST = 4 * BYTE_BATCHES;
        pub const WIRE_LAST = 4 * (BATCHES - 1);

        pub const BORROW_COUNT = checks.len * (CHUNKS - 1);
        pub const BOOLEANS = 1 + BORROW_COUNT + (if (HAS_NONZERO) CHUNKS else 0);
        pub const NONZERO_CONSTRAINTS = if (HAS_NONZERO) 2 else 0;
        pub const ODD_CONSTRAINTS = @intFromBool(d.odd_modulus);
        pub const GROUPS = blk: {
            @setEvalBranchQuota(100_000_000);
            var n: usize = 0;
            for (geo) |g| n += g.groups;
            break :blk n;
        };
        pub const CHUNK_CONSTRAINTS = checks.len * CHUNKS;
        pub const ACTIVITY = 4;
        pub const MAIN_CONSTRAINTS = BOOLEANS + NONZERO_CONSTRAINTS + ODD_CONSTRAINTS + GROUPS + CHUNK_CONSTRAINTS + ACTIVITY;
        pub const CONSTRAINTS = MAIN_CONSTRAINTS + BATCHES;

        pub fn validateGeometry(calls: usize, first_id: u32, log: u32) !void {
            const modulus = core.fields.m31.Modulus;
            if (log < MIN_LOG or log > MAX_LOG) return error.InvalidCurveGeometry;
            const n = @as(usize, 1) << @intCast(log);
            // At least one inactive padding row; the activity prefix ends before LAST.
            if (calls >= n or first_id == 0 or first_id >= modulus or @as(u64, first_id) + calls > modulus) return error.InvalidCurveGeometry;
            // BYTE multiplicities and Wire35 events stay below the characteristic.
            if (@as(u64, BYTE_QUERIES) * n >= modulus or @as(u64, WIRE_FRACTIONS) * n >= modulus) return error.CurveLookupMassExceeded;
        }
        /// Smallest admitted log for `calls` rows plus one padding row.
        pub fn logSize(calls: usize) !u32 {
            const log: u32 = @intCast(std.math.log2_int_ceil(usize, @max(@as(usize, 1) << MIN_LOG, try std.math.add(usize, calls, 1))));
            try validateGeometry(calls, 1, log);
            return log;
        }
        pub fn widths() [3]usize {
            return .{ FIXED, MAIN, INTERACTION };
        }
        /// Constant column of the modulus at byte k (constant moduli only).
        pub fn modulusByte(k: usize) u32 {
            return switch (d.modulus) {
                .constant => |p| spec.limbOf(p, k),
                .variable => unreachable,
            };
        }
    };
}
