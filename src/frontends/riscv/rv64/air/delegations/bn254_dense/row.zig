//! Canonical direct-polynomial witness and exact integer residual authority.
//! No input range inheritance is claimed by this isolated module: callers must
//! bind every input byte through a public frontier or typed canonical writers.
const std = @import("std");
pub const S = @import("spec.zig");
const B = S.B;
pub fn Layout(comptime kind: S.Kind) type {
    return struct {
        pub const G = S.commonGeometry(kind);
        pub const ACTIVE = 0;
        pub const INPUT = 1;
        pub const OUTPUT = INPUT + 32 * S.inputs(kind);
        pub const QUOTIENT = OUTPUT + 32;
        pub const CARRY = QUOTIENT + G.q_bytes;
        pub const DISTANCE = CARRY + G.carries * G.carry_bytes;
        pub const BORROW = DISTANCE + 32;
        pub const MULT = BORROW + 15;
        pub const MAIN = MULT + 1;
        pub const Row = [MAIN]u32;
        pub const BYTE_QUERIES = 32 + G.q_bytes + G.carries * G.carry_bytes + (if (G.top_bits < 8) G.carries else 0) + 32;
        pub fn read(row: *const Row, start: usize, bytes: usize) B.Big {
            var v: B.Big = 0;
            for (0..bytes) |i| v |= @as(B.Big, row[start + i]) << @intCast(8 * i);
            return v;
        }
        fn put(row: *Row, start: usize, bytes: usize, v: B.Big) void {
            for (0..bytes) |i| row[start + i] = B.limbOf(v, i);
        }
        pub fn output(comptime coordinate: usize, input: *const [S.inputs(kind)]u256) u256 {
            var pos: B.Big = G.kp;
            var neg: B.Big = 0;
            inline for (comptime S.terms(kind, coordinate)) |t| if (t.b) |bb| {
                const a = input[t.a.in];
                const b = input[bb.in];
                const magnitude = @as(B.Big, a) * b * @as(B.Big, @intCast(@abs(t.coef)));
                if (t.coef > 0) pos += magnitude else neg += magnitude;
            };
            std.debug.assert(pos >= neg);
            return @intCast((pos - neg) % B.BN254_P);
        }
        pub fn coefficient(comptime coordinate: usize, row: *const Row, n: usize) i64 {
            var total: i64 = 0;
            inline for (comptime S.terms(kind, coordinate)) |term| {
                if (term.b) |bb| {
                    if (n < 63) {
                        const first = if (n >= 32) n - 31 else 0;
                        for (first..@min(n + 1, 32)) |i| total += @as(i64, term.coef) * row[INPUT + 32 * @as(usize, term.a.in) + i] * row[INPUT + 32 * @as(usize, bb.in) + n - i];
                    }
                } else if (n < 32) total -= row[OUTPUT + n];
            }
            total += @as(i64, B.limbOf(G.kp, n)) * row[ACTIVE];
            const first = if (n >= 32) n - 31 else 0;
            var i = first;
            while (i < G.q_bytes and i <= n) : (i += 1) total -= @as(i64, row[QUOTIENT + i]) * B.limbOf(B.BN254_P, n - i);
            return total;
        }
        pub fn fill(comptime coordinate: usize, input: *const [S.inputs(kind)]u256) Row {
            var row: Row = @splat(0);
            row[ACTIVE] = 1;
            for (input, 0..) |v, i| put(&row, INPUT + 32 * i, 32, v);
            const value = output(coordinate, input);
            put(&row, OUTPUT, 32, value);
            var pos: B.Big = G.kp;
            var neg: B.Big = value;
            inline for (comptime S.terms(kind, coordinate)) |t| if (t.b) |bb| {
                const mag = @as(B.Big, input[t.a.in]) * input[bb.in] * @as(B.Big, @intCast(@abs(t.coef)));
                if (t.coef > 0) pos += mag else neg += mag;
            };
            std.debug.assert(pos >= neg and (pos - neg) % B.BN254_P == 0);
            const q = (pos - neg) / B.BN254_P;
            std.debug.assert(q >> @intCast(8 * G.q_bytes) == 0);
            put(&row, QUOTIENT, G.q_bytes, q);
            var carry: i64 = 0;
            for (0..G.groups) |group| {
                const sum = coefficient(coordinate, &row, group) + carry;
                std.debug.assert(@mod(sum, 256) == 0);
                carry = @divExact(sum, 256);
                if (group == G.carries) {
                    std.debug.assert(carry == 0);
                    break;
                }
                const encoded = carry + @as(i64, @intCast(G.carry_offset));
                std.debug.assert(encoded >= 0 and encoded < (@as(i64, 1) << @intCast(G.carry_bits)));
                put(&row, CARRY + group * G.carry_bytes, G.carry_bytes, @intCast(encoded));
            }
            put(&row, DISTANCE, 32, B.BN254_P - 1 - value);
            var borrow: u32 = 0;
            for (0..15) |i| {
                const sum = row[OUTPUT + 2 * i] + 256 * row[OUTPUT + 2 * i + 1] + row[DISTANCE + 2 * i] + 256 * row[DISTANCE + 2 * i + 1] + borrow + @intFromBool(i == 0);
                const m: u32 = @intCast((B.BN254_P >> @intCast(16 * i)) & 0xffff);
                std.debug.assert(sum == m or sum == m + 65536);
                borrow = @intFromBool(sum != m);
                row[BORROW + i] = borrow;
            }
            return row;
        }
        pub fn rangeValid(row: *const Row) bool {
            // Direct public-byte fixture includes inputs; production may inherit them
            // only after full source-owned frontier/SSA closure.
            for (row[INPUT..BORROW]) |v| if (v >= 256) return false;
            for (0..G.carries) |i| if (read(row, CARRY + i * G.carry_bytes, G.carry_bytes) >= @as(B.Big, 1) << @intCast(G.carry_bits)) return false;
            for (row[BORROW..MULT]) |v| if (v > 1) return false;
            return row[ACTIVE] <= 1;
        }
        pub fn valid(comptime coordinate: usize, row: *const Row) bool {
            if (!rangeValid(row)) return false;
            for (0..G.groups) |n| {
                const previous: i64 = if (n == 0) 0 else @as(i64, @intCast(read(row, CARRY + (n - 1) * G.carry_bytes, G.carry_bytes))) - @as(i64, @intCast(G.carry_offset)) * row[ACTIVE];
                const next: i64 = if (n == G.carries) 0 else @as(i64, @intCast(read(row, CARRY + n * G.carry_bytes, G.carry_bytes))) - @as(i64, @intCast(G.carry_offset)) * row[ACTIVE];
                if (coefficient(coordinate, row, n) + previous - 256 * next != 0) return false;
            }
            for (0..16) |i| {
                var residual: @TypeOf(@as(i64, 0)) = @as(i64, row[OUTPUT + 2 * i]) + 256 * @as(i64, row[OUTPUT + 2 * i + 1]) + row[DISTANCE + 2 * i] + 256 * @as(i64, row[DISTANCE + 2 * i + 1]) - @as(i64, @intCast((B.BN254_P >> @intCast(16 * i)) & 0xffff)) * row[ACTIVE];
                if (i == 0) residual += row[ACTIVE];
                if (i > 0) residual += row[BORROW + i - 1];
                if (i < 15) residual -= 65536 * @as(i64, row[BORROW + i]);
                if (residual != 0) return false;
            }
            if (row[ACTIVE] == 0) {
                for (row[INPUT..MULT]) |v| if (v != 0) return false;
            }
            return true;
        }
    };
}
