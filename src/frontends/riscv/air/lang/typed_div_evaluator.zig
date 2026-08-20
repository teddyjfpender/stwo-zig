//! Hot typed-DIV constraint and lookup evaluator.
//!
//! The fixed recipes and binding digest remain authoritative in
//! `typed_div_authority.zig`; this shard specializes their execution for the
//! caller's symbolic field type without allocation or runtime dispatch.

const std = @import("std");
const common = @import("../semantics/common.zig");
const entry = @import("../lookups/entry.zig");

pub fn Evaluator(comptime api: type, comptime S: type) type {
    const CANONICAL_LOOKUP_RECIPE = api.CANONICAL_LOOKUP_RECIPE;
    const DIRECT_CONSTRAINT_COUNT = api.DIRECT_CONSTRAINT_COUNT;
    const LOOKUP_BATCH_SIZE = api.LOOKUP_BATCH_SIZE;
    const LOOKUP_COUNT = api.LOOKUP_COUNT;
    const MAIN_COLUMN_COUNT = api.MAIN_COLUMN_COUNT;
    const OPCODE_IDS = api.OPCODE_IDS;
    return struct {
        const ops = common.Ops(S);
        const e = entry.Builder(S);

        pub const DirectConstraints = struct {
            values: [DIRECT_CONSTRAINT_COUNT]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub const ConstraintProgram = struct {
            active_row: S,
            direct_constraints: DirectConstraints,
            lookup_entries: e.List,
        };

        pub const Row = struct {
            clock: S,
            pc: S,
            rd: ops.Access,
            rs1: ops.Access,
            rs2: ops.Access,
            zero_divisor: S,
            r_zero: S,
            q: [4]S,
            r: [4]S,
            b_sign: S,
            c_sign: S,
            q_sign: S,
            sign_xor: S,
            c_sum_inv: S,
            r_sum_inv: S,
            r_abs: [4]S,
            r_inv: [4]S,
            lt_markers: [4]S,
            lt_diff: S,
            is_div: S,
            is_divu: S,
            is_rem: S,
            is_remu: S,
            destination: ops.Destination,

            pub inline fn fromMainColumns(columns: []const S) !Row {
                if (columns.len != MAIN_COLUMN_COUNT)
                    return error.InvalidMainTraceShape;
                return .{
                    .clock = columns[0],
                    .pc = columns[1],
                    .rd = ops.accessFromColumns(columns[2..12]),
                    .rs1 = ops.accessFromColumns(columns[12..22]),
                    .rs2 = ops.accessFromColumns(columns[22..32]),
                    .zero_divisor = columns[32],
                    .r_zero = columns[33],
                    .q = columns[34..38].*,
                    .r = columns[38..42].*,
                    .b_sign = columns[42],
                    .c_sign = columns[43],
                    .q_sign = columns[44],
                    .sign_xor = columns[45],
                    .c_sum_inv = columns[46],
                    .r_sum_inv = columns[47],
                    .r_abs = columns[48..52].*,
                    .r_inv = columns[52..56].*,
                    .lt_markers = columns[56..60].*,
                    .lt_diff = columns[60],
                    .is_div = columns[61],
                    .is_divu = columns[62],
                    .is_rem = columns[63],
                    .is_remu = columns[64],
                    .destination = ops.destinationFromColumns(columns[65..67]),
                };
            }

            pub inline fn active(self: Row) S {
                return self.is_div.add(self.is_divu).add(self.is_rem).add(self.is_remu);
            }
        };

        pub const Derived = struct {
            active: S,
            is_division: S,
            is_signed: S,
            special_case: S,
            valid_not_zero_divisor: S,
            valid_not_special: S,
            q_sum: S,
            c_sum: S,
            r_sum: S,
            diffs: [4]S,
            result: [4]S,
            negation_carries: [4]S,
            prefixes: [4]S,
            product_carries: [8]S,
            sign_checks: [2]S,
        };

        pub inline fn direct(columns: []const S, is_active: S) !DirectConstraints {
            return directRow(try Row.fromMainColumns(columns), is_active);
        }

        pub fn build(columns: []const S, is_active: S) !ConstraintProgram {
            const row = try Row.fromMainColumns(columns);
            const direct_constraints = directRow(row, is_active);
            var lookup_entries: e.List = undefined;
            lookupsRowInto(row, &lookup_entries);
            return .{
                .active_row = row.active(),
                .direct_constraints = direct_constraints,
                .lookup_entries = lookup_entries,
            };
        }

        inline fn sumLimbs(limbs: [4]S) S {
            return limbs[0].add(limbs[1]).add(limbs[2]).add(limbs[3]);
        }

        pub inline fn derive(row: Row) Derived {
            @setEvalBranchQuota(100_000);
            const one = S.one();
            const active = row.active();
            const is_division = row.is_div.add(row.is_divu);
            const is_signed = row.is_div.add(row.is_rem);
            const special_case = row.zero_divisor.add(row.r_zero);
            const q_sum = sumLimbs(row.q);
            const c_sum = sumLimbs(row.rs2.next);
            const r_sum = sumLimbs(row.r);
            const sign_factor = one.sub(row.c_sign.mul(ops.q(2)));

            var diffs: [4]S = undefined;
            var result: [4]S = undefined;
            var negation_carries: [4]S = undefined;
            inline for (0..4) |limb| {
                diffs[limb] = sign_factor.mul(
                    row.rs2.next[limb].sub(row.r_abs[limb]),
                );
                result[limb] = is_division.mul(row.q[limb])
                    .add(one.sub(is_division).mul(row.r[limb]));
                const previous = if (limb == 0)
                    S.zero()
                else
                    negation_carries[limb - 1];
                negation_carries[limb] = previous.add(row.r[limb])
                    .add(row.r_abs[limb]).mul(ops.INV_BYTE_RADIX());
            }

            var prefixes: [4]S = undefined;
            var prefix = special_case;
            var limb: usize = 4;
            while (limb > 0) {
                limb -= 1;
                prefix = prefix.add(row.lt_markers[limb]);
                prefixes[limb] = prefix;
            }

            const c_hi = row.c_sign.mul(ops.q(255));
            const q_hi = row.q_sign.mul(ops.q(255));
            const b_hi = row.b_sign.mul(ops.q(255));
            const r_hi = row.b_sign.mul(one.sub(row.r_zero)).mul(ops.q(255));
            const b = row.rs1.next;
            const c = row.rs2.next;
            const q = row.q;
            const r = row.r;
            var carry: [8]S = undefined;
            carry[0] = c[0].mul(q[0]).add(r[0]).sub(b[0])
                .mul(ops.INV_BYTE_RADIX());
            carry[1] = carry[0].add(c[0].mul(q[1])).add(c[1].mul(q[0]))
                .add(r[1]).sub(b[1]).mul(ops.INV_BYTE_RADIX());
            carry[2] = carry[1].add(c[0].mul(q[2])).add(c[1].mul(q[1]))
                .add(c[2].mul(q[0])).add(r[2]).sub(b[2])
                .mul(ops.INV_BYTE_RADIX());
            carry[3] = carry[2].add(c[0].mul(q[3])).add(c[1].mul(q[2]))
                .add(c[2].mul(q[1])).add(c[3].mul(q[0])).add(r[3])
                .sub(b[3]).mul(ops.INV_BYTE_RADIX());
            carry[4] = carry[3].add(c[0].mul(q_hi)).add(c[1].mul(q[3]))
                .add(c[2].mul(q[2])).add(c[3].mul(q[1])).add(c_hi.mul(q[0]))
                .add(r_hi).sub(b_hi).mul(ops.INV_BYTE_RADIX());
            carry[5] = carry[4].add(c[0].add(c[1]).mul(q_hi))
                .add(c[2].mul(q[3])).add(c[3].mul(q[2]))
                .add(c_hi.mul(q[0].add(q[1]))).add(r_hi).sub(b_hi)
                .mul(ops.INV_BYTE_RADIX());
            carry[6] = carry[5].add(c_sum.sub(c[3]).mul(q_hi))
                .add(c[3].mul(q[3])).add(c_hi.mul(q_sum.sub(q[3])))
                .add(r_hi).sub(b_hi).mul(ops.INV_BYTE_RADIX());
            carry[7] = carry[6].add(c_sum.mul(q_hi)).add(c_hi.mul(q_sum))
                .add(r_hi).sub(b_hi).mul(ops.INV_BYTE_RADIX());

            return .{
                .active = active,
                .is_division = is_division,
                .is_signed = is_signed,
                .special_case = special_case,
                .valid_not_zero_divisor = active.sub(row.zero_divisor),
                .valid_not_special = active.sub(special_case),
                .q_sum = q_sum,
                .c_sum = c_sum,
                .r_sum = r_sum,
                .diffs = diffs,
                .result = result,
                .negation_carries = negation_carries,
                .prefixes = prefixes,
                .product_carries = carry,
                .sign_checks = .{
                    is_signed.mul(row.rs1.next[3].sub(row.b_sign.mul(ops.q(128))))
                        .mul(ops.q(2)),
                    is_signed.mul(row.rs2.next[3].sub(row.c_sign.mul(ops.q(128))))
                        .mul(ops.q(2)),
                },
            };
        }

        pub inline fn directRow(row: Row, is_active: S) DirectConstraints {
            @setEvalBranchQuota(100_000);
            const one = S.one();
            const d = derive(row);
            var out: [DIRECT_CONSTRAINT_COUNT]S = undefined;
            var n: usize = 0;

            out[n] = d.active.mul(one.sub(d.active));
            n += 1;
            inline for ([_]S{ row.is_div, row.is_divu, row.is_rem, row.is_remu }) |flag| {
                out[n] = flag.mul(one.sub(flag));
                n += 1;
            }
            inline for ([_]S{
                row.zero_divisor,
                row.r_zero,
                row.b_sign,
                row.c_sign,
                row.q_sign,
                row.sign_xor,
            }) |value| {
                out[n] = value.mul(one.sub(value));
                n += 1;
            }
            inline for (row.lt_markers) |marker| {
                out[n] = marker.mul(one.sub(marker));
                n += 1;
            }
            inline for ([_]S{
                d.special_case,
                d.valid_not_zero_divisor,
                d.valid_not_special,
            }) |value| {
                out[n] = value.mul(one.sub(value));
                n += 1;
            }
            inline for (row.rs2.next) |limb| {
                out[n] = row.zero_divisor.mul(limb);
                n += 1;
            }
            inline for (row.q) |limb| {
                out[n] = row.zero_divisor.mul(limb.sub(ops.q(255)));
                n += 1;
            }
            out[n] = d.valid_not_zero_divisor.mul(
                d.c_sum.mul(row.c_sum_inv).sub(one),
            );
            n += 1;
            inline for (row.r) |limb| {
                out[n] = row.r_zero.mul(limb);
                n += 1;
            }
            out[n] = d.valid_not_special.mul(d.r_sum.mul(row.r_sum_inv).sub(one));
            n += 1;

            out[n] = one.sub(d.is_signed).mul(row.b_sign);
            n += 1;
            out[n] = one.sub(d.is_signed).mul(row.c_sign);
            n += 1;
            out[n] = d.active.mul(
                row.sign_xor.sub(row.b_sign).sub(row.c_sign)
                    .add(row.b_sign.mul(row.c_sign).mul(ops.q(2))),
            );
            n += 1;
            out[n] = one.sub(row.zero_divisor).mul(d.q_sum)
                .mul(row.q_sign.sub(row.sign_xor));
            n += 1;
            out[n] = one.sub(row.zero_divisor)
                .mul(row.q_sign.sub(row.sign_xor)).mul(row.q_sign);
            n += 1;
            out[n] = row.zero_divisor.mul(row.q_sign.sub(d.is_signed));
            n += 1;

            inline for (0..4) |limb| {
                const previous = if (limb == 0)
                    S.zero()
                else
                    d.negation_carries[limb - 1];
                const carry = d.negation_carries[limb];
                out[n] = one.sub(row.sign_xor)
                    .mul(row.r_abs[limb].sub(row.r[limb]));
                n += 1;
                out[n] = if (limb == 0)
                    row.sign_xor.mul(carry).mul(carry.sub(one))
                else
                    row.sign_xor.mul(carry.sub(previous)).mul(carry.sub(one));
                n += 1;
                out[n] = row.sign_xor.mul(one.sub(carry)).mul(row.r_abs[limb]);
                n += 1;
                out[n] = row.sign_xor.mul(
                    row.r_abs[limb].sub(ops.q(256))
                        .mul(row.r_inv[limb]).sub(one),
                );
                n += 1;
            }

            var scan_limb: usize = 4;
            while (scan_limb > 0) {
                scan_limb -= 1;
                out[n] = one.sub(d.prefixes[scan_limb]).mul(d.diffs[scan_limb]);
                n += 1;
                out[n] = row.lt_markers[scan_limb]
                    .mul(row.lt_diff.sub(d.diffs[scan_limb]));
                n += 1;
            }
            out[n] = d.active.mul(one.sub(d.prefixes[0]));
            n += 1;
            out[n] = row.destination.nonzero.mul(row.destination.nonzero.sub(one));
            n += 1;
            out[n] = row.rd.addr.mul(one.sub(row.destination.nonzero));
            n += 1;
            out[n] = row.rd.addr.mul(row.destination.inverse)
                .sub(row.destination.nonzero);
            n += 1;
            inline for (0..4) |limb| {
                out[n] = row.rd.next[limb].sub(
                    row.destination.nonzero.mul(d.result[limb]),
                );
                n += 1;
            }
            inline for (0..4) |limb| {
                out[n] = d.active.mul(
                    row.rs1.next[limb].sub(row.rs1.previous[limb]),
                );
                n += 1;
            }
            inline for (0..4) |limb| {
                out[n] = d.active.mul(
                    row.rs2.next[limb].sub(row.rs2.previous[limb]),
                );
                n += 1;
            }
            std.debug.assert(n == DIRECT_CONSTRAINT_COUNT - 1);
            out[n] = d.active.sub(is_active);
            n += 1;
            std.debug.assert(n == DIRECT_CONSTRAINT_COUNT);
            return .{ .values = out };
        }

        pub fn lookups(columns: []const S) !e.List {
            var result: e.List = undefined;
            try lookupsInto(columns, &result);
            return result;
        }

        pub fn lookupsInto(columns: []const S, result: *e.List) !void {
            lookupsRowInto(try Row.fromMainColumns(columns), result);
        }

        fn lookupsRowInto(row: Row, result: *e.List) void {
            @setEvalBranchQuota(100_000);
            const d = derive(row);
            const negative_active = d.active.neg();
            const zero = S.zero();
            const one = S.one();
            const four = ops.q(4);
            const source_1_clock = row.clock.sub(one).mul(four).add(one);
            const source_2_clock = row.clock.sub(one).mul(four).add(ops.q(2));
            const destination_clock = row.clock.sub(one).mul(four).add(ops.q(3));
            const source_1_gap = source_1_clock.sub(row.rs1.previous_clock).sub(one);
            const source_2_gap = source_2_clock.sub(row.rs2.previous_clock).sub(one);
            const destination_gap = destination_clock.sub(row.rd.previous_clock).sub(one);
            const opcode = row.is_div.mul(ops.q(OPCODE_IDS[0]))
                .add(row.is_divu.mul(ops.q(OPCODE_IDS[1])))
                .add(row.is_rem.mul(ops.q(OPCODE_IDS[2])))
                .add(row.is_remu.mul(ops.q(OPCODE_IDS[3])));
            const quotient_sign_live = d.is_signed.mul(d.valid_not_zero_divisor)
                .sub(row.b_sign.mul(row.c_sign));

            result.* = .{ .batch_size = LOOKUP_BATCH_SIZE };
            appendLookup(result, 0, negative_active, .{
                row.pc, opcode, row.rd.addr, row.rs1.addr, row.rs2.addr,
            });
            appendLookup(result, 1, negative_active, .{ row.pc, row.clock });
            appendLookup(result, 2, d.active, .{
                row.pc.add(four), row.clock.add(one),
            });
            appendLookup(result, 3, negative_active, .{
                zero,                row.rs1.addr,        row.rs1.previous_clock,
                row.rs1.previous[0], row.rs1.previous[1], row.rs1.previous[2],
                row.rs1.previous[3],
            });
            appendLookup(result, 4, d.active, .{
                zero,            row.rs1.addr,    source_1_clock,
                row.rs1.next[0], row.rs1.next[1], row.rs1.next[2],
                row.rs1.next[3],
            });
            appendLookup(result, 5, negative_active, .{source_1_gap});
            appendLookup(result, 6, negative_active, .{
                zero,                row.rs2.addr,        row.rs2.previous_clock,
                row.rs2.previous[0], row.rs2.previous[1], row.rs2.previous[2],
                row.rs2.previous[3],
            });
            appendLookup(result, 7, d.active, .{
                zero,            row.rs2.addr,    source_2_clock,
                row.rs2.next[0], row.rs2.next[1], row.rs2.next[2],
                row.rs2.next[3],
            });
            appendLookup(result, 8, negative_active, .{source_2_gap});
            appendLookup(result, 9, negative_active, .{
                row.rs2.next[0], row.rs2.next[1],
            });
            appendLookup(result, 10, negative_active, .{
                row.rs2.next[2], row.rs2.next[3],
            });
            inline for (d.product_carries, 0..) |carry, limb| {
                const value = if (limb < 4) row.q[limb] else row.r[limb - 4];
                appendLookup(result, 11 + limb, negative_active, .{ value, carry });
            }
            appendLookup(result, 19, quotient_sign_live.neg(), .{
                zero,
                row.q[3].sub(row.q_sign.mul(ops.q(128))),
            });
            appendLookup(result, 20, negative_active, .{
                d.sign_checks[0], d.sign_checks[1],
            });
            appendLookup(result, 21, d.valid_not_special.neg(), .{
                row.lt_diff.sub(one),
            });
            appendLookup(result, 22, negative_active, .{
                zero,               row.rd.addr,        row.rd.previous_clock,
                row.rd.previous[0], row.rd.previous[1], row.rd.previous[2],
                row.rd.previous[3],
            });
            appendLookup(result, 23, d.active, .{
                zero,           row.rd.addr,    destination_clock,
                row.rd.next[0], row.rd.next[1], row.rd.next[2],
                row.rd.next[3],
            });
            appendLookup(result, 24, negative_active, .{destination_gap});
            std.debug.assert(result.len == LOOKUP_COUNT);
        }

        inline fn appendLookup(
            result: *e.List,
            comptime index: usize,
            numerator: S,
            values: anytype,
        ) void {
            const descriptor = CANONICAL_LOOKUP_RECIPE[index];
            comptime if (@intFromEnum(descriptor.recipe) != index or
                descriptor.arity != values.len)
            {
                @compileError("typed DIV fixed lookup append drifted");
            };
            const target = &result.entries[index];
            target.* = .{
                .domain = descriptor.domain,
                .numerator = numerator,
                .arity = descriptor.arity,
                .role = descriptor.role,
                .access_ordinal = descriptor.access_ordinal,
            };
            inline for (values, 0..) |value, value_index|
                target.values[value_index] = value;
            result.len = index + 1;
        }
    };
}
