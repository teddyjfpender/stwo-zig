//! Row witnesses of the eleven circuit AIR components: base-trace columns and
//! the lookups each row adds to the common LogUp relation.
//!
//! Ports `crates/circuit_prover/src/witness/components/*.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230) by column order and lookup order,
//! not by structure (design §4.3):
//!
//! - one row function per gate component writes the row's base columns from
//!   the gate's input values; `lookups` derives the row's LogUp tuples from
//!   those columns and the preprocessed row, so the base pass (table
//!   multiplicities) and the interaction pass (fractions) read one definition;
//! - `LookupData` is never materialised: the interaction pass re-derives each
//!   tuple from the committed base columns;
//! - table multiplicities are direct-indexed `u32` histograms,
//!   `row = (a << n_bits) | b` (`verify_bitwise_xor_12`: column
//!   `(ah << 2) + bh`, row `(al << 10) + bl`), instead of upstream's
//!   `make_input_to_row` hash maps and atomic columns. The counts are exact
//!   integer sums, so the committed multiplicity columns are identical.
//!
//! A lookup's numerator is `1` for a use and `-multiplicity` for a yield;
//! the secure columns pair consecutive lookups (`finalize_logup_in_pairs`),
//! with the pairing listed in `interaction_pairs`.

const std = @import("std");
const core = @import("stwo_core");
const component_list = @import("../common/component_list.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const ComponentList = component_list.ComponentList;

pub const Error = error{
    /// A gate's input is not a `(u16, u16, 0, 0)`-encoded u32 or the lookup
    /// it implies is outside its table (upstream panics on the
    /// `input_to_row` lookup).
    LookupOutsideTable,
};

/// The largest tuple, relation id included: `(GATE, address, 4 limbs)`.
pub const MAX_TUPLE: usize = 6;

/// One lookup of a row: `numerator / combine(tuple)`.
pub const Lookup = struct {
    numerator: M31,
    tuple: [MAX_TUPLE]M31 = undefined,
    len: u8,

    fn use(entries: anytype) Lookup {
        return withNumerator(M31.one(), entries);
    }

    fn yield(multiplicity: M31, entries: anytype) Lookup {
        return withNumerator(multiplicity.neg(), entries);
    }

    fn withNumerator(numerator: M31, entries: anytype) Lookup {
        var lookup = Lookup{ .numerator = numerator, .len = entries.len };
        inline for (entries, 0..) |entry, index| lookup.tuple[index] = entry;
        return lookup;
    }

    pub fn relation(self: Lookup) u32 {
        return self.tuple[0].toU32();
    }

    pub fn values(self: *const Lookup) []const M31 {
        return self.tuple[0..self.len];
    }
};

inline fn m(value: u32) M31 {
    return M31.fromCanonical(value);
}

const gate = m(component_list.GATE_RELATION_ID);
const rc16 = m(component_list.RANGE_CHECK_16_RELATION_ID);
const xor4 = m(component_list.VERIFY_BITWISE_XOR_4_RELATION_ID);
const xor7 = m(component_list.VERIFY_BITWISE_XOR_7_RELATION_ID);
const xor8 = m(component_list.VERIFY_BITWISE_XOR_8_RELATION_ID);
const xor8_b = m(component_list.VERIFY_BITWISE_XOR_8_B_RELATION_ID);
const xor9 = m(component_list.VERIFY_BITWISE_XOR_9_RELATION_ID);
const xor12 = m(component_list.VERIFY_BITWISE_XOR_12_RELATION_ID);

/// A u32 encoded in a QM31 as `(low u16, high u16, 0, 0)`:
/// `UInt32::from(q[0] | q[1] << 16)`.
inline fn u32Of(value: QM31) u32 {
    const limbs = value.toM31Array();
    return limbs[0].toU32() | (limbs[1].toU32() << 16);
}

inline fn lo(x: u32) u32 {
    return x & 0xffff;
}

inline fn hi(x: u32) u32 {
    return x >> 16;
}

// ---------------------------------------------------------------------------
// eq (`witness/components/eq.rs`): 4 columns, the gate's value.

pub const eq = struct {
    pub const n_columns = 4;
    pub const n_lookups = 2;
    pub const Pp = struct { in0: M31, in1: M31 };

    pub fn row(value: QM31, out: *[n_columns]M31) void {
        out.* = value.toM31Array();
    }

    pub fn lookups(c: *const [n_columns]M31, pp: Pp) [n_lookups]Lookup {
        return .{
            Lookup.use(.{ gate, pp.in0, c[0], c[1], c[2], c[3] }),
            Lookup.use(.{ gate, pp.in1, c[0], c[1], c[2], c[3] }),
        };
    }
};

// ---------------------------------------------------------------------------
// qm31_ops (`qm31_ops.rs`): in0, in1, out limbs.

pub const qm31_ops = struct {
    pub const n_columns = 12;
    pub const n_lookups = 3;
    pub const Pp = struct { in0: M31, in1: M31, out: M31, mults: M31 };

    pub fn row(in0: QM31, in1: QM31, out_value: QM31, out: *[n_columns]M31) void {
        out[0..4].* = in0.toM31Array();
        out[4..8].* = in1.toM31Array();
        out[8..12].* = out_value.toM31Array();
    }

    pub fn lookups(c: *const [n_columns]M31, pp: Pp) [n_lookups]Lookup {
        return .{
            Lookup.use(.{ gate, pp.in0, c[0], c[1], c[2], c[3] }),
            Lookup.use(.{ gate, pp.in1, c[4], c[5], c[6], c[7] }),
            Lookup.yield(pp.mults, .{ gate, pp.out, c[8], c[9], c[10], c[11] }),
        };
    }
};

// ---------------------------------------------------------------------------
// triple_xor (`triple_xor.rs`): limbs of a, b, c, a^b^c, their high bytes and
// the four byte xors of a and b.

pub const triple_xor = struct {
    pub const n_columns = 20;
    pub const n_lookups = 12;
    pub const Pp = struct { in0: M31, in1: M31, in2: M31, out: M31, mults: M31 };

    pub fn row(a: u32, b: u32, c: u32, o: u32, out: *[n_columns]M31) void {
        const limbs = [_]u32{ lo(a), hi(a), lo(b), hi(b), lo(c), hi(c), lo(o), hi(o) };
        for (limbs, 0..) |limb, index| {
            out[index] = m(limb);
            out[8 + index] = m(limb >> 8);
        }
        out[16] = m((limbs[0] & 0xff) ^ (limbs[2] & 0xff));
        out[17] = m((limbs[0] >> 8) ^ (limbs[2] >> 8));
        out[18] = m((limbs[1] & 0xff) ^ (limbs[3] & 0xff));
        out[19] = m((limbs[1] >> 8) ^ (limbs[3] >> 8));
    }

    pub fn lookups(c: *const [n_columns]M31, pp: Pp) [n_lookups]Lookup {
        const low = lowPart(8);
        return .{
            Lookup.use(.{ xor8, low(c[0], c[8]), low(c[2], c[10]), c[16] }),
            Lookup.use(.{ xor8, c[8], c[10], c[17] }),
            Lookup.use(.{ xor8, low(c[1], c[9]), low(c[3], c[11]), c[18] }),
            Lookup.use(.{ xor8, c[9], c[11], c[19] }),
            Lookup.use(.{ xor8, c[16], low(c[4], c[12]), low(c[6], c[14]) }),
            Lookup.use(.{ xor8, c[17], c[12], c[14] }),
            Lookup.use(.{ xor8, c[18], low(c[5], c[13]), low(c[7], c[15]) }),
            Lookup.use(.{ xor8, c[19], c[13], c[15] }),
            Lookup.use(.{ gate, pp.in0, c[0], c[1] }),
            Lookup.use(.{ gate, pp.in1, c[2], c[3] }),
            Lookup.use(.{ gate, pp.in2, c[4], c[5] }),
            Lookup.yield(pp.mults, .{ gate, pp.out, c[6], c[7] }),
        };
    }
};

/// `split_16_low_part_size_{n}`'s low part, `limb - high * 2^n`, as the
/// generated witness computes it in the field.
fn lowPart(comptime n_bits: u5) fn (M31, M31) M31 {
    return struct {
        fn f(limb: M31, high: M31) M31 {
            return limb.sub(high.mul(m(@as(u32, 1) << n_bits)));
        }
    }.f;
}

// ---------------------------------------------------------------------------
// m_31_to_u_32 (`m_31_to_u_32.rs`): the M31 input, its u16 limbs and the
// inverse-or-one of the input.

pub const m31_to_u32 = struct {
    pub const n_columns = 4;
    pub const n_lookups = 5;
    pub const Pp = struct { input: M31, output: M31, mults: M31 };

    pub fn row(input: M31, out: *[n_columns]M31) void {
        const x = input.toU32();
        out[0] = input;
        out[1] = m(lo(x));
        out[2] = m(hi(x));
        // `(is_zero + input).inverse()`; `input + 1` is never zero for a zero input.
        const base = if (input.isZero()) M31.one() else input;
        out[3] = base.inv() catch unreachable;
    }

    pub fn lookups(c: *const [n_columns]M31, pp: Pp) [n_lookups]Lookup {
        return .{
            Lookup.use(.{ rc16, c[1] }),
            Lookup.use(.{ rc16, c[2] }),
            Lookup.use(.{ rc16, m(32767).sub(c[2]) }),
            Lookup.use(.{ gate, pp.input, c[0] }),
            Lookup.yield(pp.mults, .{ gate, pp.output, c[1], c[2] }),
        };
    }
};

// ---------------------------------------------------------------------------
// blake_g_gate (`blake_g_gate.rs`): the inputs and claimed outputs as limbs,
// then the intermediate words of `G` split for the xor tables. The outputs
// are the gate's output wires; the AIR checks that they are `G(inputs)`.

pub const blake_g_gate = struct {
    pub const n_columns = 52;
    pub const n_lookups = 26;
    pub const Pp = struct { inputs: [6]M31, outputs: [4]M31, mults: M31 };

    /// `words`: a, b, c, d, f0, f1, then the outputs a', b', c', d'.
    pub fn row(words: [10]u32, out: *[n_columns]M31) void {
        for (words, 0..) |word, index| {
            out[2 * index] = m(lo(word));
            out[2 * index + 1] = m(hi(word));
        }
        const a = words[0];
        const b = words[1];
        const c = words[2];
        const d = words[3];
        const f0 = words[4];
        const a_out = words[6];
        const b_out = words[7];
        const c_out = words[8];
        const d_out = words[9];

        // Triple sum 32, then xor-rotate right by 16.
        const t0 = a +% b +% f0;
        out[20] = m(lo(t0));
        out[21] = m(hi(t0));
        out[22] = m(lo(t0) >> 8);
        out[23] = m(hi(t0) >> 8);
        out[24] = m(lo(d) >> 8);
        out[25] = m(hi(d) >> 8);
        const x26 = (lo(t0) & 0xff) ^ (lo(d) & 0xff);
        const x27 = (lo(t0) >> 8) ^ (lo(d) >> 8);
        const x28 = (hi(t0) & 0xff) ^ (hi(d) & 0xff);
        const x29 = (hi(t0) >> 8) ^ (hi(d) >> 8);
        out[26] = m(x26);
        out[27] = m(x27);
        out[28] = m(x28);
        out[29] = m(x29);
        const xr16 = (x28 + x29 * 256) | ((x26 + x27 * 256) << 16);

        // Triple sum 32 (c + xr16 + 0), then xor-rotate right by 12.
        const t1 = c +% xr16;
        out[30] = m(lo(t1));
        out[31] = m(hi(t1));
        out[32] = m(lo(b) >> 12);
        out[33] = m(hi(b) >> 12);
        out[34] = m(lo(t1) >> 12);
        out[35] = m(hi(t1) >> 12);
        const x36 = (lo(b) & 0xfff) ^ (lo(t1) & 0xfff);
        const x37 = (lo(b) >> 12) ^ (lo(t1) >> 12);
        const x38 = (hi(b) & 0xfff) ^ (hi(t1) & 0xfff);
        const x39 = (hi(b) >> 12) ^ (hi(t1) >> 12);
        out[36] = m(x36);
        out[37] = m(x37);
        out[38] = m(x38);
        out[39] = m(x39);
        const xr12 = (x37 + x38 * 16) | ((x39 + x36 * 16) << 16);

        // Verify xor-rotate right by 8: a' ^ xr16 == d' rotated.
        out[40] = m(lo(a_out) >> 8);
        out[41] = m(hi(a_out) >> 8);
        out[42] = m(lo(xr16) >> 8);
        out[43] = m(hi(xr16) >> 8);
        out[44] = m(lo(d_out) >> 8);
        out[45] = m(hi(d_out) >> 8);

        // Verify xor-rotate right by 7: xr12 ^ c' == b' rotated.
        out[46] = m(lo(xr12) >> 7);
        out[47] = m(hi(xr12) >> 7);
        out[48] = m(lo(c_out) >> 7);
        out[49] = m(hi(c_out) >> 7);
        out[50] = m(lo(b_out) >> 9);
        out[51] = m(hi(b_out) >> 9);
    }

    pub fn lookups(c: *const [n_columns]M31, pp: Pp) [n_lookups]Lookup {
        const low8 = lowPart(8);
        const low12 = lowPart(12);
        const low7 = lowPart(7);
        const low9 = lowPart(9);
        // The two xor-rotate outputs, recomposed from their xor columns.
        const xr16_lo = c[28].add(c[29].mul(m(256)));
        const xr16_hi = c[26].add(c[27].mul(m(256)));
        const xr12_lo = c[37].add(c[38].mul(m(16)));
        const xr12_hi = c[39].add(c[36].mul(m(16)));
        return .{
            // 0..7: xor_8 (6) and xor_8_b (2) in `LookupData` field order
            // interleaved as the interaction pairs consume them.
            Lookup.use(.{ xor8, low8(c[20], c[22]), low8(c[6], c[24]), c[26] }),
            Lookup.use(.{ xor8, c[22], c[24], c[27] }),
            Lookup.use(.{ xor8_b, low8(c[21], c[23]), low8(c[7], c[25]), c[28] }),
            Lookup.use(.{ xor8_b, c[23], c[25], c[29] }),
            Lookup.use(.{ xor12, low12(c[2], c[32]), low12(c[30], c[34]), c[36] }),
            Lookup.use(.{ xor4, c[32], c[34], c[37] }),
            Lookup.use(.{ xor12, low12(c[3], c[33]), low12(c[31], c[35]), c[38] }),
            Lookup.use(.{ xor4, c[33], c[35], c[39] }),
            Lookup.use(.{ xor8, c[40], c[42], low8(c[18], c[44]) }),
            Lookup.use(.{ xor8, low8(c[13], c[41]), low8(xr16_hi, c[43]), c[44] }),
            Lookup.use(.{ xor8, c[41], c[43], low8(c[19], c[45]) }),
            Lookup.use(.{ xor8, low8(c[12], c[40]), low8(xr16_lo, c[42]), c[45] }),
            Lookup.use(.{ xor9, c[46], c[48], low9(c[14], c[50]) }),
            Lookup.use(.{ xor7, low7(xr12_hi, c[47]), low7(c[17], c[49]), c[50] }),
            Lookup.use(.{ xor9, c[47], c[49], low9(c[15], c[51]) }),
            Lookup.use(.{ xor7, low7(xr12_lo, c[46]), low7(c[16], c[48]), c[51] }),
            // 16..25: the gate uses and yields.
            Lookup.use(.{ gate, pp.inputs[0], c[0], c[1] }),
            Lookup.use(.{ gate, pp.inputs[1], c[2], c[3] }),
            Lookup.use(.{ gate, pp.inputs[2], c[4], c[5] }),
            Lookup.use(.{ gate, pp.inputs[3], c[6], c[7] }),
            Lookup.use(.{ gate, pp.inputs[4], c[8], c[9] }),
            Lookup.use(.{ gate, pp.inputs[5], c[10], c[11] }),
            Lookup.yield(pp.mults, .{ gate, pp.outputs[0], c[12], c[13] }),
            Lookup.yield(pp.mults, .{ gate, pp.outputs[1], c[14], c[15] }),
            Lookup.yield(pp.mults, .{ gate, pp.outputs[2], c[16], c[17] }),
            Lookup.yield(pp.mults, .{ gate, pp.outputs[3], c[18], c[19] }),
        };
    }
};

// ---------------------------------------------------------------------------
// Tables: the multiplicity columns and the rows they yield.

/// A `verify_bitwise_xor_{n}` table other than 12: one multiplicity column
/// per relation over `2^(2 n)` rows, the table columns `bitwise_xor_{n}_*`.
pub const XorTable = struct {
    n_bits: u5,
    relations: []const M31,

    pub fn logSize(self: XorTable) u32 {
        return 2 * @as(u32, self.n_bits);
    }

    /// The row a use `(a, b, a ^ b)` increments.
    pub fn rowOf(self: XorTable, tuple: []const M31) Error!usize {
        return xorRow(self.n_bits, tuple);
    }
};

fn xorRow(n_bits: u5, tuple: []const M31) Error!usize {
    const a = tuple[1].toU32();
    const b = tuple[2].toU32();
    const limit = @as(u32, 1) << n_bits;
    if (a >= limit or b >= limit or tuple[3].toU32() != a ^ b) return error.LookupOutsideTable;
    return (@as(usize, a) << n_bits) | b;
}

pub const xor_8 = XorTable{ .n_bits = 8, .relations = &.{ xor8, xor8_b } };
pub const xor_4 = XorTable{ .n_bits = 4, .relations = &.{xor4} };
pub const xor_7 = XorTable{ .n_bits = 7, .relations = &.{xor7} };
pub const xor_9 = XorTable{ .n_bits = 9, .relations = &.{xor9} };

/// `verify_bitwise_xor_12` (`verify_bitwise_xor_12.rs`): 16 multiplicity
/// columns over 2^20 rows. Column `(ah << 2) + bh` holds the operands whose
/// top two bits are `ah`, `bh`; row `(al << 10) + bl` the low ten bits.
pub const xor_12 = struct {
    pub const limb_bits: u5 = 10;
    pub const expand_bits: u5 = 2;
    pub const log_size: u32 = 2 * limb_bits;
    pub const n_mult_columns: usize = 1 << (2 * expand_bits);
    pub const relation = xor12;

    pub const Slot = struct { column: usize, row: usize };

    pub fn slotOf(tuple: []const M31) Error!Slot {
        const a = tuple[1].toU32();
        const b = tuple[2].toU32();
        if (a >= 1 << 12 or b >= 1 << 12 or tuple[3].toU32() != a ^ b) return error.LookupOutsideTable;
        const mask = (@as(u32, 1) << limb_bits) - 1;
        return .{
            .column = ((a >> limb_bits) << expand_bits) + (b >> limb_bits),
            .row = ((a & mask) << limb_bits) + (b & mask),
        };
    }

    /// The tuple of multiplicity column `column` at `row`.
    pub fn tupleAt(column: usize, row: usize) [4]M31 {
        const ah: u32 = @intCast(column >> expand_bits);
        const bh: u32 = @intCast(column & ((1 << expand_bits) - 1));
        const al: u32 = @intCast(row >> limb_bits);
        const bl: u32 = @intCast(row & ((1 << limb_bits) - 1));
        const a = (ah << limb_bits) | al;
        const b = (bh << limb_bits) | bl;
        return .{ relation, m(a), m(b), m(a ^ b) };
    }
};

pub const range_check_16 = struct {
    pub const log_size: u32 = 16;
    pub const relation = rc16;

    pub fn rowOf(tuple: []const M31) Error!usize {
        const value = tuple[1].toU32();
        if (value >= 1 << 16) return error.LookupOutsideTable;
        return value;
    }
};

/// The table multiplicities the gate components' uses accumulate, as exact
/// `u32` counts (`AtomicMultiplicityColumn`).
pub const TableMultiplicities = struct {
    xor8: [2][]u32,
    xor12: [xor_12.n_mult_columns][]u32,
    xor4: []u32,
    xor7: []u32,
    xor9: []u32,
    rc16: []u32,

    pub fn init(allocator: std.mem.Allocator) !TableMultiplicities {
        var self: TableMultiplicities = undefined;
        var owned: std.ArrayListUnmanaged([]u32) = .empty;
        defer owned.deinit(allocator);
        errdefer for (owned.items) |counts| allocator.free(counts);
        const zeroed = struct {
            fn f(a: std.mem.Allocator, list: *std.ArrayListUnmanaged([]u32), log_size: u32) ![]u32 {
                const counts = try a.alloc(u32, @as(usize, 1) << @intCast(log_size));
                @memset(counts, 0);
                list.append(a, counts) catch |err| {
                    a.free(counts);
                    return err;
                };
                return counts;
            }
        }.f;
        for (&self.xor8) |*counts| counts.* = try zeroed(allocator, &owned, xor_8.logSize());
        for (&self.xor12) |*counts| counts.* = try zeroed(allocator, &owned, xor_12.log_size);
        self.xor4 = try zeroed(allocator, &owned, xor_4.logSize());
        self.xor7 = try zeroed(allocator, &owned, xor_7.logSize());
        self.xor9 = try zeroed(allocator, &owned, xor_9.logSize());
        self.rc16 = try zeroed(allocator, &owned, range_check_16.log_size);
        owned.clearRetainingCapacity();
        return self;
    }

    pub fn deinit(self: *TableMultiplicities, allocator: std.mem.Allocator) void {
        for (self.xor8) |counts| allocator.free(counts);
        for (self.xor12) |counts| allocator.free(counts);
        allocator.free(self.xor4);
        allocator.free(self.xor7);
        allocator.free(self.xor9);
        allocator.free(self.rc16);
        self.* = undefined;
    }

    /// Counts every table use among `lookups` (gate lookups are skipped).
    pub fn addUses(self: *TableMultiplicities, lookups: []const Lookup) Error!void {
        for (lookups) |*lookup| {
            const tuple = lookup.values();
            const id = lookup.tuple[0];
            if (id.eql(gate)) continue;
            if (id.eql(xor8)) {
                self.xor8[0][try xorRow(8, tuple)] += 1;
            } else if (id.eql(xor8_b)) {
                self.xor8[1][try xorRow(8, tuple)] += 1;
            } else if (id.eql(xor12)) {
                const slot = try xor_12.slotOf(tuple);
                self.xor12[slot.column][slot.row] += 1;
            } else if (id.eql(xor4)) {
                self.xor4[try xorRow(4, tuple)] += 1;
            } else if (id.eql(xor7)) {
                self.xor7[try xorRow(7, tuple)] += 1;
            } else if (id.eql(xor9)) {
                self.xor9[try xorRow(9, tuple)] += 1;
            } else if (id.eql(rc16)) {
                self.rc16[try range_check_16.rowOf(tuple)] += 1;
            } else unreachable;
        }
    }
};

/// The lookups of a table row. `mults` holds the row's multiplicity columns
/// (base-trace values) and `table` the preprocessed table columns.
pub fn xorTableLookups(table: XorTable, pp: [3]M31, mults: []const M31, out: []Lookup) void {
    for (table.relations, mults, out) |relation, multiplicity, *lookup|
        lookup.* = Lookup.yield(multiplicity, .{ relation, pp[0], pp[1], pp[2] });
}

/// The secure-column pairing of each component's lookups
/// (`write_interaction_trace`): consecutive pairs, an odd last lookup alone.
/// `verify_bitwise_xor_12` pairs its multiplicity columns (0, 1), (2, 3), ….
pub fn nInteractionColumns(n_lookups: usize) usize {
    return std.math.divCeil(usize, n_lookups, 2) catch unreachable;
}

test "circuit witness: interaction widths match the component facts" {
    const facts = component_list.component_facts;
    try std.testing.expectEqual(facts.eq.interaction_columns, 4 * nInteractionColumns(eq.n_lookups));
    try std.testing.expectEqual(facts.qm31_ops.interaction_columns, 4 * nInteractionColumns(qm31_ops.n_lookups));
    try std.testing.expectEqual(facts.triple_xor.interaction_columns, 4 * nInteractionColumns(triple_xor.n_lookups));
    try std.testing.expectEqual(facts.m_31_to_u_32.interaction_columns, 4 * nInteractionColumns(m31_to_u32.n_lookups));
    try std.testing.expectEqual(facts.blake_g_gate.interaction_columns, 4 * nInteractionColumns(blake_g_gate.n_lookups));
    try std.testing.expectEqual(facts.verify_bitwise_xor_8.interaction_columns, 4 * nInteractionColumns(2));
    try std.testing.expectEqual(facts.verify_bitwise_xor_12.interaction_columns, 4 * nInteractionColumns(xor_12.n_mult_columns));
    try std.testing.expectEqual(facts.eq.trace_columns, eq.n_columns);
    try std.testing.expectEqual(facts.qm31_ops.trace_columns, qm31_ops.n_columns);
    try std.testing.expectEqual(facts.triple_xor.trace_columns, triple_xor.n_columns);
    try std.testing.expectEqual(facts.m_31_to_u_32.trace_columns, m31_to_u32.n_columns);
    try std.testing.expectEqual(facts.blake_g_gate.trace_columns, blake_g_gate.n_columns);
}

test "circuit witness: xor_12 slots invert to their tuples" {
    const tuple = [_]M31{ xor12, m(0xabc), m(0x5d3), m(0xabc ^ 0x5d3) };
    const slot = try xor_12.slotOf(&tuple);
    try std.testing.expectEqual(@as(usize, (2 << 2) + 1), slot.column);
    const back = xor_12.tupleAt(slot.column, slot.row);
    for (tuple, back) |want, got| try std.testing.expect(want.eql(got));
}
