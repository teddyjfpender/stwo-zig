//! Field-generic terminal-read equations and packed RAM relation emission.
//! Standalone algebra only: no accepted proof, PCS component or key is exposed.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Protocol = @import("block_v7_terminal_protocol_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
pub const TUPLE_WIDTH = Word.TRANSITION_ARITY;
pub const COLUMN_COUNT = TUPLE_WIDTH + 8;
pub const CONSTRAINT_COUNT = TUPLE_WIDTH + 16;

pub fn witness(plan: Protocol.Plan, index: usize, high_byte: u8) ![COLUMN_COUNT]M {
    if (index >= Protocol.ROWS) return error.InvalidTerminalReadIndex;
    var row: [COLUMN_COUNT]M = @splat(M.zero());
    if (index >= Protocol.READS) return row;
    @memcpy(row[0..TUPLE_WIDTH], &Word.transitionTuple(try plan.transition(index, high_byte)));
    if (index == Protocol.READS - 1) for (0..8) |bit| {
        row[TUPLE_WIDTH + bit] = M.fromCanonical((high_byte >> @intCast(bit)) & 1);
    };
    return row;
}

pub fn Algebra(comptime S: type) type {
    return struct {
        pub const Row = [COLUMN_COUNT]S;
        pub const Fixed = struct { active: S, tail: S, address: [2]S, clock: [4]S, value: [2]S };
        pub const Emission = struct { tuple: [TUPLE_WIDTH]S, weight: S };

        pub fn lift(value: Protocol.Fixed) Fixed {
            var result: Fixed = undefined;
            result.active = base(value.active);
            result.tail = base(value.tail);
            for (&result.address, value.address) |*out, cell| out.* = base(cell);
            for (&result.clock, value.clock) |*out, cell| out.* = base(cell);
            for (&result.value, value.value) |*out, cell| out.* = base(cell);
            return result;
        }

        pub fn constraints(fixed: Fixed, row: Row) [CONSTRAINT_COUNT]S {
            var h = S.zero();
            var out: [CONSTRAINT_COUNT]S = undefined;
            for (row[TUPLE_WIDTH..], 0..) |bit, index| {
                h = h.add(base(M.fromCanonical(@as(u32, 1) << @intCast(index))).mul(bit));
                out[TUPLE_WIDTH + index] = bit.mul(bit.sub(S.one()));
                out[TUPLE_WIDTH + 8 + index] = S.one().sub(fixed.tail).mul(bit);
            }
            const value = [2]S{ fixed.value[0], fixed.value[1].add(fixed.tail.mul(base(M.fromCanonical(256))).mul(h)) };
            const expected = .{fixed.active} ++ fixed.address ++ fixed.clock ++ value ++ value;
            for (0..TUPLE_WIDTH) |i| out[i] = row[i].sub(expected[i]);
            return out;
        }

        pub fn emission(fixed: Fixed, row: Row) Emission {
            return .{ .tuple = row[0..TUPLE_WIDTH].*, .weight = fixed.active };
        }

        /// Cyclic LogUp recurrence: normalization is claimed_sum/domain_size.
        /// The proof integration must absorb that physical claim before its
        /// interaction commitment and close the positive sum against RAM.
        pub fn interactionConstraint(fixed: Fixed, row: Row, relation: anytype, current: S, previous: S, normalized: S) S {
            const item = emission(fixed, row);
            return current.sub(previous).add(normalized).mul(relation.combineSecure(item.tuple)).sub(item.weight);
        }

        fn base(value: M) S {
            if (S == M) return value;
            if (S == core.fields.packed_qm31.PackedQM31) return S.splat(core.fields.qm31.QM31.fromBase(value));
            return S.fromBase(value);
        }
    };
}
