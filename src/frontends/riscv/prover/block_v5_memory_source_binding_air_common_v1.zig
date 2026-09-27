//! Shared typed page-binding kernel; schemas fix exact original source
//! inventory and grammar. No host/source descriptor grants proof authority.
const core = @import("stwo_core");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Exact original source bit -> arithmetic recursion_wire(6) LogUp supplier.
        //! All bit values come from the ORIGINAL source main tree, never copied cells.
        const Eq = Schema.Equations;
        const First = Schema.Protocol;
        const Routing = Schema.BindingPlan;
        pub const PAIRS = Eq.BIT_COUNT / 2;
        pub const FIXED_COUNT = First.FIXED_COUNT + Routing.ROUTING_COUNT;
        pub const MAIN_COUNT = Eq.BIT_COUNT;
        pub const INTERACTION_COUNT = 4 * PAIRS;
        pub const CONSTRAINT_COUNT = 2 * MAIN_COUNT + PAIRS;
        pub fn Algebra(comptime S: type) type {
            return struct {
                pub const Challenge = struct { z: S, powers: [6]S };
                pub fn denominator(c: Challenge, circuit: S, node: S, value: S) S {
                    return c.powers[0].mul(circuit).add(c.powers[1].mul(node)).add(c.powers[2].mul(value)).sub(c.z);
                }
                pub fn constraints(fixed: [FIXED_COUNT]S, bits: [MAIN_COUNT]S, current: [INTERACTION_COUNT]S, previous: [INTERACTION_COUNT]S, normalized: [PAIRS]S, c: Challenge) [CONSTRAINT_COUNT]S {
                    var out: [CONSTRAINT_COUNT]S = undefined;
                    for (bits, 0..) |value, bit| {
                        out[2 * bit] = value.mul(value.sub(S.one()));
                        out[2 * bit + 1] = value.mul(S.one().sub(fixed[0]));
                    }
                    const circuit = fixed[First.FIXED_COUNT];
                    for (0..PAIRS) |pair| {
                        const bit = 2 * pair;
                        const at = First.FIXED_COUNT + 1 + 2 * bit;
                        const left = denominator(c, circuit, fixed[at], bits[bit]);
                        const right = denominator(c, circuit, fixed[at + 2], bits[bit + 1]);
                        const change = S.fromPartialEvals(current[4 * pair ..][0..4].*).sub(S.fromPartialEvals(previous[4 * pair ..][0..4].*)).add(normalized[pair]);
                        out[2 * MAIN_COUNT + pair] = change.mul(left).mul(right).sub(fixed[at + 1].mul(right)).sub(fixed[at + 3].mul(left));
                    }
                    return out;
                }
            };
        }
        pub fn degree(index: usize) !u8 {
            if (index >= CONSTRAINT_COUNT) return error.InvalidConstraintIndex;
            return if (index < 2 * MAIN_COUNT) 2 else 3;
        }
        comptime {
            if (MAIN_COUNT % 2 != 0 or @import("../recursion/air/wire_relation.zig").ARITY != 6) @compileError("source bit wire ABI drift");
        }
    };
}
