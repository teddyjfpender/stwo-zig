//! Canonical relation challenge powers for symbolic provider admission.
const S = @import("symbolic.zig").Scalar;
const native_relations = @import("../relation_challenges.zig");
pub fn Relation(comptime Scalar: type) type {
    return struct {
        z: Scalar,
        alpha: Scalar,
        pub fn combine(self: @This(), values: anytype) Scalar {
            var powers: [values.len]Scalar = undefined;
            var power = Scalar.one();
            for (&powers) |*slot| {
                slot.* = power;
                power = power.mul(self.alpha);
            }
            return native_relations.combineGeneric(Scalar, self.z, powers, values);
        }
    };
}
const R = Relation(S);
pub const Relations = struct {
    registers_state: R,
    memory_access: R,
    program_access: R,
    merkle: R,
    poseidon2: R,
    poseidon2_io: R,
    bitwise: R,
    range_check_20: R,
    range_check_8_11: R,
    range_check_8_8_4: R,
    range_check_8_8: R,
    range_check_m31: R,
};
