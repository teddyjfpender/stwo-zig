// RIP-7212 verification using constrained modular arithmetic and group addition.
// Scalars use 256 fixed binary digits; no signature-validity or MSM-result hint.
from starkware.cairo.common.cairo_builtins import ModBuiltin
from starkware.cairo.common.math import assert_nn_le
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import U256, U256Struct, U384, U384Struct
from ethereum.utils.numeric import divmod, U256_le, U256_sub, U256__eq__
from cairo_ec.curve.g1_point import G1Point, G1PointStruct, G1Point_zero
from cairo_ec.ec_ops import ec_add
from cairo_ec.uint384 import uint256_to_uint384, uint384_to_uint256, uint384_eq_mod_p
from cairo_ec.circuits.mod_ops_compiled import mul, add, div
from op_stack.environment_binding import read_be
from op_stack.p256_parameters import parameters, Curve

func word{range_check_ptr}(data: Bytes, offset: felt) -> U256 {
    alloc_locals;
    let high = read_be(data.value.data + offset, 16, 0);
    local high = high;
    let low = read_be(data.value.data + offset + 16, 16, 0);
    tempvar result = U256(new U256Struct(low, high));
    return result;
}

func wide{range_check_ptr}(value: U256) -> U384 {
    let converted = uint256_to_uint384([value.value]);
    tempvar result = U384(new converted);
    return result;
}

func invalid_scalar{range_check_ptr}(value: U256, order: U256) -> felt {
    if (value.value.low == 0 and value.value.high == 0) {
        return 1;
    }
    let high = U256_le(order, value);
    return high.value;
}

func reduce_once{range_check_ptr}(value: U256, modulus: U256) -> U256 {
    let high = U256_le(modulus, value);
    if (high.value != 0) {
        let reduced = U256_sub(value, modulus);
        return reduced;
    }
    return value;
}

func multiply_limb{
    range_check_ptr, range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}(base: G1Point, limb: felt, remaining: felt, accumulator: G1Point, a: U384, p: U384) -> (G1Point, G1Point) {
    alloc_locals;
    if (remaining == 0) {
        assert limb = 0;
        return (base, accumulator);
    }
    let (next, bit) = divmod(limb, 2);
    local next = next;
    local range_check_ptr = range_check_ptr;
    local updated: G1Point;
    if (bit != 0) {
        let sum = ec_add(accumulator, base, a, p);
        assert updated = sum;
        tempvar range_check96_ptr = range_check96_ptr;
        tempvar add_mod_ptr = add_mod_ptr;
        tempvar mul_mod_ptr = mul_mod_ptr;
    } else {
        assert updated = accumulator;
        tempvar range_check96_ptr = range_check96_ptr;
        tempvar add_mod_ptr = add_mod_ptr;
        tempvar mul_mod_ptr = mul_mod_ptr;
    }
    let range_check96_ptr = cast([ap - 3], felt*);
    let add_mod_ptr = cast([ap - 2], ModBuiltin*);
    let mul_mod_ptr = cast([ap - 1], ModBuiltin*);
    let doubled = ec_add(base, base, a, p);
    return multiply_limb(doubled, next, remaining - 1, updated, a, p);
}

func multiply{
    range_check_ptr, range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}(point: G1Point, scalar: U256, curve: Curve*) -> G1Point {
    let zero = G1Point_zero();
    let (base, accumulator) = multiply_limb(point, scalar.value.low, 128, zero, curve.a, curve.p);
    let (base, accumulator) = multiply_limb(base, scalar.value.high, 128, accumulator, curve.a, curve.p);
    return accumulator;
}

func verify_signature{
    range_check_ptr, range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}(data: Bytes) -> felt {
    alloc_locals;
    if (data.value.len != 160) {
        return 0;
    }
    let curve = parameters();
    local curve: Curve* = curve;
    let hash = word(data, 0);
    local hash: U256 = hash;
    let r = word(data, 32);
    local r: U256 = r;
    let s = word(data, 64);
    local s: U256 = s;
    let x = word(data, 96);
    local x: U256 = x;
    let y = word(data, 128);
    local y: U256 = y;
    let bad_r = invalid_scalar(r, curve.order256);
    local bad_r = bad_r;
    let bad_s = invalid_scalar(s, curve.order256);
    local bad_s = bad_s;
    let bad_x = U256_le(curve.prime256, x);
    local bad_x_value = bad_x.value;
    let bad_y = U256_le(curve.prime256, y);
    if (bad_r + bad_s + bad_x_value + bad_y.value != 0) {
        return 0;
    }
    let x_wide = wide(x);
    local x_wide: U384 = x_wide;
    let y_wide = wide(y);
    local y_wide: U384 = y_wide;
    local range_check_ptr = range_check_ptr;
    let lhs = mul(y_wide, y_wide, curve.p);
    local lhs: U384 = lhs;
    let square = mul(x_wide, x_wide, curve.p);
    let cube = mul(square, x_wide, curve.p);
    local cube: U384 = cube;
    let linear = mul(curve.a, x_wide, curve.p);
    let rhs = add(cube, linear, curve.p);
    let rhs = add(rhs, curve.b, curve.p);
    let on_curve = uint384_eq_mod_p(lhs, rhs, curve.p);
    if (on_curve == 0) {
        return 0;
    }
    let h_wide = wide(hash);
    local h_wide: U384 = h_wide;
    let r_wide = wide(r);
    local r_wide: U384 = r_wide;
    let s_wide = wide(s);
    local s_wide: U384 = s_wide;
    local range_check_ptr = range_check_ptr;
    let u1 = div(h_wide, s_wide, curve.order);
    local u1: U384 = u1;
    let u2 = div(r_wide, s_wide, curve.order);
    local u2: U384 = u2;
    let u1_bits = uint384_to_uint256([u1.value]);
    tempvar u1_scalar = U256(new u1_bits);
    local u1_scalar: U256 = u1_scalar;
    let u2_bits = uint384_to_uint256([u2.value]);
    tempvar u2_scalar = U256(new u2_bits);
    local u2_scalar: U256 = u2_scalar;
    tempvar public_key = G1Point(new G1PointStruct(x_wide, y_wide));
    local public_key: G1Point = public_key;
    let left = multiply(curve.generator, u1_scalar, curve);
    local left: G1Point = left;
    let right = multiply(public_key, u2_scalar, curve);
    local range_check_ptr = range_check_ptr;
    let sum = ec_add(left, right, curve.a, curve.p);
    let x_bits = uint384_to_uint256([sum.value.x.value]);
    tempvar result_x = U256(new x_bits);
    // Modular circuit representatives are reduced before the ECDSA x mod n
    // comparison. Both p and n exceed 2^255, so one subtraction suffices.
    let result_x = reduce_once(result_x, curve.prime256);
    let result_x = reduce_once(result_x, curve.order256);
    let equal = U256__eq__(result_x, r);
    return equal.value;
}
