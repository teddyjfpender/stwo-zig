// Fjord data-fee and Isthmus/Jovian operator-fee arithmetic, including
// full uint256 base fees. No guessed fee or compressed-length witnesses.
from starkware.cairo.common.math import assert_nn_le, split_felt
from starkware.cairo.common.math_cmp import is_le_felt
from ethereum_types.numeric import U256, U256Struct
from ethereum.utils.numeric import divmod

func estimated_size_scaled{range_check_ptr}(fastlz_size: felt) -> felt {
    assert_nn_le(fastlz_size, 0xffffffff);
    let scaled = fastlz_size * 836500;
    let below_minimum = is_le_felt(scaled, 142585600);
    if (below_minimum != 0) {
        return 100000000;
    }
    return scaled - 42585600;
}

func fjord_fee{range_check_ptr}(
    fastlz_size: felt, base_fee: U256, blob_fee: U256, base_scalar: felt, blob_scalar: felt
) -> U256 {
    alloc_locals;
    assert_nn_le(base_fee.value.low, 2 ** 128 - 1);
    assert_nn_le(base_fee.value.high, 2 ** 128 - 1);
    assert_nn_le(blob_fee.value.low, 2 ** 128 - 1);
    assert_nn_le(blob_fee.value.high, 2 ** 128 - 1);
    assert_nn_le(base_scalar, 0xffffffff);
    assert_nn_le(blob_scalar, 0xffffffff);
    let estimated = estimated_size_scaled(fastlz_size);
    // Each product has fewer than 219 bits, so no Cairo-field wrap is possible.
    let low_cost = 16 * base_scalar * base_fee.value.low + blob_scalar * blob_fee.value.low;
    let high_cost = 16 * base_scalar * base_fee.value.high + blob_scalar * blob_fee.value.high;
    let (carry, low) = split_felt(estimated * low_cost);
    let (top, middle) = split_felt(estimated * high_cost + carry);
    // Long division of the exact 384-bit numerator by 1e12. Every quotient
    // limb is below 2^128; a nonzero top quotient cannot fund a valid tx.
    let (overflow, rem) = divmod(top, 1000000000000);
    assert overflow = 0;
    let (high, rem) = divmod(rem * 2 ** 128 + middle, 1000000000000);
    let (low, _) = divmod(rem * 2 ** 128 + low, 1000000000000);
    tempvar fee = U256(new U256Struct(low, high));
    return fee;
}

func operator_fee{range_check_ptr}(gas: felt, scalar: felt, constant: felt, jovian: felt) -> felt {
    assert_nn_le(gas, 2 ** 64 - 1);
    assert_nn_le(scalar, 0xffffffff);
    assert_nn_le(constant, 2 ** 64 - 1);
    if (jovian == 0) {
        let (fee, _) = divmod(gas * scalar, 1000000);
        return fee + constant;
    }
    assert jovian = 1;
    return gas * scalar * 100 + constant;
}
