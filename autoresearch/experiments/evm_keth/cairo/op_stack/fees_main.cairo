%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from starkware.cairo.common.cairo_builtins import (
    BitwiseBuiltin, PoseidonBuiltin, ModBuiltin, HashBuiltin, SignatureBuiltin, EcOpBuiltin
)
from starkware.cairo.common.math import assert_nn_le
from ethereum_types.bytes import TupleBytes
from ethereum_types.numeric import U256
from ethereum.crypto.hash import keccak256
from ethereum.utils.numeric import divmod
from op_stack.fastlz import flz_length
from op_stack.fees import fjord_fee, operator_fee, estimated_size_scaled

func main{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*,
    keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*, range_check96_ptr: felt*,
    add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}() {
    alloc_locals;
    local transactions: TupleBytes;
    local gas_limits: felt*;
    local gas_used: felt*;
    local base_fee: U256;
    local blob_fee: U256;
    local base_scalar;
    local blob_scalar;
    local operator_scalar;
    local operator_constant;
    local jovian;
    local da_scalar;
    %{
        from typing import Tuple
        from ethereum_types.bytes import Bytes
        from ethereum_types.numeric import U256
        ids.transactions = gen_arg(Tuple[Bytes, ...], tuple(Bytes.fromhex(x.removeprefix("0x")) for x in program_input["transactions"]))
        ids.gas_limits = segments.gen_arg(program_input["gas_limits"])
        ids.gas_used = segments.gen_arg(program_input["gas_used"])
        ids.base_fee = gen_arg(U256, U256(program_input["base_fee"]))
        ids.blob_fee = gen_arg(U256, U256(program_input["blob_fee"]))
        ids.base_scalar = program_input["base_scalar"]
        ids.blob_scalar = program_input["blob_scalar"]
        ids.operator_scalar = program_input["operator_scalar"]
        ids.operator_constant = program_input["operator_constant"]
        ids.jovian = program_input["jovian"]
        ids.da_scalar = program_input["da_scalar"]
    %}
    assert_nn_le(transactions.value.len, 1000000);
    assert_nn_le(da_scalar, 65535);
    assert_nn_le(base_fee.value.low, 2 ** 128 - 1);
    assert_nn_le(base_fee.value.high, 2 ** 128 - 1);
    assert_nn_le(blob_fee.value.low, 2 ** 128 - 1);
    assert_nn_le(blob_fee.value.high, 2 ** 128 - 1);
    assert_nn_le(base_scalar, 0xffffffff);
    assert_nn_le(blob_scalar, 0xffffffff);
    assert_nn_le(operator_scalar, 0xffffffff);
    assert_nn_le(operator_constant, 2 ** 64 - 1);
    assert jovian * (jovian - 1) = 0;
    let builtin_keccak_ptr = keccak_ptr;
    let (keccak_ptr) = alloc();
    let start = keccak_ptr;
    assert [output_ptr] = transactions.value.len;
    assert [output_ptr + 1] = base_fee.value.low;
    assert [output_ptr + 2] = base_fee.value.high;
    assert [output_ptr + 3] = blob_fee.value.low;
    assert [output_ptr + 4] = blob_fee.value.high;
    assert [output_ptr + 5] = base_scalar;
    assert [output_ptr + 6] = blob_scalar;
    assert [output_ptr + 7] = operator_scalar;
    assert [output_ptr + 8] = operator_constant;
    assert [output_ptr + 9] = jovian;
    assert [output_ptr + 10] = da_scalar;
    let output_ptr = output_ptr + 11;
    rows(transactions, gas_limits, gas_used, base_fee, blob_fee, base_scalar, blob_scalar,
         operator_scalar, operator_constant, jovian, da_scalar, 0);
    finalize_keccak(start, keccak_ptr);
    let keccak_ptr = builtin_keccak_ptr;
    return ();
}

func rows{output_ptr: felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*}(
    transactions: TupleBytes, gas_limits: felt*, gas_used: felt*, base_fee: U256, blob_fee: U256,
    base_scalar: felt, blob_scalar: felt, operator_scalar: felt, operator_constant: felt,
    jovian: felt, da_scalar: felt, index: felt
) {
    alloc_locals;
    if (index == transactions.value.len) {
        return ();
    }
    let data = transactions.value.data[index];
    let hash = keccak256(data);
    let size = flz_length(data);
    let fee = fjord_fee(size, base_fee, blob_fee, base_scalar, blob_scalar);
    let reserve = operator_fee(gas_limits[index], operator_scalar, operator_constant, jovian);
    let charged = operator_fee(gas_used[index], operator_scalar, operator_constant, jovian);
    assert_nn_le(gas_used[index], gas_limits[index]);
    let scaled = estimated_size_scaled(size);
    let (da_size, _) = divmod(scaled, 1000000);
    assert [output_ptr] = hash.value.low;
    assert [output_ptr + 1] = hash.value.high;
    assert [output_ptr + 2] = data.value.len;
    assert [output_ptr + 3] = size;
    assert [output_ptr + 4] = fee.value.low;
    assert [output_ptr + 5] = fee.value.high;
    assert [output_ptr + 6] = reserve;
    assert [output_ptr + 7] = charged;
    assert [output_ptr + 8] = da_size;
    assert [output_ptr + 9] = da_size * da_scalar;
    assert [output_ptr + 10] = gas_limits[index];
    assert [output_ptr + 11] = gas_used[index];
    let output_ptr = output_ptr + 12;
    return rows(transactions, gas_limits, gas_used, base_fee, blob_fee, base_scalar, blob_scalar,
                operator_scalar, operator_constant, jovian, da_scalar, index + 1);
}
