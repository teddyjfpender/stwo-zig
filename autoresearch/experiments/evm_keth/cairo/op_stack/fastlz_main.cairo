%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from starkware.cairo.common.cairo_builtins import (
    BitwiseBuiltin, PoseidonBuiltin, ModBuiltin, HashBuiltin, SignatureBuiltin, EcOpBuiltin
)
from ethereum_types.bytes import Bytes
from ethereum.crypto.hash import keccak256
from op_stack.fastlz import flz_length

func main{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*,
    keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*, range_check96_ptr: felt*,
    add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}() {
    alloc_locals;
    local data: Bytes;
    %{
        from ethereum_types.bytes import Bytes
        ids.data = gen_arg(Bytes, Bytes.fromhex(program_input["encoded"].removeprefix("0x")))
    %}
    let builtin_keccak_ptr = keccak_ptr;
    let (keccak_ptr) = alloc();
    let start = keccak_ptr;
    let hash = keccak256(data);
    let length = flz_length(data);
    assert [output_ptr] = hash.value.low;
    assert [output_ptr + 1] = hash.value.high;
    assert [output_ptr + 2] = data.value.len;
    assert [output_ptr + 3] = length;
    finalize_keccak(start, keccak_ptr);
    let keccak_ptr = builtin_keccak_ptr;
    let output_ptr = output_ptr + 4;
    return ();
}
