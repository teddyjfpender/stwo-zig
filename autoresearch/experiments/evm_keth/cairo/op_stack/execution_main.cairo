%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin, HashBuiltin, SignatureBuiltin, EcOpBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from starkware.cairo.common.math import assert_nn_le
from ethereum.crypto.hash import Hash32
from op_stack.execution_inputs import load_input, Input
from op_stack.environment_binding import bind_environment
from op_stack.state_bound_execution import transition

func main{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*,
    keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*, range_check96_ptr: felt*,
    add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}() {
    alloc_locals;
    let input = load_input();
    local input: Input* = input;
    local builtin_keccak_ptr: felt* = keccak_ptr;
    let (keccak_ptr) = alloc();
    local start: felt* = keccak_ptr;
    let (block_hash, parent_root) = bind_environment(input.env, input.header, input.history, input.history_len);
    local block_hash: Hash32 = block_hash;
    if (input.action == 0) {
        assert [input.before.value] = [parent_root.value];
        assert input.index.value = 0;
        assert input.previous_gas.value = 0;
        assert input.raw.value.len = 0;
    }
    let block_env = input.env;
    let node_store = input.nodes;
    let address_preimages = input.address_preimages;
    let storage_key_preimages = input.storage_preimages;
    with block_env, node_store, address_preimages, storage_key_preimages {
        let (tx_hash, used, receipt_hash, footprint) = transition(input.action, input.header.value.parent_hash,
            input.before, input.after, input.raw, input.encoded, input.index, input.previous_gas,
            input.addresses, input.keys, input.n);
        assert_nn_le(input.previous_gas.value + used, input.header.value.gas_limit.value);
        assert [output_ptr] = 0x6f705f657865637574696f6e5f7472616e736974696f6e5f7631;
        assert [output_ptr + 1] = input.action;
        assert [output_ptr + 2] = 10;
        assert [output_ptr + 3] = block_hash.value.low;
        assert [output_ptr + 4] = block_hash.value.high;
        assert [output_ptr + 5] = input.index.value;
        assert [output_ptr + 6] = tx_hash.value.low;
        assert [output_ptr + 7] = tx_hash.value.high;
        assert [output_ptr + 8] = input.before.value.low;
        assert [output_ptr + 9] = input.before.value.high;
        assert [output_ptr + 10] = input.after.value.low;
        assert [output_ptr + 11] = input.after.value.high;
        assert [output_ptr + 12] = input.previous_gas.value;
        assert [output_ptr + 13] = used;
        assert [output_ptr + 14] = receipt_hash.value.low;
        assert [output_ptr + 15] = receipt_hash.value.high;
        assert [output_ptr + 16] = footprint;
        let output_ptr = output_ptr + 17;
        finalize_keccak(start, keccak_ptr);
        let keccak_ptr = builtin_keccak_ptr;
        return ();
    }
}
