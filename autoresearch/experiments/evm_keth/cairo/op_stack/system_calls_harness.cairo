from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from ethereum_types.bytes import TupleBytes32
from ethereum.prague.fork_types import Address
from ethereum.prague.vm.env_impl import BlockEnvironment, BlockEnvImpl
from ethereum.prague.state import finalize_state
from ethereum.crypto.hash import Hash32
from op_stack.block_system_calls import pre_transactions
from op_stack.state_view import detach_account_snapshot, state_view
from op_stack.access_coverage import assert_access_coverage

func transition{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment,
}(parent_hash: Hash32) -> (Hash32, Hash32) {
    alloc_locals;
    local addresses: Address*;
    local keys: TupleBytes32*;
    local n;
    %{
        from typing import Tuple
        from ethereum_types.bytes import Bytes32
        ids.addresses = segments.gen_arg([int.from_bytes(bytes.fromhex(a["address"][2:]), "little") for a in program_input["access_list"]])
        ids.keys = segments.gen_arg([gen_arg(Tuple[Bytes32, ...], tuple(Bytes32.fromhex(k[2:]) for k in a["storageKeys"])) for a in program_input["access_list"]])
        ids.n = len(program_input["access_list"])
    %}
    let state = detach_account_snapshot(block_env.value.state);
    let before = state_view{state=state}(addresses, keys, n, 1);
    BlockEnvImpl.set_state(state);
    let (keccak_ptr) = alloc();
    let start = keccak_ptr;
    pre_transactions(parent_hash);
    let state = block_env.value.state;
    let after = state_view{state=state}(addresses, keys, n, 0);
    finalize_state{state=state}();
    assert_access_coverage(state, addresses, keys, n);
    BlockEnvImpl.set_state(state);
    finalize_keccak(start, keccak_ptr);
    return (before, after);
}
