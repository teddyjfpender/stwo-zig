// Post-Isthmus OP pre-execution calls. OP omits Ethereum's Prague request
// queue calls after execution; the withdrawals header commits the MessagePasser.
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from ethereum.crypto.hash import Hash32
from ethereum.prague.fork_types import Address
from ethereum.prague.fork import process_unchecked_system_transaction, BEACON_ROOTS_ADDRESS, HISTORY_STORAGE_ADDRESS
from ethereum.prague.vm.env_impl import BlockEnvironment, BlockEnvImpl
from ethereum.utils.bytes import Bytes32_to_Bytes
from op_stack.deposit_execution import close_original_storage

func pre_transactions{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment,
}(parent_hash: Hash32) {
    alloc_locals;
    let beacon = Bytes32_to_Bytes(block_env.value.parent_beacon_block_root);
    process_unchecked_system_transaction(Address(BEACON_ROOTS_ADDRESS), beacon);
    let state = block_env.value.state;
    close_original_storage{state=state}();
    BlockEnvImpl.set_state(state);
    let parent = Bytes32_to_Bytes(parent_hash);
    process_unchecked_system_transaction(Address(HISTORY_STORAGE_ADDRESS), parent);
    let state = block_env.value.state;
    close_original_storage{state=state}();
    BlockEnvImpl.set_state(state);
    return ();
}
