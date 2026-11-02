// Typed differential entry for sequencer execution and receipt construction.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from ethereum_types.bytes import Bytes, TupleBytes32
from ethereum_types.numeric import Uint
from ethereum.prague.fork_types import Address
from ethereum.prague.blocks import UnionBytesLegacyTransaction
from ethereum.prague.vm import BlockOutput, BlockOutputStruct, BlockOutput__hash__, empty_block_output
from ethereum.prague.vm.env_impl import BlockEnvironment, BlockEnvImpl
from ethereum.prague.state import finalize_state
from ethereum.crypto.hash import Hash32
from op_stack.state_view import detach_account_snapshot, state_view
from op_stack.access_coverage import assert_access_coverage
from op_stack.sequencer_execution import execute_sequencer

func transition{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment,
}(raw: Bytes, encoded: UnionBytesLegacyTransaction, index: Uint, previous_gas: Uint) -> (BlockOutput, Hash32, felt, Hash32, Hash32) {
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
    state_view{state=state}(addresses, keys, n, 1);
    BlockEnvImpl.set_state(state);
    let (keccak_ptr) = alloc();
    let start = keccak_ptr;
    let empty = empty_block_output();
    tempvar block_output = BlockOutput(new BlockOutputStruct(
        previous_gas, empty.value.transactions_trie, empty.value.receipts_trie,
        empty.value.receipt_keys, empty.value.block_logs, empty.value.withdrawals_trie,
        empty.value.blob_gas_used, empty.value.requests));
    with block_output {
    let (tx_hash, used) = execute_sequencer(raw, encoded, index);
    let state = block_env.value.state;
    let after = state_view{state=state}(addresses, keys, n, 0);
    finalize_state{state=state}();
    assert_access_coverage(state, addresses, keys, n);
    BlockEnvImpl.set_state(state);
    let output_hash = BlockOutput__hash__(block_output);
    finalize_keccak(start, keccak_ptr);
    return (block_output, tx_hash, used, after, output_hash);
    }
}
