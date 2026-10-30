// A root-to-root execution statement, including authenticated unchanged reads.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from starkware.cairo.common.math import assert_nn_le
from ethereum_types.bytes import Bytes, BytesStruct, TupleBytes32
from ethereum_types.numeric import Uint, U256Struct
from ethereum.prague.blocks import UnionBytesLegacyTransaction
from ethereum.prague.fork_types import Address
from ethereum.prague.state import State, finalize_state
from ethereum.prague.vm import BlockOutput, BlockOutput__hash__, empty_block_output, BlockOutputStruct
from ethereum.prague.vm.env_impl import BlockEnvironment, BlockEnvImpl
from ethereum.crypto.hash import Hash32, keccak256
from mpt.types import NodeStore, MappingBytes32Address, MappingBytes32Bytes32
from op_stack.state_authentication import authenticate_state
from op_stack.root_transition import assert_root_transition
from op_stack.state_view import detach_account_snapshot, state_view
from op_stack.access_coverage import assert_access_coverage
from op_stack.block_system_calls import pre_transactions
from op_stack.deposit_types import decode_deposit
from op_stack.deposit_execution import execute_deposit_detailed
from op_stack.sequencer_execution import execute_sequencer_detailed
from op_stack.receipts import deposit_receipt, sequencer_receipt

func execute_action{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment, block_output: BlockOutput,
}(action: felt, parent_hash: Hash32, raw: Bytes, encoded: UnionBytesLegacyTransaction,
  index: Uint, previous_gas: Uint) -> (Hash32, felt, Bytes, felt) {
    alloc_locals;
    if (action == 0) {
        pre_transactions(parent_hash);
        tempvar zero = Hash32(new U256Struct(0, 0));
        let (data) = alloc();
        tempvar receipt = Bytes(new BytesStruct(data, 0));
        return (zero, 0, receipt, 0);
    }
    if (action == 1) {
        let tx_hash = keccak256(raw);
        let deposit = decode_deposit(raw);
        assert_nn_le(deposit.gas.value, block_env.value.block_gas_limit.value - previous_gas.value);
        let (used, success, nonce, logs) = execute_deposit_detailed(deposit, tx_hash);
        let receipt = deposit_receipt(success, Uint(previous_gas.value + used), logs, nonce);
        return (tx_hash, used, receipt, 0);
    }
    assert action = 2;
    let (tx_hash, used, footprint) = execute_sequencer_detailed(raw, encoded, index);
    let receipt = sequencer_receipt(index);
    return (tx_hash, used, receipt, footprint);
}

func transition{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment, node_store: NodeStore,
    address_preimages: MappingBytes32Address, storage_key_preimages: MappingBytes32Bytes32,
}(action: felt, parent_hash: Hash32, before: Hash32, after: Hash32,
  raw: Bytes, encoded: UnionBytesLegacyTransaction, index: Uint, previous_gas: Uint,
  addresses: Address*, keys: TupleBytes32*, n: felt) -> (Hash32, felt, Hash32, felt) {
    alloc_locals;
    assert_nn_le(previous_gas.value, block_env.value.block_gas_limit.value);
    let state = detach_account_snapshot(block_env.value.state);
    // Enforce the code-cache and account-metadata input rules as well.
    state_view{state=state}(addresses, keys, n, 1);
    authenticate_state{state=state}(before, addresses, keys, n);
    local node_store: NodeStore = node_store;
    BlockEnvImpl.set_state(state);
    let empty = empty_block_output();
    tempvar block_output = BlockOutput(new BlockOutputStruct(
        previous_gas, empty.value.transactions_trie, empty.value.receipts_trie,
        empty.value.receipt_keys, empty.value.block_logs, empty.value.withdrawals_trie,
        empty.value.blob_gas_used, empty.value.requests));
    with block_output {
        let (tx_hash, used, receipt, footprint) = execute_action(action, parent_hash, raw, encoded, index, previous_gas);
        local tx_hash: Hash32 = tx_hash;
        local used = used;
        local footprint = footprint;
        local range_check96_ptr: felt* = range_check96_ptr;
        local add_mod_ptr: ModBuiltin* = add_mod_ptr;
        local mul_mod_ptr: ModBuiltin* = mul_mod_ptr;
        let receipt_hash = keccak256(receipt);
        local receipt_hash: Hash32 = receipt_hash;
        let state = block_env.value.state;
        state_view{state=state}(addresses, keys, n, 0);
        finalize_state{state=state}();
        assert_access_coverage(state, addresses, keys, n);
        BlockEnvImpl.set_state(state);
        local block_env: BlockEnvironment = block_env;
        local state: State = state;
        BlockOutput__hash__(block_output);
        assert_root_transition(state, before, after, node_store, address_preimages, storage_key_preimages);
        return (tx_hash, used, receipt_hash, footprint);
    }
}
