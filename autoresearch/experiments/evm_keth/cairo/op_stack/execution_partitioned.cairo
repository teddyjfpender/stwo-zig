// Three independently verified STARKs joined by state-view and diff commitments.
// Phase 0 authenticates every read, 1 executes, and 2 authenticates every change.
%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin, HashBuiltin, SignatureBuiltin, EcOpBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from starkware.cairo.common.math import assert_nn_le
from ethereum.crypto.hash import Hash32, keccak256
from ethereum_types.bytes import Bytes, BytesStruct
from ethereum_types.numeric import U256Struct
from ethereum.prague.state import State, finalize_state
from ethereum.prague.vm import BlockOutput, BlockOutputStruct, BlockOutput__hash__, empty_block_output
from ethereum.prague.vm.env_impl import BlockEnvImpl
from mpt.hash_diff import hash_state_account_diff, hash_state_storage_diff
from op_stack.execution_inputs import load_input, Input
from op_stack.environment_binding import bind_environment
from op_stack.state_view import detach_account_snapshot, state_view
from op_stack.state_authentication import authenticate_state
from op_stack.access_coverage import assert_access_coverage
from op_stack.root_transition import root_diff_hashes
from op_stack.state_bound_execution import execute_action

func phase_result{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}(input: Input*, phase: felt) -> (felt, Hash32, felt, Hash32, felt, felt) {
    alloc_locals;
    tempvar zero = Hash32(new U256Struct(0, 0));
    local zero: Hash32 = zero;
    let (empty_data) = alloc();
    tempvar empty_bytes = Bytes(new BytesStruct(empty_data, 0));
    let empty_receipt = keccak256(empty_bytes);
    local empty_receipt: Hash32 = empty_receipt;
    if (phase == 2) {
        let (accounts, slots) = root_diff_hashes(input.before, input.after, input.nodes, input.address_preimages, input.storage_preimages);
        return (0, empty_receipt, 0, zero, accounts, slots);
    }
    let state = detach_account_snapshot(input.env.value.state);
    let view = state_view{state=state}(input.addresses, input.keys, input.n, 1);
    local view: Hash32 = view;
    if (phase == 0) {
        let node_store = input.nodes;
        with node_store {
            authenticate_state{state=state}(input.before, input.addresses, input.keys, input.n);
        }
        finalize_state{state=state}();
        return (0, empty_receipt, 0, view, 0, 0);
    }
    assert phase = 1;
    let block_env = input.env;
    with block_env {
        BlockEnvImpl.set_state(state);
        assert_nn_le(input.previous_gas.value, block_env.value.block_gas_limit.value);
        let empty = empty_block_output();
        tempvar block_output = BlockOutput(new BlockOutputStruct(
            input.previous_gas, empty.value.transactions_trie, empty.value.receipts_trie,
            empty.value.receipt_keys, empty.value.block_logs, empty.value.withdrawals_trie,
            empty.value.blob_gas_used, empty.value.requests));
        with block_output {
            let (tx_hash, used, receipt, footprint) = execute_action(input.action, input.header.value.parent_hash,
                input.raw, input.encoded, input.index, input.previous_gas);
            local used = used;
            local footprint = footprint;
            local range_check96_ptr: felt* = range_check96_ptr;
            local add_mod_ptr: ModBuiltin* = add_mod_ptr;
            local mul_mod_ptr: ModBuiltin* = mul_mod_ptr;
            let receipt_hash = keccak256(receipt);
            local receipt_hash: Hash32 = receipt_hash;
            let state = block_env.value.state;
            state_view{state=state}(input.addresses, input.keys, input.n, 0);
            finalize_state{state=state}();
            assert_access_coverage(state, input.addresses, input.keys, input.n);
            local state: State = state;
            BlockOutput__hash__(block_output);
            let accounts = hash_state_account_diff(state);
            local accounts = accounts;
            let slots = hash_state_storage_diff(state);
            return (used, receipt_hash, footprint, view, accounts, slots);
        }
    }
}

func main{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*,
    keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*, range_check96_ptr: felt*,
    add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}() {
    alloc_locals;
    let input = load_input();
    local input: Input* = input;
    local phase;
    %{ ids.phase = program_input["proof_phase"] %}
    assert phase * (phase - 1) * (phase - 2) = 0;
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
    let tx_hash = keccak256(input.raw);
    local tx_hash: Hash32 = tx_hash;
    let (used, receipt_hash, footprint, view, accounts, slots) = phase_result(input, phase);
    assert_nn_le(input.previous_gas.value + used, input.header.value.gas_limit.value);
    assert [output_ptr] = 0x6f705f657865637574696f6e5f706172746974696f6e5f7631;
    assert [output_ptr + 1] = phase;
    assert [output_ptr + 2] = input.action;
    assert [output_ptr + 3] = 10;
    assert [output_ptr + 4] = block_hash.value.low;
    assert [output_ptr + 5] = block_hash.value.high;
    assert [output_ptr + 6] = input.index.value;
    assert [output_ptr + 7] = tx_hash.value.low;
    assert [output_ptr + 8] = tx_hash.value.high;
    assert [output_ptr + 9] = input.before.value.low;
    assert [output_ptr + 10] = input.before.value.high;
    assert [output_ptr + 11] = input.after.value.low;
    assert [output_ptr + 12] = input.after.value.high;
    assert [output_ptr + 13] = input.previous_gas.value;
    assert [output_ptr + 14] = used;
    assert [output_ptr + 15] = receipt_hash.value.low;
    assert [output_ptr + 16] = receipt_hash.value.high;
    assert [output_ptr + 17] = footprint;
    assert [output_ptr + 18] = view.value.low;
    assert [output_ptr + 19] = view.value.high;
    assert [output_ptr + 20] = accounts;
    assert [output_ptr + 21] = slots;
    let output_ptr = output_ptr + 22;
    finalize_keccak(start, keccak_ptr);
    let keccak_ptr = builtin_keccak_ptr;
    return ();
}
