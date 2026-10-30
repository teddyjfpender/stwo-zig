// Bind finalized execution changes to an authenticated MPT root transition.
// authenticate_state must separately bind unchanged reads to the starting root.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin
from starkware.cairo.common.dict_access import DictAccess
from ethereum.prague.state import State
from ethereum.crypto.hash import Hash32
from ethereum_types.bytes import Bytes, BytesStruct
from ethereum.utils.bytes import Bytes32_to_Bytes
from mpt.types import (
    NodeStore, MappingBytes32Address, MappingBytes32Bytes32,
    AddressAccountDiffEntry, StorageDiffEntry, AccountDiff, StorageDiff,
)
from mpt.trie_diff import OptionalUnionInternalNodeExtendedImpl, compute_diff_entrypoint
from mpt.hash_diff import hash_state_account_diff, hash_state_storage_diff, hash_account_diff_segment, hash_storage_diff_segment
from mpt.utils import sort_account_diff, sort_storage_diff
from legacy.utils.dict import dict_squash

func assert_root_transition{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*,
}(state: State, before: Hash32, after: Hash32, node_store: NodeStore,
  address_preimages: MappingBytes32Address, storage_key_preimages: MappingBytes32Bytes32) {
    alloc_locals;
    let (account_hash, slot_hash) = root_diff_hashes(before, after, node_store, address_preimages, storage_key_preimages);
    local account_hash = account_hash;
    local slot_hash = slot_hash;
    let execution_accounts = hash_state_account_diff(state);
    local execution_accounts = execution_accounts;
    let execution_slots = hash_state_storage_diff(state);
    with_attr error_message("Execution changes do not match MPT root transition") {
        assert execution_accounts = account_hash;
        assert execution_slots = slot_hash;
    }
    return ();
}

func root_diff_hashes{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*,
}(before: Hash32, after: Hash32, node_store: NodeStore,
  address_preimages: MappingBytes32Address, storage_key_preimages: MappingBytes32Bytes32) -> (felt, felt) {
    alloc_locals;
    let left_bytes = Bytes32_to_Bytes(before);
    let left = OptionalUnionInternalNodeExtendedImpl.from_bytes(left_bytes);
    let right_bytes = Bytes32_to_Bytes(after);
    let right = OptionalUnionInternalNodeExtendedImpl.from_bytes(right_bytes);
    let (path_data) = alloc();
    tempvar path = Bytes(new BytesStruct(path_data, 0));
    let (account_start: AddressAccountDiffEntry*) = alloc();
    let (storage_start: StorageDiffEntry*) = alloc();
    let (accounts, slots) = compute_diff_entrypoint(
        node_store=node_store, address_preimages=address_preimages, storage_key_preimages=storage_key_preimages,
        left=left, right=right, start_path=path,
        main_trie_start=account_start, main_trie_end=account_start,
        storage_tries_start=storage_start, storage_tries_end=storage_start);
    local node_store: NodeStore = node_store;
    local address_preimages: MappingBytes32Address = address_preimages;
    local storage_key_preimages: MappingBytes32Bytes32 = storage_key_preimages;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    local keccak_ptr: felt* = keccak_ptr;
    local poseidon_ptr: PoseidonBuiltin* = poseidon_ptr;
    local slots: StorageDiff = slots;
    let accounts = sort_account_diff(accounts);
    local accounts: AccountDiff = accounts;
    let slots = sort_storage_diff(slots);
    local slots: StorageDiff = slots;
    let account_hash = hash_account_diff_segment(accounts);
    local account_hash = account_hash;
    let slot_hash = hash_storage_diff_segment(slots);
    return (account_hash, slot_hash);
}
