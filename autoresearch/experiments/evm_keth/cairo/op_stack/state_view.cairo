// Commitment to the complete supplied access view, including unchanged reads.
// This is not an Ethereum MPT root or an in-Cairo membership proof.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, assert_le_felt
from ethereum_types.bytes import TupleBytes32
from ethereum.prague.fork_types import Address, MappingAddressAccount, MappingAddressAccountStruct
from ethereum.prague.trie import TrieAddressOptionalAccount, TrieAddressOptionalAccountStruct
from ethereum.prague.state import State, StateStruct, account_exists, get_account, get_storage
from ethereum.crypto.hash import Hash32
from ethereum.prague.vm.env_impl import BlockEnvironment
from cairo_core.hash.blake2s import blake2s, blake2s_add_felt

const VIEW_DOMAIN = 0x6f705f73746174655f766965775f7632;
const ENV_DOMAIN = 0x6f705f656e7669726f6e6d656e745f7631;

func environment_view{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(env: BlockEnvironment) -> Hash32 {
    alloc_locals;
    let (buffer) = alloc();
    let data = buffer;
    with data {
        blake2s_add_felt(ENV_DOMAIN, 0);
        blake2s_add_felt(env.value.chain_id.value, 0);
        blake2s_add_felt(env.value.block_gas_limit.value, 0);
        blake2s_add_felt(env.value.coinbase.value, 0);
        blake2s_add_felt(env.value.number.value, 0);
        blake2s_add_felt(env.value.base_fee_per_gas.value, 0);
        blake2s_add_felt(env.value.time.value.low, 0);
        blake2s_add_felt(env.value.time.value.high, 0);
        blake2s_add_felt(env.value.prev_randao.value.low, 0);
        blake2s_add_felt(env.value.prev_randao.value.high, 0);
        blake2s_add_felt(env.value.excess_blob_gas.value, 0);
        blake2s_add_felt(env.value.parent_beacon_block_root.value.low, 0);
        blake2s_add_felt(env.value.parent_beacon_block_root.value.high, 0);
        let hashes = env.value.block_hashes;
        assert_nn_le(hashes.value.len, 256);
        blake2s_add_felt(hashes.value.len, 0);
        hash_history(hashes.value.data, hashes.value.len);
        let (hash) = blake2s(buffer, (data - buffer) * 4);
        tempvar result = Hash32(new hash);
        return result;
    }
}

func hash_history{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, data: felt*}(hashes: Hash32*, n: felt) {
    if (n == 0) {
        return ();
    }
    blake2s_add_felt(hashes[0].value.low, 0);
    blake2s_add_felt(hashes[0].value.high, 0);
    return hash_history(hashes + 1, n - 1);
}

// The first snapshot supplies original SSTORE values. As in Keth's body entry,
// detach its account parent before transaction execution/finalization.
func detach_account_snapshot(state: State) -> State {
    // An input hint cannot pre-mark an existing account as created in this
    // transaction and thereby alter EIP-6780 SELFDESTRUCT behavior.
    with_attr error_message("Initial transaction-created marker set must be empty") {
        assert state.value.created_accounts.value.dict_ptr_start = state.value.created_accounts.value.dict_ptr;
    }
    tempvar data = MappingAddressAccount(new MappingAddressAccountStruct(
        state.value._main_trie.value._data.value.dict_ptr_start,
        state.value._main_trie.value._data.value.dict_ptr,
        cast(0, MappingAddressAccountStruct*)
    ));
    tempvar trie = TrieAddressOptionalAccount(new TrieAddressOptionalAccountStruct(
        state.value._main_trie.value.secured, state.value._main_trie.value.default, data
    ));
    tempvar result = State(new StateStruct(trie, state.value._storage_tries,
        state.value.created_accounts, state.value.original_storage_tries));
    return result;
}

func state_view{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, state: State}(
    addresses: Address*, keys: TupleBytes32*, n: felt, require_uncached: felt
) -> Hash32 {
    alloc_locals;
    assert_nn_le(n, 1000000);
    let (buffer) = alloc();
    let data = buffer;
    with data {
        blake2s_add_felt(VIEW_DOMAIN, 0);
        blake2s_add_felt(n, 0);
        blake2s_add_felt(require_uncached, 0);
        view_accounts(addresses, keys, n, require_uncached);
        let (hash) = blake2s(buffer, (data - buffer) * 4);
        tempvar result = Hash32(new hash);
        return result;
    }
}

func view_accounts{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, state: State, data: felt*}(
    addresses: Address*, keys: TupleBytes32*, n: felt, require_uncached: felt
) {
    alloc_locals;
    if (n == 0) {
        return ();
    }
    let address = addresses[0];
    assert_le_felt(address.value, 2 ** 160 - 1);
    let exists = account_exists(address);
    let account = get_account(address);
    if (require_uncached * exists.value != 0) {
        // Initial cached code must never bypass get_account_code's Keccak check.
        assert cast(account.value.code.value, felt) = 0;
    }
    assert_nn_le(account.value.nonce.value, 2 ** 64 - 1);
    assert_nn_le(account.value.balance.value.low, 2 ** 128 - 1);
    assert_nn_le(account.value.balance.value.high, 2 ** 128 - 1);
    assert_nn_le(account.value.code_hash.value.low, 2 ** 128 - 1);
    assert_nn_le(account.value.code_hash.value.high, 2 ** 128 - 1);
    blake2s_add_felt(address.value, 0);
    blake2s_add_felt(exists.value, 0);
    blake2s_add_felt(account.value.nonce.value, 0);
    blake2s_add_felt(account.value.balance.value.low, 0);
    blake2s_add_felt(account.value.balance.value.high, 0);
    blake2s_add_felt(account.value.code_hash.value.low, 0);
    blake2s_add_felt(account.value.code_hash.value.high, 0);
    commit_initial_storage_root(account.value.storage_root.value.low,
                                account.value.storage_root.value.high, require_uncached);
    assert_nn_le(keys[0].value.len, 1000000);
    blake2s_add_felt(keys[0].value.len, 0);
    view_storage(address, keys[0], 0);
    return view_accounts(addresses + 1, keys + 1, n - 1, require_uncached);
}

func commit_initial_storage_root{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, data: felt*}(
    low: felt, high: felt, initial: felt
) {
    if (initial == 0) {
        return ();
    }
    assert_nn_le(low, 2 ** 128 - 1);
    assert_nn_le(high, 2 ** 128 - 1);
    blake2s_add_felt(low, 0);
    blake2s_add_felt(high, 0);
    return ();
}

func view_storage{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, state: State, data: felt*}(
    address: Address, keys: TupleBytes32, index: felt
) {
    alloc_locals;
    if (index == keys.value.len) {
        return ();
    }
    let key = keys.value.data[index];
    assert_nn_le(key.value.low, 2 ** 128 - 1);
    assert_nn_le(key.value.high, 2 ** 128 - 1);
    let value = get_storage(address, key);
    assert_nn_le(value.value.low, 2 ** 128 - 1);
    assert_nn_le(value.value.high, 2 ** 128 - 1);
    blake2s_add_felt(key.value.low, 0);
    blake2s_add_felt(key.value.high, 0);
    blake2s_add_felt(value.value.low, 0);
    blake2s_add_felt(value.value.high, 0);
    return view_storage(address, keys, index + 1);
}
