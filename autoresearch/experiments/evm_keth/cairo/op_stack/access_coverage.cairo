// Every finalized EVM account/storage dictionary key must have appeared in the
// supplied state view. Default-dictionary finalization constrains set membership.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.default_dict import default_dict_new
from starkware.cairo.common.dict_access import DictAccess
from ethereum_types.bytes import TupleBytes32
from ethereum.prague.fork_types import Address
from ethereum.prague.state import State
from legacy.utils.dict import dict_read, dict_write, default_dict_finalize
from cairo_core.hash.blake2s import blake2s_hash_many

func assert_access_coverage{range_check_ptr}(
    state: State, addresses: Address*, keys: TupleBytes32*, n: felt
) {
    alloc_locals;
    let (accounts) = default_dict_new(0);
    local account_start: DictAccess* = accounts;
    let (storage) = default_dict_new(0);
    local storage_start: DictAccess* = storage;
    let allowed_accounts = accounts;
    let allowed_storage = storage;
    with allowed_accounts, allowed_storage {
        allow_accounts(addresses, keys, n);
        local storage_after_allow: DictAccess* = allowed_storage;
        let main = state.value._main_trie.value._data;
        check_keys{allowed=allowed_accounts}(
            cast(main.value.dict_ptr_start, DictAccess*), cast(main.value.dict_ptr, DictAccess*));
        local accounts_after_check: DictAccess* = allowed_accounts;
        let allowed_storage = storage_after_allow;
        let slots = state.value._storage_tries.value._data;
        check_keys{allowed=allowed_storage}(
            cast(slots.value.dict_ptr_start, DictAccess*), cast(slots.value.dict_ptr, DictAccess*));
        local storage_after_check: DictAccess* = allowed_storage;
        default_dict_finalize(account_start, accounts_after_check, 0);
        default_dict_finalize(storage_start, storage_after_check, 0);
    }
    // EIP-6780's transaction-created marker set starts empty. Its initial
    // values must not be supplied freely by the input State hint.
    let created = state.value.created_accounts;
    default_dict_finalize(cast(created.value.dict_ptr_start, DictAccess*),
                          cast(created.value.dict_ptr, DictAccess*), 0);
    return ();
}

func allow_accounts{range_check_ptr, allowed_accounts: DictAccess*, allowed_storage: DictAccess*}(
    addresses: Address*, keys: TupleBytes32*, n: felt
) {
    alloc_locals;
    if (n == 0) {
        return ();
    }
    dict_write{dict_ptr=allowed_accounts}(addresses[0].value, 1);
    local allowed_accounts: DictAccess* = allowed_accounts;
    allow_storage(addresses[0], keys[0], 0);
    return allow_accounts(addresses + 1, keys + 1, n - 1);
}

func allow_storage{range_check_ptr, allowed_storage: DictAccess*}(
    address: Address, keys: TupleBytes32, index: felt
) {
    alloc_locals;
    if (index == keys.value.len) {
        return ();
    }
    let (buffer) = alloc();
    assert buffer[0] = address.value;
    assert buffer[1] = keys.value.data[index].value.low;
    assert buffer[2] = keys.value.data[index].value.high;
    let (key) = blake2s_hash_many(3, buffer);
    dict_write{dict_ptr=allowed_storage}(key, 1);
    return allow_storage(address, keys, index + 1);
}

func check_keys{allowed: DictAccess*}(current: DictAccess*, end: DictAccess*) {
    if (current == end) {
        return ();
    }
    let (member) = dict_read{dict_ptr=allowed}(current.key);
    with_attr error_message("EVM access outside committed view") {
        assert member = 1;
    }
    return check_keys(current + DictAccess.SIZE, end);
}
