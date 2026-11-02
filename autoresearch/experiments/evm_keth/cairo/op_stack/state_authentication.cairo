// Authenticate every supplied account and slot, including unchanged reads.
// NodeStore values are witnesses; resolve checks each fetched node's Keccak.
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin
from starkware.cairo.common.math import assert_not_zero
from ethereum_types.bytes import Bytes, BytesStruct, TupleBytes32
from ethereum_types.numeric import U256, U256Struct
from ethereum.prague.fork_types import Address
from ethereum.prague.state import State, account_exists, get_account, get_storage
from ethereum.prague.trie import bytes_to_nibble_list
from ethereum.crypto.hash import Hash32, keccak256
from ethereum.utils.bytes import Bytes32_to_Bytes, Bytes20_to_Bytes, Bytes__eq__, Bytes__startswith__
from ethereum_rlp.rlp import Extended, Account_from_rlp, U256_from_rlp
from mpt.types import NodeStore, OptionalUnionInternalNodeExtended
from mpt.trie_diff import OptionalUnionInternalNodeExtendedImpl, resolve

func empty_bytes() -> Bytes {
    let (buffer) = alloc();
    tempvar result = Bytes(new BytesStruct(buffer, 0));
    return result;
}

func lookup{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*, node_store: NodeStore,
}(root: Hash32, secure_key: Hash32) -> Bytes {
    alloc_locals;
    let root_bytes = Bytes32_to_Bytes(root);
    let reference = OptionalUnionInternalNodeExtendedImpl.from_bytes(root_bytes);
    local reference: OptionalUnionInternalNodeExtended = reference;
    let bytes = Bytes32_to_Bytes(secure_key);
    let path = bytes_to_nibble_list(bytes);
    return walk(reference, path);
}

func walk{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*, node_store: NodeStore,
}(reference: OptionalUnionInternalNodeExtended, path: Bytes) -> Bytes {
    alloc_locals;
    let resolved = resolve(reference);
    if (cast(resolved.value, felt) == 0) {
        let empty = empty_bytes();
        return empty;
    }
    if (cast(resolved.value.leaf_node.value, felt) != 0) {
        let leaf = resolved.value.leaf_node;
        let equal = Bytes__eq__(path, leaf.value.rest_of_key);
        if (equal.value == 0) {
            let empty = empty_bytes();
        return empty;
        }
        return leaf.value.value.value.bytes;
    }
    if (cast(resolved.value.extension_node.value, felt) != 0) {
        let extension = resolved.value.extension_node;
        let segment = extension.value.key_segment;
        assert_not_zero(segment.value.len);
        let prefix = Bytes__startswith__(path, segment);
        if (prefix.value == 0) {
            let empty = empty_bytes();
        return empty;
        }
        tempvar rest = Bytes(new BytesStruct(path.value.data + segment.value.len,
                                            path.value.len - segment.value.len));
        let child = OptionalUnionInternalNodeExtendedImpl.from_extended(extension.value.subnode);
        return walk(child, rest);
    }
    let branch = resolved.value.branch_node;
    if (path.value.len == 0) {
        return branch.value.value.value.bytes;
    }
    let children = cast(branch.value.subnodes.value, Extended*);
    let child = OptionalUnionInternalNodeExtendedImpl.from_extended(children[path.value.data[0]]);
    tempvar rest = Bytes(new BytesStruct(path.value.data + 1, path.value.len - 1));
    return walk(child, rest);
}

func authenticate_state{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*, node_store: NodeStore, state: State,
}(root: Hash32, addresses: Address*, keys: TupleBytes32*, n: felt) {
    alloc_locals;
    if (n == 0) {
        return ();
    }
    let address_bytes = Bytes20_to_Bytes(addresses[0]);
    let secure_key = keccak256(address_bytes);
    let leaf = lookup(root, secure_key);
    local node_store: NodeStore = node_store;
    let exists = account_exists(addresses[0]);
    if (leaf.value.len == 0) {
        with_attr error_message("Account non-membership mismatch") {
            assert exists.value = 0;
        }
        absent_slots(addresses[0], keys[0], 0);
        return authenticate_state(root, addresses + 1, keys + 1, n - 1);
    }
    with_attr error_message("Account membership mismatch") {
        assert exists.value = 1;
    }
    let account = get_account(addresses[0]);
    local state: State = state;
    let (authenticated, storage_root) = Account_from_rlp(leaf);
    assert account.value.nonce.value = authenticated.value.nonce.value;
    assert [account.value.balance.value] = [authenticated.value.balance.value];
    assert [account.value.code_hash.value] = [authenticated.value.code_hash.value];
    assert [account.value.storage_root.value] = [authenticated.value.storage_root.value];
    authenticate_slots(authenticated.value.storage_root, addresses[0], keys[0], 0);
    return authenticate_state(root, addresses + 1, keys + 1, n - 1);
}

func absent_slots{range_check_ptr, state: State}(address: Address, keys: TupleBytes32, index: felt) {
    if (index == keys.value.len) {
        return ();
    }
    let value = get_storage(address, keys.value.data[index]);
    assert value.value.low = 0;
    assert value.value.high = 0;
    return absent_slots(address, keys, index + 1);
}

func authenticate_slots{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*, node_store: NodeStore, state: State,
}(root: Hash32, address: Address, keys: TupleBytes32, index: felt) {
    alloc_locals;
    if (index == keys.value.len) {
        return ();
    }
    let key_bytes = Bytes32_to_Bytes(keys.value.data[index]);
    let secure_key = keccak256(key_bytes);
    let leaf = lookup(root, secure_key);
    local node_store: NodeStore = node_store;
    let value = get_storage(address, keys.value.data[index]);
    local state: State = state;
    if (leaf.value.len == 0) {
        assert value.value.low = 0;
        assert value.value.high = 0;
        return authenticate_slots(root, address, keys, index + 1);
    }
    let authenticated = U256_from_rlp(leaf);
    assert [value.value] = [authenticated.value];
    return authenticate_slots(root, address, keys, index + 1);
}
