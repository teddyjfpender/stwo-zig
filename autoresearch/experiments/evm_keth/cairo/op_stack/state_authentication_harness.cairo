from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from starkware.cairo.common.dict_access import DictAccess
from ethereum_types.bytes import Bytes, TupleBytes32
from ethereum.prague.fork_types import Address
from ethereum.prague.state import State, finalize_state
from ethereum.crypto.hash import Hash32
from mpt.types import NodeStore
from legacy.utils.dict import dict_squash
from op_stack.state_authentication import authenticate_state, lookup

func read{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*, node_store: NodeStore,
}(root: Hash32, secure_key: Hash32) -> Bytes {
    alloc_locals;
    let (keccak_ptr) = alloc();
    local start: felt* = keccak_ptr;
    let result = lookup(root, secure_key);
    local result: Bytes = result;
    local keccak_ptr: felt* = keccak_ptr;
    local node_store: NodeStore = node_store;
    dict_squash(cast(node_store.value.dict_ptr_start, DictAccess*),
                cast(node_store.value.dict_ptr, DictAccess*));
    finalize_keccak(start, keccak_ptr);
    return result;
}

func authenticate{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
    poseidon_ptr: PoseidonBuiltin*, node_store: NodeStore, state: State,
}(root: Hash32) {
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
    let (keccak_ptr) = alloc();
    local start: felt* = keccak_ptr;
    authenticate_state(root, addresses, keys, n);
    local state: State = state;
    local keccak_ptr: felt* = keccak_ptr;
    local node_store: NodeStore = node_store;
    dict_squash(cast(node_store.value.dict_ptr_start, DictAccess*),
                cast(node_store.value.dict_ptr, DictAccess*));
    finalize_state{state=state}();
    finalize_keccak(start, keccak_ptr);
    return ();
}
