from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, PoseidonBuiltin, ModBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from ethereum_types.bytes import Bytes, TupleBytes32
from ethereum_types.numeric import Uint
from ethereum.prague.blocks import UnionBytesLegacyTransaction
from ethereum.prague.fork_types import Address
from ethereum.prague.vm.env_impl import BlockEnvironment
from ethereum.crypto.hash import Hash32
from mpt.types import NodeStore, MappingBytes32Address, MappingBytes32Bytes32
from op_stack.state_bound_execution import transition

func run{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr: felt*, add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
    block_env: BlockEnvironment,
}(action: felt, parent_hash: Hash32, before: Hash32, after: Hash32,
  raw: Bytes, encoded: UnionBytesLegacyTransaction, index: Uint, previous_gas: Uint,
  node_store: NodeStore, address_preimages: MappingBytes32Address,
  storage_key_preimages: MappingBytes32Bytes32) -> (Hash32, felt, Hash32, felt) {
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
    with node_store, address_preimages, storage_key_preimages {
    let (tx_hash, used, receipt_hash, footprint) = transition(
        action, parent_hash, before, after, raw, encoded, index, previous_gas, addresses, keys, n);
    local tx_hash: Hash32 = tx_hash;
    local used = used;
    local receipt_hash: Hash32 = receipt_hash;
    local footprint = footprint;
    local block_env: BlockEnvironment = block_env;
    local node_store: NodeStore = node_store;
    local address_preimages: MappingBytes32Address = address_preimages;
    local storage_key_preimages: MappingBytes32Bytes32 = storage_key_preimages;
    local range_check96_ptr: felt* = range_check96_ptr;
    local add_mod_ptr: ModBuiltin* = add_mod_ptr;
    local mul_mod_ptr: ModBuiltin* = mul_mod_ptr;
    finalize_keccak(start, keccak_ptr);
    return (tx_hash, used, receipt_hash, footprint);
    }
}
