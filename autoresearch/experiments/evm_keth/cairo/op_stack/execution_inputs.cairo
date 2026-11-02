from ethereum.prague.blocks import Header, UnionBytesLegacyTransaction
from ethereum.prague.vm.env_impl import BlockEnvironment
from ethereum_types.bytes import Bytes, TupleBytes32
from ethereum_types.numeric import Uint
from ethereum.prague.fork_types import Address
from ethereum.crypto.hash import Hash32
from mpt.types import NodeStore, MappingBytes32Address, MappingBytes32Bytes32

struct Input {
    env: BlockEnvironment,
    header: Header,
    history: Header*,
    history_len: felt,
    action: felt,
    before: Hash32,
    after: Hash32,
    raw: Bytes,
    encoded: UnionBytesLegacyTransaction,
    index: Uint,
    previous_gas: Uint,
    addresses: Address*,
    keys: TupleBytes32*,
    n: felt,
    nodes: NodeStore,
    address_preimages: MappingBytes32Address,
    storage_preimages: MappingBytes32Bytes32,
}

func load_input() -> Input* {
    alloc_locals;
    local env: BlockEnvironment;
    local header: Header;
    local history: Header*;
    local history_len;
    local action;
    local before: Hash32;
    local after: Hash32;
    local raw: Bytes;
    local encoded: UnionBytesLegacyTransaction;
    local index: Uint;
    local previous_gas: Uint;
    local addresses: Address*;
    local keys: TupleBytes32*;
    local n;
    local nodes: NodeStore;
    local address_preimages: MappingBytes32Address;
    local storage_preimages: MappingBytes32Bytes32;
    %{
        from typing import Mapping, Tuple, Union
        from eth_hash.auto import keccak
        from ethereum.crypto.hash import Hash32
        from ethereum.prague.blocks import Header
        from ethereum.prague.vm import BlockEnvironment
        from ethereum.prague.fork_types import Address
        from ethereum.prague.transactions import LegacyTransaction
        from ethereum_rlp.rlp import decode_to
        from ethereum_types.bytes import Bytes, Bytes32
        from ethereum_types.numeric import Uint
        from utils.fixture_loader import LoadKethFixture
        from autoresearch.experiments.evm_keth.op_vm_input import environment
        loader = LoadKethFixture("Prague", "prague")
        value = program_input
        ids.env = gen_arg(BlockEnvironment, environment(value))
        ids.header = gen_arg(Header, loader.json_to_header(value["header"]))
        ids.history = segments.gen_arg([gen_arg(Header, loader.json_to_header(h)) for h in value["headers"]])
        ids.history_len = len(value["headers"])
        ids.action = value["action"]
        ids.before = gen_arg(Hash32, Hash32.fromhex(value["before_root"][2:]))
        ids.after = gen_arg(Hash32, Hash32.fromhex(value["after_root"][2:]))
        raw = Bytes.fromhex(value["transaction"][2:])
        ids.raw = gen_arg(Bytes, raw)
        encoded = raw if not raw or raw[0] < 0x80 else decode_to(LegacyTransaction, raw)
        ids.encoded = gen_arg(Union[Bytes, LegacyTransaction], encoded)
        ids.index = gen_arg(Uint, Uint(value["transaction_index"]))
        ids.previous_gas = gen_arg(Uint, Uint(value["previous_gas"]))
        accesses = value["access_list"]
        ids.addresses = segments.gen_arg([int.from_bytes(bytes.fromhex(a["address"][2:]), "little") for a in accesses])
        ids.keys = segments.gen_arg([gen_arg(Tuple[Bytes32, ...], tuple(Bytes32.fromhex(k[2:]) for k in a["storageKeys"])) for a in accesses])
        ids.n = len(accesses)
        nodes = {Hash32(keccak(bytes.fromhex(raw[2:]))): Bytes.fromhex(raw[2:]) for raw in value["proof_nodes"]}
        ids.nodes = gen_arg(Mapping[Hash32, Bytes], nodes)
        ids.address_preimages = gen_arg(Mapping[Hash32, Address], {Hash32(keccak(bytes.fromhex(a["address"][2:]))): Address.fromhex(a["address"][2:]) for a in accesses})
        ids.storage_preimages = gen_arg(Mapping[Hash32, Bytes32], {Hash32(keccak(bytes.fromhex(k[2:]))): Bytes32.fromhex(k[2:]) for a in accesses for k in a["storageKeys"]})
        program_input["codehash_to_code"] = {(int.from_bytes(bytes.fromhex(h[2:])[:16], "little"), int.from_bytes(bytes.fromhex(h[2:])[16:], "little")): Bytes.fromhex(c[2:]) for h,c in value["codes"].items()}
    %}
    tempvar result = new Input(env, header, history, history_len, action, before, after, raw,
        encoded, index, previous_gas, addresses, keys, n, nodes, address_preimages, storage_preimages);
    return result;
}
