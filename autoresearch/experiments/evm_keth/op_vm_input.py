"""Witness serialization helpers; Cairo establishes the execution statement."""
from __future__ import annotations

import keth_types.patches
from ethereum.prague.vm import BlockEnvironment
from ethereum.prague.fork_types import Address
from ethereum_types.bytes import Bytes32
from ethereum_types.numeric import U64, U256, Uint
from mpt.ethereum_tries import PreState


def environment(value):
    state = PreState.from_data({'extra': {'preState': value['pre_state'], 'accessList': value['access_list']}})
    e = value['environment']
    return BlockEnvironment(chain_id=U64(e['chain_id']), state=state, block_gas_limit=Uint(e['gas_limit']),
        block_hashes=[Bytes32.fromhex(h[2:]) for h in e['block_hashes']],
        coinbase=Address.fromhex(e['coinbase'][2:]), number=Uint(e['number']), base_fee_per_gas=Uint(e['base_fee']),
        time=U256(e['timestamp']), prev_randao=Bytes32.fromhex(e['prev_randao'][2:]), excess_blob_gas=U64(0),
        parent_beacon_block_root=Bytes32.fromhex(e['parent_beacon_block_root'][2:]))
