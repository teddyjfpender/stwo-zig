%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak
from starkware.cairo.common.cairo_builtins import (
    BitwiseBuiltin, PoseidonBuiltin, ModBuiltin, HashBuiltin, SignatureBuiltin, EcOpBuiltin
)
from ethereum_types.bytes import Bytes, TupleBytes32
from ethereum.prague.fork_types import Address
from ethereum.prague.state import finalize_state
from ethereum.prague.vm.env_impl import BlockEnvironment, BlockEnvImpl
from ethereum.crypto.hash import keccak256
from op_stack.deposit_types import decode_deposit
from op_stack.deposit_execution import execute_deposit
from op_stack.state_view import state_view, detach_account_snapshot, environment_view
from op_stack.access_coverage import assert_access_coverage

func main{
    output_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*, bitwise_ptr: BitwiseBuiltin*, ec_op_ptr: EcOpBuiltin*,
    keccak_ptr: felt*, poseidon_ptr: PoseidonBuiltin*, range_check96_ptr: felt*,
    add_mod_ptr: ModBuiltin*, mul_mod_ptr: ModBuiltin*,
}() {
    alloc_locals;
    local block_env: BlockEnvironment;
    local raw: Bytes;
    local addresses: Address*;
    local storage_keys: TupleBytes32*;
    local n;
    %{
        from typing import Tuple
        from mpt.ethereum_tries import PreState
        from ethereum.prague.vm import BlockEnvironment
        from ethereum.prague.fork_types import Address
        from ethereum_types.bytes import Bytes, Bytes32
        from ethereum_types.numeric import U64, U256, Uint
        state = PreState.from_data({"extra": {"preState": program_input["pre_state"], "accessList": program_input["access_list"]}})
        e = program_input["environment"]
        environment = BlockEnvironment(
            chain_id=U64(e["chain_id"]), state=state, block_gas_limit=Uint(e["gas_limit"]),
            block_hashes=[Bytes32.fromhex(x[2:]) for x in e["block_hashes"]],
            coinbase=Address.fromhex(e["coinbase"][2:]), number=Uint(e["number"]),
            base_fee_per_gas=Uint(e["base_fee"]), time=U256(e["timestamp"]),
            prev_randao=Bytes32.fromhex(e["prev_randao"][2:]), excess_blob_gas=U64(0),
            parent_beacon_block_root=Bytes32.fromhex(e["parent_beacon_block_root"][2:]))
        ids.block_env = gen_arg(BlockEnvironment, environment)
        ids.raw = gen_arg(Bytes, Bytes.fromhex(program_input["transaction"][2:]))
        ids.addresses = segments.gen_arg([int.from_bytes(bytes.fromhex(a["address"][2:]), "little") for a in program_input["access_list"]])
        ids.storage_keys = segments.gen_arg([gen_arg(Tuple[Bytes32, ...], tuple(Bytes32.fromhex(k[2:]) for k in a["storageKeys"])) for a in program_input["access_list"]])
        ids.n = len(program_input["access_list"])
        program_input["codehash_to_code"] = {(int.from_bytes(bytes.fromhex(h[2:])[:16], "little"), int.from_bytes(bytes.fromhex(h[2:])[16:], "little")): Bytes.fromhex(c[2:]) for h, c in program_input["codes"].items()}
    %}
    let builtin_keccak_ptr = keccak_ptr;
    let (keccak_ptr) = alloc();
    let start = keccak_ptr;
    let state = detach_account_snapshot(block_env.value.state);
    let before = state_view{state=state}(addresses, storage_keys, n, 1);
    BlockEnvImpl.set_state{block_env=block_env}(state);
    let environment_hash = environment_view(block_env);
    let tx_hash = keccak256(raw);
    let deposit = decode_deposit(raw);
    let (used, success, nonce) = execute_deposit{block_env=block_env}(deposit, tx_hash);
    let state = block_env.value.state;
    let after = state_view{state=state}(addresses, storage_keys, n, 0);
    finalize_state{state=state}();
    assert_access_coverage(state, addresses, storage_keys, n);
    assert [output_ptr] = block_env.value.chain_id.value;
    assert [output_ptr + 1] = block_env.value.number.value;
    assert [output_ptr + 2] = tx_hash.value.low;
    assert [output_ptr + 3] = tx_hash.value.high;
    assert [output_ptr + 4] = deposit.source_hash.value.low;
    assert [output_ptr + 5] = deposit.source_hash.value.high;
    assert [output_ptr + 6] = before.value.low;
    assert [output_ptr + 7] = before.value.high;
    assert [output_ptr + 8] = after.value.low;
    assert [output_ptr + 9] = after.value.high;
    assert [output_ptr + 10] = used;
    assert [output_ptr + 11] = success;
    assert [output_ptr + 12] = nonce.value;
    assert [output_ptr + 13] = environment_hash.value.low;
    assert [output_ptr + 14] = environment_hash.value.high;
    let output_ptr = output_ptr + 15;
    finalize_keccak(start, keccak_ptr);
    let keccak_ptr = builtin_keccak_ptr;
    return ();
}
