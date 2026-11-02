// OP Mainnet post-Karst execution context and authenticated BLOCKHASH history.
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from starkware.cairo.common.math_cmp import is_le_felt
from ethereum.prague.blocks import Header
from ethereum.prague.vm.env_impl import BlockEnvironment
from ethereum.crypto.hash import Hash32, keccak256
from ethereum_rlp.rlp import encode_header
from ethereum.utils.numeric import divmod, min, max

func header_hash{range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*}(header: Header) -> Hash32 {
    let encoded = encode_header(header);
    let result = keccak256(encoded);
    return result;
}

func read_be{range_check_ptr}(data: felt*, n: felt, value: felt) -> felt {
    if (n == 0) {
        return value;
    }
    assert_nn_le(data[0], 255);
    return read_be(data + 1, n - 1, value * 256 + data[0]);
}

func fee_parameters{range_check_ptr}(header: Header) -> (felt, felt, felt) {
    alloc_locals;
    assert header.value.extra_data.value.len = 17;
    assert header.value.extra_data.value.data[0] = 1;
    let denominator = read_be(header.value.extra_data.value.data + 1, 4, 0);
    local denominator = denominator;
    let elasticity = read_be(header.value.extra_data.value.data + 5, 4, 0);
    local elasticity = elasticity;
    let minimum = read_be(header.value.extra_data.value.data + 9, 8, 0);
    assert_not_zero(denominator);
    assert_not_zero(elasticity);
    return (denominator, elasticity, minimum);
}

func expected_base_fee{range_check_ptr}(parent: Header) -> felt {
    alloc_locals;
    assert_nn_le(parent.value.base_fee_per_gas.value, 2 ** 128 - 1);
    assert_nn_le(parent.value.gas_limit.value, 2 ** 63 - 1);
    assert_nn_le(parent.value.gas_used.value, parent.value.gas_limit.value);
    assert_nn_le(parent.value.blob_gas_used.value, parent.value.gas_limit.value);
    let (denominator, elasticity, minimum) = fee_parameters(parent);
    local denominator = denominator;
    local minimum = minimum;
    let (target, _) = divmod(parent.value.gas_limit.value, elasticity);
    local target = target;
    assert_not_zero(target);
    let metered = max(parent.value.gas_used.value, parent.value.blob_gas_used.value);
    local calculated;
    if (metered == target) {
        assert calculated = parent.value.base_fee_per_gas.value;
        tempvar range_check_ptr = range_check_ptr;
    } else {
        let above = is_le_felt(target, metered);
        if (above != 0) {
            let (change, _) = divmod(parent.value.base_fee_per_gas.value * (metered - target), target);
            let (change, _) = divmod(change, denominator);
            let change = max(change, 1);
            assert calculated = parent.value.base_fee_per_gas.value + change;
            tempvar range_check_ptr = range_check_ptr;
        } else {
            let (change, _) = divmod(parent.value.base_fee_per_gas.value * (target - metered), target);
            let (change, _) = divmod(change, denominator);
            assert_nn_le(change, parent.value.base_fee_per_gas.value);
            assert calculated = parent.value.base_fee_per_gas.value - change;
            tempvar range_check_ptr = range_check_ptr;
        }
        let range_check_ptr = [ap - 1];
        tempvar range_check_ptr = range_check_ptr;
    }
    let range_check_ptr = [ap - 1];
    let result = max(calculated, minimum);
    return result;
}

func ancestors{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
}(env: BlockEnvironment, headers: Header*, n: felt, index: felt) {
    alloc_locals;
    if (index == n) {
        return ();
    }
    let header = headers[index];
    assert header.value.number.value = env.value.number.value - n + index;
    let hash = header_hash(header);
    local range_check_ptr = range_check_ptr;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    local keccak_ptr: felt* = keccak_ptr;
    assert [hash.value] = [env.value.block_hashes.value.data[index].value];
    if (index != 0) {
        assert [header.value.parent_hash.value] = [env.value.block_hashes.value.data[index - 1].value];
    }
    return ancestors(env, headers, n, index + 1);
}

func bind_environment{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
}(env: BlockEnvironment, header: Header, history: Header*, n: felt) -> (Hash32, Hash32) {
    alloc_locals;
    assert_nn_le(n - 1, 255);
    assert env.value.chain_id.value = 10;
    assert env.value.block_hashes.value.len = n;
    assert env.value.number.value = header.value.number.value;
    assert env.value.block_gas_limit.value = header.value.gas_limit.value;
    assert env.value.base_fee_per_gas.value = header.value.base_fee_per_gas.value;
    assert [env.value.time.value] = [header.value.timestamp.value];
    assert [env.value.prev_randao.value] = [header.value.prev_randao.value];
    assert env.value.coinbase.value = header.value.coinbase.value;
    assert [env.value.parent_beacon_block_root.value] = [header.value.parent_beacon_block_root.value];
    assert env.value.excess_blob_gas.value = header.value.excess_blob_gas.value;
    assert_nn_le(header.value.number.value, 2 ** 64 - 1);
    assert_nn_le(header.value.timestamp.value.low, 2 ** 64 - 1);
    assert header.value.timestamp.value.high = 0;
    assert_nn_le(1783526401, header.value.timestamp.value.low);
    assert_nn_le(header.value.gas_limit.value, 2 ** 63 - 1);
    assert_nn_le(header.value.gas_used.value, header.value.gas_limit.value);
    assert_nn_le(header.value.blob_gas_used.value, header.value.gas_limit.value);
    assert header.value.excess_blob_gas.value = 0;
    assert header.value.difficulty.value = 0;
    assert header.value.nonce.value = 0;
    assert header.value.ommers_hash.value.low = 0x1ad4ccb667b585ab7a5dc7dee84dcc1d;
    assert header.value.ommers_hash.value.high = 0x4793d440fd42a1f013748a941b4512d3;
    assert header.value.requests_hash.value.low = 0x24b96f99c8f4fb9a141cfc9842c4b0e3;
    assert header.value.requests_hash.value.high = 0x55b852781b9995a44c939b64e441ae27;
    fee_parameters(header);
    ancestors(env, history, n, 0);
    let parent = history[n - 1];
    assert [header.value.parent_hash.value] = [env.value.block_hashes.value.data[n - 1].value];
    assert parent.value.timestamp.value.high = 0;
    assert_nn_le(1783526401, parent.value.timestamp.value.low);
    assert_nn_le(parent.value.timestamp.value.low + 1, header.value.timestamp.value.low);
    let base_fee = expected_base_fee(parent);
    assert header.value.base_fee_per_gas.value = base_fee;
    let hash = header_hash(header);
    return (hash, parent.value.state_root);
}
