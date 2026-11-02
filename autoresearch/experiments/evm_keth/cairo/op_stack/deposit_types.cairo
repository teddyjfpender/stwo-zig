// Post-Regolith deposit envelope. Authorization belongs to L1 derivation.
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, assert_not_zero
from ethereum_types.bytes import Bytes, BytesStruct, Bytes32
from ethereum_types.numeric import U256, Uint
from ethereum.prague.fork_types import Address
from ethereum.prague.transactions_types import To
from ethereum_rlp.rlp import decode, decode_item_length, _decode_to
from ethereum.utils.numeric import U256_from_be_bytes, U64_from_be_bytes, Bytes32_from_be_bytes
from op_stack.fastlz import assert_bytes

struct Deposit {
    source_hash: Bytes32,
    sender: Address,
    to: To,
    mint: U256,
    value: U256,
    gas: Uint,
    data: Bytes,
}

func canonical_integer{range_check_ptr}(value: Bytes) {
    if (value.value.len == 0) {
        return ();
    }
    assert_not_zero(value.value.data[0]);
    return ();
}

func decode_deposit{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(raw: Bytes) -> Deposit* {
    alloc_locals;
    assert_nn_le(raw.value.len, 0xffffffff);
    assert_not_zero(raw.value.len);
    assert_bytes(raw.value.data, raw.value.len);
    assert raw.value.data[0] = 0x7e;
    tempvar encoded = Bytes(new BytesStruct(raw.value.data + 1, raw.value.len - 1));
    let length = decode_item_length(encoded);
    assert length = encoded.value.len;
    let decoded = decode(encoded);
    assert cast(decoded.value.bytes.value, felt) = 0;
    let items = decoded.value.sequence.value.data;
    assert decoded.value.sequence.value.len = 8;
    assert cast(items[0].value.sequence.value, felt) = 0;
    assert cast(items[1].value.sequence.value, felt) = 0;
    assert cast(items[2].value.sequence.value, felt) = 0;
    assert cast(items[3].value.sequence.value, felt) = 0;
    assert cast(items[4].value.sequence.value, felt) = 0;
    assert cast(items[5].value.sequence.value, felt) = 0;
    assert cast(items[6].value.sequence.value, felt) = 0;
    assert cast(items[7].value.sequence.value, felt) = 0;
    assert items[0].value.bytes.value.len = 32;
    assert items[1].value.bytes.value.len = 20;
    let source_hash = Bytes32_from_be_bytes(items[0].value.bytes);
    let sender_to = _decode_to(items[1].value.bytes);
    if (items[2].value.bytes.value.len != 0) {
        assert items[2].value.bytes.value.len = 20;
    }
    let to = _decode_to(items[2].value.bytes);
    canonical_integer(items[3].value.bytes);
    canonical_integer(items[4].value.bytes);
    canonical_integer(items[5].value.bytes);
    let mint = U256_from_be_bytes(items[3].value.bytes);
    let value = U256_from_be_bytes(items[4].value.bytes);
    let gas = U64_from_be_bytes(items[5].value.bytes);
    // System deposits are invalid from Regolith onward; false RLP is empty.
    assert items[6].value.bytes.value.len = 0;
    return new Deposit(source_hash, [sender_to.value.address], to, mint, value, Uint(gas.value), items[7].value.bytes);
}

// Small standard-type return surface for differential codec tests.
func deposit_fields{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(raw: Bytes) -> (
    Bytes32, Address, U256, U256, Uint, Bytes
) {
    let tx = decode_deposit(raw);
    return (tx.source_hash, tx.sender, tx.mint, tx.value, tx.gas, tx.data);
}
