from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from ethereum_types.bytes import Bytes, BytesStruct
from ethereum_types.numeric import Uint
from ethereum.prague.blocks import TupleLog
from ethereum.prague.bloom import logs_bloom
from ethereum_rlp.rlp import Extended, ExtendedImpl, SequenceExtended, SequenceExtendedStruct, encode, decode, encode_bloom, encode_tuple_log, encode_receipt, encode_uint
from ethereum.prague.vm import BlockOutput, BlockOutputStruct
from ethereum.prague.trie import trie_get_TrieBytesOptionalUnionBytesReceipt

func deposit_receipt{
    range_check_ptr, bitwise_ptr: BitwiseBuiltin*, keccak_ptr: felt*,
}(success: felt, cumulative: Uint, logs: TupleLog, nonce: Uint) -> Bytes {
    alloc_locals;
    let (fields: Extended*) = alloc();
    let success_field = integer_field(Uint(success));
    assert fields[0] = success_field;
    let cumulative_field = integer_field(cumulative);
    assert fields[1] = cumulative_field;
    let bloom = logs_bloom(logs);
    let encoded_bloom = encode_bloom(bloom);
    let decoded_bloom = decode(encoded_bloom);
    let bloom_field = ExtendedImpl.from_simple(decoded_bloom);
    assert fields[2] = bloom_field;
    let encoded_logs = encode_tuple_log(logs);
    let decoded_logs = decode(encoded_logs);
    let logs_field = ExtendedImpl.from_simple(decoded_logs);
    assert fields[3] = logs_field;
    let nonce_field = integer_field(nonce);
    assert fields[4] = nonce_field;
    let version_field = integer_field(Uint(1));
    assert fields[5] = version_field;
    tempvar sequence = SequenceExtended(new SequenceExtendedStruct(fields, 6));
    let extended = ExtendedImpl.sequence(sequence);
    let encoded = encode(extended);
    let (data) = alloc();
    assert data[0] = 0x7e;
    memcpy(data + 1, encoded.value.data, encoded.value.len);
    tempvar result = Bytes(new BytesStruct(data, encoded.value.len + 1));
    return result;
}

func sequencer_receipt{range_check_ptr, block_output: BlockOutput}(index: Uint) -> Bytes {
    alloc_locals;
    let key = encode_uint(index);
    let receipts = block_output.value.receipts_trie;
    let receipt = trie_get_TrieBytesOptionalUnionBytesReceipt{trie=receipts}(key);
    tempvar block_output = BlockOutput(new BlockOutputStruct(
        block_output.value.block_gas_used, block_output.value.transactions_trie, receipts,
        block_output.value.receipt_keys, block_output.value.block_logs, block_output.value.withdrawals_trie,
        block_output.value.blob_gas_used, block_output.value.requests));
    if (cast(receipt.value.bytes.value, felt) != 0) {
        return receipt.value.bytes;
    }
    let encoded = encode_receipt(receipt.value.receipt);
    return encoded;
}

func integer_field{range_check_ptr}(value: Uint) -> Extended {
    alloc_locals;
    let encoded = encode_uint(value);
    let decoded = decode(encoded);
    local range_check_ptr = range_check_ptr;
    let field = ExtendedImpl.from_simple(decoded);
    return field;
}
