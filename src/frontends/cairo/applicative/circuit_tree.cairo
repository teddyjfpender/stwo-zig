// Reconstruct the ordered public output of a recursive circuit tree.
//
// The node hints supply a witness. Cairo checks each selected circuit hash
// against the pinned config, hashes every leaf preimage, and hashes every
// multiverifier pair in the same order as circuit_multiverifier. The caller
// compares the resulting root to the output of stwo_circuit_verifier and
// compares the revealed task outputs to the Starknet aggregator's input.

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_blake2s.blake2s import (
    blake_with_opcode,
    encode_felt252s_to_u32s,
)
from starkware.cairo.common.math import assert_nn_le
from starkware.cairo.common.memcpy import memcpy

const N_DIGEST_WORDS = 8;

struct CircuitUnpackerConfig {
    n_supported_circuit_hashes: felt,
    supported_circuit_hashes: felt*,
}

// Returns the circuit hash and output digest as pointers to eight u32 words,
// plus the end of the ordered simple-bootloader task output and leaf count.
func unpack_circuit_tree{range_check_ptr}(
    config: CircuitUnpackerConfig*, tasks_output_ptr: felt*
) -> (circuit_hash: felt*, digest: felt*, tasks_output_end: felt*, n_leaves: felt) {
    alloc_locals;
    local circuit_hash_index;
    %{ CIRCUIT_UNPACK_SET_CIRCUIT_HASH_INDEX %}
    assert_nn_le(circuit_hash_index, config.n_supported_circuit_hashes - 1);
    let circuit_hash = config.supported_circuit_hashes + circuit_hash_index * N_DIGEST_WORDS;

    local is_leaf;
    %{ CIRCUIT_UNPACK_SET_IS_LEAF %}
    if (is_leaf != 0) {
        local preimage: felt*;
        local preimage_len;
        %{ CIRCUIT_UNPACK_SET_LEAF_DATA %}
        let (local encoded: felt*) = alloc();
        let encoded_len = encode_felt252s_to_u32s(
            packed_values_len=preimage_len, packed_values=preimage, unpacked_u32s=encoded
        );
        let (local digest: felt*) = alloc();
        blake_with_opcode(len=encoded_len, data=encoded, out=digest);
        assert tasks_output_ptr[0] = preimage_len + 1;
        memcpy(dst=tasks_output_ptr + 1, src=preimage, len=preimage_len);
        return (
            circuit_hash=circuit_hash,
            digest=digest,
            tasks_output_end=tasks_output_ptr + 1 + preimage_len,
            n_leaves=1,
        );
    }

    %{ CIRCUIT_UNPACK_ENTER_SUBTASK_0 %}
    let (left_hash, left_digest, left_end, left_leaves) = unpack_circuit_tree(
        config=config, tasks_output_ptr=tasks_output_ptr
    );
    %{ CIRCUIT_UNPACK_EXIT_SCOPE %}

    local is_self_fold;
    %{ CIRCUIT_UNPACK_SET_IS_SELF_FOLD %}
    if (is_self_fold != 0) {
        let (local pair: felt*) = alloc();
        memcpy(dst=pair, src=left_hash, len=N_DIGEST_WORDS);
        memcpy(dst=pair + 8, src=left_digest, len=N_DIGEST_WORDS);
        memcpy(dst=pair + 16, src=left_hash, len=N_DIGEST_WORDS);
        memcpy(dst=pair + 24, src=left_digest, len=N_DIGEST_WORDS);
        let (local digest: felt*) = alloc();
        blake_with_opcode(len=32, data=pair, out=digest);
        return (
            circuit_hash=circuit_hash,
            digest=digest,
            tasks_output_end=left_end,
            n_leaves=left_leaves,
        );
    }

    %{ CIRCUIT_UNPACK_ENTER_SUBTASK_1 %}
    let (right_hash, right_digest, right_end, right_leaves) = unpack_circuit_tree(
        config=config, tasks_output_ptr=left_end
    );
    %{ CIRCUIT_UNPACK_EXIT_SCOPE %}

    let (local pair: felt*) = alloc();
    memcpy(dst=pair, src=left_hash, len=N_DIGEST_WORDS);
    memcpy(dst=pair + 8, src=left_digest, len=N_DIGEST_WORDS);
    memcpy(dst=pair + 16, src=right_hash, len=N_DIGEST_WORDS);
    memcpy(dst=pair + 24, src=right_digest, len=N_DIGEST_WORDS);
    let (local digest: felt*) = alloc();
    blake_with_opcode(len=32, data=pair, out=digest);
    return (
        circuit_hash=circuit_hash,
        digest=digest,
        tasks_output_end=right_end,
        n_leaves=left_leaves + right_leaves,
    );
}
