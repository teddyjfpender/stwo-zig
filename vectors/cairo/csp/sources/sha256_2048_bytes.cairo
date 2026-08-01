// Reference https://github.com/cartridge-gg/cairo-sha256
// Refer the above link for usage

%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.math import assert_nn_le, unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le_felt
from starkware.cairo.common.memcpy import memcpy
from starkware.cairo.common.memset import memset
from starkware.cairo.common.pow import pow

from starkware.cairo.common.cairo_sha256.sha256_utils import (
    compute_message_schedule,
    sha2_compress,
    get_round_constants,
)

const BLOCK_SIZE = 7;
const SHA256_INPUT_CHUNK_SIZE_FELTS = 16;
const SHA256_INPUT_CHUNK_SIZE_BYTES = 64;
const SHA256_STATE_SIZE_FELTS = 8;
// Each instance consists of 16 words of message, 8 words for the input state and 8 words
// for the output state.
const SHA256_INSTANCE_SIZE = SHA256_INPUT_CHUNK_SIZE_FELTS + 2 * SHA256_STATE_SIZE_FELTS;

// Computes SHA256 of 'input'. Inputs of arbitrary length are supported.
// To use this function, split the input into (up to) 14 words of 32 bits (big endian).
// For example, to compute sha256('Hello world'), use:
//   input = [1214606444, 1864398703, 1919706112]
// where:
//   1214606444 == int.from_bytes(b'Hell', 'big')
//   1864398703 == int.from_bytes(b'o wo', 'big')
//   1919706112 == int.from_bytes(b'rld\x00', 'big')  # Note the '\x00' padding.
//
// block layout:
// 0 - 15: Message
// 16 - 23: Input State
// 24 - 32: Output
//
// output is an array of 8 32-bit words (big endian).
//
// Note: You must call finalize_sha2() at the end of the program. Otherwise, this function
// is not sound and a malicious prover may return a wrong result.
// Note: the interface of this function may change in the future.
func sha256{range_check_ptr, sha256_ptr: felt*}(data: felt*, n_bytes: felt) -> (output: felt*) {
    alloc_locals;

    // Set the initial input state to IV.
    assert sha256_ptr[16] = 0x6A09E667;
    assert sha256_ptr[17] = 0xBB67AE85;
    assert sha256_ptr[18] = 0x3C6EF372;
    assert sha256_ptr[19] = 0xA54FF53A;
    assert sha256_ptr[20] = 0x510E527F;
    assert sha256_ptr[21] = 0x9B05688C;
    assert sha256_ptr[22] = 0x1F83D9AB;
    assert sha256_ptr[23] = 0x5BE0CD19;

    sha256_inner(data=data, n_bytes=n_bytes, total_bytes=n_bytes);

    // Set `output` to the start of the final state.
    let output = sha256_ptr;
    // Set `sha256_ptr` to the end of the output state.
    let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;
    return (output,);
}

// Computes the sha256 hash of the input chunk from `message` to `message + SHA256_INPUT_CHUNK_SIZE_FELTS`
func _sha256_chunk{range_check_ptr, sha256_start: felt*, state: felt*, output: felt*}() {
    %{
        from starkware.cairo.common.cairo_sha256.sha256_utils import (
            compute_message_schedule, sha2_compress_function)

        _sha256_input_chunk_size_felts = int(ids.SHA256_INPUT_CHUNK_SIZE_FELTS)
        assert 0 <= _sha256_input_chunk_size_felts < 100
        _sha256_state_size_felts = int(ids.SHA256_STATE_SIZE_FELTS)
        assert 0 <= _sha256_state_size_felts < 100
        w = compute_message_schedule(memory.get_range(
            ids.sha256_start, _sha256_input_chunk_size_felts))
        new_state = sha2_compress_function(memory.get_range(ids.state, _sha256_state_size_felts), w)
        segments.write_arg(ids.output, new_state)
    %}
    return ();
}

// Inner loop for sha256. `sha256_ptr` points to the start of the block.
func sha256_inner{range_check_ptr, sha256_ptr: felt*}(
    data: felt*, n_bytes: felt, total_bytes: felt
) {
    alloc_locals;

    let message = sha256_ptr;
    let state = sha256_ptr + SHA256_INPUT_CHUNK_SIZE_FELTS;
    let output = state + SHA256_STATE_SIZE_FELTS;

    let zero_bytes = is_le_felt(n_bytes, 0);
    let zero_total_bytes = is_le_felt(total_bytes, 0);

    // If the previous message block was full we are still missing "1" at the end of the message
    let (_, r_div_by_64) = unsigned_div_rem(total_bytes, 64);
    let missing_bit_one = is_le_felt(r_div_by_64, 0);

    // This works for 0 total bytes too, because zero_chunk will be -1 and, therefore, not 0.
    let zero_chunk = zero_bytes - zero_total_bytes - missing_bit_one;

    let is_last_block = is_le_felt(n_bytes, 55);
    if (is_last_block == 1) {
        _sha256_input(data, n_bytes, SHA256_INPUT_CHUNK_SIZE_FELTS - 2, zero_chunk);
        // Append the original message length at the end of the message block as a 64-bit big-endian integer.
        assert sha256_ptr[0] = 0;
        assert sha256_ptr[1] = total_bytes * 8;
        let sha256_ptr = sha256_ptr + 2;
        _sha256_chunk{sha256_start=message, state=state, output=output}();
        let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;

        return ();
    }

    let (q, r) = unsigned_div_rem(n_bytes, SHA256_INPUT_CHUNK_SIZE_BYTES);
    let is_remainder_block = is_le_felt(q, 0);
    if (is_remainder_block == 1) {
        _sha256_input(data, r, SHA256_INPUT_CHUNK_SIZE_FELTS, 0);
        _sha256_chunk{sha256_start=message, state=state, output=output}();

        let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;
        memcpy(output + SHA256_STATE_SIZE_FELTS + SHA256_INPUT_CHUNK_SIZE_FELTS, output, SHA256_STATE_SIZE_FELTS);
        let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;

        return sha256_inner(data=data, n_bytes=n_bytes - r, total_bytes=total_bytes);
    } else {
        _sha256_input(data, SHA256_INPUT_CHUNK_SIZE_BYTES, SHA256_INPUT_CHUNK_SIZE_FELTS, 0);
        _sha256_chunk{sha256_start=message, state=state, output=output}();

        let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;
        memcpy(output + SHA256_STATE_SIZE_FELTS + SHA256_INPUT_CHUNK_SIZE_FELTS, output, SHA256_STATE_SIZE_FELTS);
        let sha256_ptr = sha256_ptr + SHA256_STATE_SIZE_FELTS;

        return sha256_inner(
            data=data + SHA256_INPUT_CHUNK_SIZE_FELTS,
            n_bytes=n_bytes - SHA256_INPUT_CHUNK_SIZE_BYTES,
            total_bytes=total_bytes,
        );
    }
}

// 1. Encode the input to binary using UTF-8 and append a single '1' to it.
// 2. Prepend that binary to the message block.
func _sha256_input{range_check_ptr, sha256_ptr: felt*}(
    input: felt*, n_bytes: felt, n_words: felt, pad_chunk: felt
) {
    alloc_locals;

    local full_word;
    %{ ids.full_word = int(ids.n_bytes >= 4) %}

    if (full_word != 0) {
        assert sha256_ptr[0] = input[0];
        let sha256_ptr = sha256_ptr + 1;
        return _sha256_input(
            input=input + 1, n_bytes=n_bytes - 4, n_words=n_words - 1, pad_chunk=pad_chunk
        );
    }

    if (n_words == 0) {
        return ();
    }

    if (n_bytes == 0 and pad_chunk == 1) {
        // Add zeros between the encoded message and the length integer so that the message block is a multiple of 512.
        memset(dst=sha256_ptr, value=0, n=n_words);
        let sha256_ptr = sha256_ptr + n_words;
        return ();
    }

    if (n_bytes == 0) {
        // This is the last input word, so we should add a byte '0x80' at the end and fill the rest with zeros.
        assert sha256_ptr[0] = 0x80000000;
        // Add zeros between the encoded message and the length integer so that the message block is a multiple of 512.
        memset(dst=sha256_ptr + 1, value=0, n=n_words - 1);
        let sha256_ptr = sha256_ptr + n_words;
        return ();
    }

    assert_nn_le(n_bytes, 3);
    let (padding) = pow(256, 3 - n_bytes);
    local range_check_ptr = range_check_ptr;

    assert sha256_ptr[0] = input[0] + padding * 0x80;

    memset(dst=sha256_ptr + 1, value=0, n=n_words - 1);
    let sha256_ptr = sha256_ptr + n_words;
    return ();
}

// Handles n blocks of BLOCK_SIZE SHA256 instances.
// Taken from: https://github.com/starkware-libs/cairo-examples/blob/0d88b41bffe3de112d98986b8b0afa795f9d67a0/sha256/sha256.cairo#L102
func _finalize_sha256_inner{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    sha256_ptr: felt*, n: felt, round_constants: felt*
) {
    if (n == 0) {
        return ();
    }

    alloc_locals;

    local MAX_VALUE = 2 ** 32 - 1;

    let sha256_start = sha256_ptr;

    let (local message_start: felt*) = alloc();
    let (local input_state_start: felt*) = alloc();

    // Handle message.

    tempvar message = message_start;
    tempvar sha256_ptr = sha256_ptr;
    tempvar range_check_ptr = range_check_ptr;
    tempvar m = SHA256_INPUT_CHUNK_SIZE_FELTS;

    message_loop:
    tempvar x0 = sha256_ptr[0 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 0] = x0;
    assert [range_check_ptr + 1] = MAX_VALUE - x0;
    tempvar x1 = sha256_ptr[1 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 2] = x1;
    assert [range_check_ptr + 3] = MAX_VALUE - x1;
    tempvar x2 = sha256_ptr[2 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 4] = x2;
    assert [range_check_ptr + 5] = MAX_VALUE - x2;
    tempvar x3 = sha256_ptr[3 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 6] = x3;
    assert [range_check_ptr + 7] = MAX_VALUE - x3;
    tempvar x4 = sha256_ptr[4 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 8] = x4;
    assert [range_check_ptr + 9] = MAX_VALUE - x4;
    tempvar x5 = sha256_ptr[5 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 10] = x5;
    assert [range_check_ptr + 11] = MAX_VALUE - x5;
    tempvar x6 = sha256_ptr[6 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 12] = x6;
    assert [range_check_ptr + 13] = MAX_VALUE - x6;
    assert message[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6;

    tempvar message = message + 1;
    tempvar sha256_ptr = sha256_ptr + 1;
    tempvar range_check_ptr = range_check_ptr + 14;
    tempvar m = m - 1;
    jmp message_loop if m != 0;

    // Handle input state.

    tempvar input_state = input_state_start;
    tempvar sha256_ptr = sha256_ptr;
    tempvar range_check_ptr = range_check_ptr;
    tempvar m = SHA256_STATE_SIZE_FELTS;

    input_state_loop:
    tempvar x0 = sha256_ptr[0 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 0] = x0;
    assert [range_check_ptr + 1] = MAX_VALUE - x0;
    tempvar x1 = sha256_ptr[1 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 2] = x1;
    assert [range_check_ptr + 3] = MAX_VALUE - x1;
    tempvar x2 = sha256_ptr[2 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 4] = x2;
    assert [range_check_ptr + 5] = MAX_VALUE - x2;
    tempvar x3 = sha256_ptr[3 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 6] = x3;
    assert [range_check_ptr + 7] = MAX_VALUE - x3;
    tempvar x4 = sha256_ptr[4 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 8] = x4;
    assert [range_check_ptr + 9] = MAX_VALUE - x4;
    tempvar x5 = sha256_ptr[5 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 10] = x5;
    assert [range_check_ptr + 11] = MAX_VALUE - x5;
    tempvar x6 = sha256_ptr[6 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 12] = x6;
    assert [range_check_ptr + 13] = MAX_VALUE - x6;
    assert input_state[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6;

    tempvar input_state = input_state + 1;
    tempvar sha256_ptr = sha256_ptr + 1;
    tempvar range_check_ptr = range_check_ptr + 14;
    tempvar m = m - 1;
    jmp input_state_loop if m != 0;

    // Run sha256 on the 7 instances.

    local sha256_ptr: felt* = sha256_ptr;
    local range_check_ptr = range_check_ptr;
    compute_message_schedule(message_start);
    let (outputs) = sha2_compress(input_state_start, message_start, round_constants);
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;

    // Handle outputs.

    tempvar outputs = outputs;
    tempvar sha256_ptr = sha256_ptr;
    tempvar range_check_ptr = range_check_ptr;
    tempvar m = SHA256_STATE_SIZE_FELTS;

    output_loop:
    tempvar x0 = sha256_ptr[0 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr] = x0;
    assert [range_check_ptr + 1] = MAX_VALUE - x0;
    tempvar x1 = sha256_ptr[1 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 2] = x1;
    assert [range_check_ptr + 3] = MAX_VALUE - x1;
    tempvar x2 = sha256_ptr[2 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 4] = x2;
    assert [range_check_ptr + 5] = MAX_VALUE - x2;
    tempvar x3 = sha256_ptr[3 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 6] = x3;
    assert [range_check_ptr + 7] = MAX_VALUE - x3;
    tempvar x4 = sha256_ptr[4 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 8] = x4;
    assert [range_check_ptr + 9] = MAX_VALUE - x4;
    tempvar x5 = sha256_ptr[5 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 10] = x5;
    assert [range_check_ptr + 11] = MAX_VALUE - x5;
    tempvar x6 = sha256_ptr[6 * SHA256_INSTANCE_SIZE];
    assert [range_check_ptr + 12] = x6;
    assert [range_check_ptr + 13] = MAX_VALUE - x6;

    assert outputs[0] = x0 + 2 ** 35 * x1 + 2 ** (35 * 2) * x2 + 2 ** (35 * 3) * x3 +
        2 ** (35 * 4) * x4 + 2 ** (35 * 5) * x5 + 2 ** (35 * 6) * x6;

    tempvar outputs = outputs + 1;
    tempvar sha256_ptr = sha256_ptr + 1;
    tempvar range_check_ptr = range_check_ptr + 14;
    tempvar m = m - 1;
    jmp output_loop if m != 0;

    return _finalize_sha256_inner(
        sha256_ptr=sha256_start + SHA256_INSTANCE_SIZE * BLOCK_SIZE,
        n=n - 1,
        round_constants=round_constants,
    );
}

// Verifies that the results of sha256() are valid.
// Taken from: https://github.com/starkware-libs/cairo-examples/blob/0d88b41bffe3de112d98986b8b0afa795f9d67a0/sha256/sha256.cairo#L246
func finalize_sha256{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(
    sha256_ptr_start: felt*, sha256_ptr_end: felt*
) {
    alloc_locals;

    let (__fp__, _) = get_fp_and_pc();

    let round_constants = get_round_constants();

    // We reuse the output state of the previous chunk as input to the next.
    tempvar n = (sha256_ptr_end - sha256_ptr_start) / SHA256_INSTANCE_SIZE;
    if (n == 0) {
        return ();
    }

    %{
        # Add dummy pairs of input and output.
        from starkware.cairo.common.cairo_sha256.sha256_utils import (
            IV, compute_message_schedule, sha2_compress_function)

        _block_size = int(ids.BLOCK_SIZE)
        assert 0 <= _block_size < 20
        _sha256_input_chunk_size_felts = int(ids.SHA256_INPUT_CHUNK_SIZE_FELTS)
        assert 0 <= _sha256_input_chunk_size_felts < 100

        message = [0] * _sha256_input_chunk_size_felts
        w = compute_message_schedule(message)
        output = sha2_compress_function(IV, w)
        padding = (message + IV + output) * (_block_size - 1)
        segments.write_arg(ids.sha256_ptr_end, padding)
    %}

    // Compute the amount of blocks (rounded up).
    let (local q, r) = unsigned_div_rem(n + BLOCK_SIZE - 1, BLOCK_SIZE);
    _finalize_sha256_inner(sha256_ptr_start, n=q, round_constants=round_constants);
    return ();
}

// Exact CSP adaptation.
//
// The 2 KiB logical input is embedded as 512 big-endian u32 words below.  This
// removes host-input hints from the statement: the compiled program hash binds
// every message byte.  The output builtin exposes the eight big-endian SHA-256
// words, and finalize_sha256 remains mandatory so the hinted compression
// results are constrained by the Cairo AIR.
func main{
    output_ptr,
    pedersen_ptr,
    range_check_ptr,
    ecdsa_ptr,
    bitwise_ptr: BitwiseBuiltin*,
    ec_op_ptr,
    keccak_ptr,
    poseidon_ptr,
    range_check96_ptr,
    add_mod_ptr,
    mul_mod_ptr,
}() {
    alloc_locals;

    let (inputs: felt*) = alloc();
    fill_exact_csp_input(input=inputs);

    let (local sha256_ptr: felt*) = alloc();
    let sha256_ptr_start = sha256_ptr;
    let (hash) = sha256{sha256_ptr=sha256_ptr}(inputs, 2048);
    finalize_sha256(sha256_ptr_start=sha256_ptr_start, sha256_ptr_end=sha256_ptr);

    assert [output_ptr] = hash[0];
    assert [output_ptr + 1] = hash[1];
    assert [output_ptr + 2] = hash[2];
    assert [output_ptr + 3] = hash[3];
    assert [output_ptr + 4] = hash[4];
    assert [output_ptr + 5] = hash[5];
    assert [output_ptr + 6] = hash[6];
    assert [output_ptr + 7] = hash[7];
    let output_ptr = output_ptr + 8;

    return ();
}

func fill_exact_csp_input(input: felt*) {
    assert input[0] = 0x11e8bf89;
    assert input[1] = 0x0555d725;
    assert input[2] = 0x2605bbb8;
    assert input[3] = 0x447ad5a8;
    assert input[4] = 0x9f51c719;
    assert input[5] = 0x72690f0f;
    assert input[6] = 0x6b752cb3;
    assert input[7] = 0x76258ce4;
    assert input[8] = 0x58f75304;
    assert input[9] = 0x01f359a3;
    assert input[10] = 0x64336bb7;
    assert input[11] = 0x53cdf751;
    assert input[12] = 0x3dce987f;
    assert input[13] = 0xb8405237;
    assert input[14] = 0xef4e134d;
    assert input[15] = 0x58d5caa3;
    assert input[16] = 0xe12a521d;
    assert input[17] = 0x9efa6af8;
    assert input[18] = 0x233bbdeb;
    assert input[19] = 0xc08e3a5b;
    assert input[20] = 0x14b98561;
    assert input[21] = 0x00b4def2;
    assert input[22] = 0x187497eb;
    assert input[23] = 0x9b183cf6;
    assert input[24] = 0xd21a7f37;
    assert input[25] = 0xff1faa98;
    assert input[26] = 0xc4972037;
    assert input[27] = 0xc87b40d4;
    assert input[28] = 0xee97ef8c;
    assert input[29] = 0x1b895c52;
    assert input[30] = 0x118d1ccf;
    assert input[31] = 0x3e7d3706;
    assert input[32] = 0xf1b4b6c2;
    assert input[33] = 0xa8b53018;
    assert input[34] = 0x9c597739;
    assert input[35] = 0x511ab522;
    assert input[36] = 0x5cd2414a;
    assert input[37] = 0x21e1bae9;
    assert input[38] = 0x38226c0b;
    assert input[39] = 0x7f166b17;
    assert input[40] = 0x47c78744;
    assert input[41] = 0x371e0db1;
    assert input[42] = 0x2f0f1815;
    assert input[43] = 0x8fd366c4;
    assert input[44] = 0x49d7d21c;
    assert input[45] = 0x0ea51ffc;
    assert input[46] = 0x6c681a64;
    assert input[47] = 0xaea7b04f;
    assert input[48] = 0x084aaf17;
    assert input[49] = 0x5bc47bab;
    assert input[50] = 0x31f43c7b;
    assert input[51] = 0x7f4b2e9e;
    assert input[52] = 0x6d804305;
    assert input[53] = 0x872d8ef0;
    assert input[54] = 0x478004ab;
    assert input[55] = 0xceb338ab;
    assert input[56] = 0x009c9e52;
    assert input[57] = 0x94d473d0;
    assert input[58] = 0x6673968c;
    assert input[59] = 0x69d6985d;
    assert input[60] = 0x4bc6cee8;
    assert input[61] = 0x47337f95;
    assert input[62] = 0x83f4c4d2;
    assert input[63] = 0x0d7fa92d;
    assert input[64] = 0x9ad504ef;
    assert input[65] = 0x88194715;
    assert input[66] = 0x412873df;
    assert input[67] = 0x05838208;
    assert input[68] = 0x270c992b;
    assert input[69] = 0x4a75cb04;
    assert input[70] = 0x373697f1;
    assert input[71] = 0x4dfd8981;
    assert input[72] = 0xb801f550;
    assert input[73] = 0xfcde1abe;
    assert input[74] = 0x01c7c404;
    assert input[75] = 0x08ba9257;
    assert input[76] = 0x840688c9;
    assert input[77] = 0xcc1af180;
    assert input[78] = 0x50c7d749;
    assert input[79] = 0x8e06f9f1;
    assert input[80] = 0x61a23c1e;
    assert input[81] = 0x4cf6ad6e;
    assert input[82] = 0x79ab7d22;
    assert input[83] = 0xe452637c;
    assert input[84] = 0xe3e1f9bc;
    assert input[85] = 0xbde28ab3;
    assert input[86] = 0xcdc8e893;
    assert input[87] = 0x81e355a2;
    assert input[88] = 0xe5427596;
    assert input[89] = 0xd35d47d2;
    assert input[90] = 0xd263f442;
    assert input[91] = 0x979a83c3;
    assert input[92] = 0x5b71e80f;
    assert input[93] = 0xf3180e25;
    assert input[94] = 0x48e83ea8;
    assert input[95] = 0x9f863813;
    assert input[96] = 0x435035b8;
    assert input[97] = 0x2eb95902;
    assert input[98] = 0x76e953be;
    assert input[99] = 0xc50187d5;
    assert input[100] = 0x7938244f;
    assert input[101] = 0x25dfc59c;
    assert input[102] = 0xc89a6140;
    assert input[103] = 0x91a11d34;
    assert input[104] = 0xe8d3827e;
    assert input[105] = 0x5575c253;
    assert input[106] = 0x410ebe31;
    assert input[107] = 0xa4fd3c4c;
    assert input[108] = 0xa7c3ee9c;
    assert input[109] = 0x873ebe0a;
    assert input[110] = 0x3d68bde3;
    assert input[111] = 0xadf62996;
    assert input[112] = 0x3ea0f2a9;
    assert input[113] = 0xd0826dbb;
    assert input[114] = 0xd85a0ff0;
    assert input[115] = 0xe034cba8;
    assert input[116] = 0xd8aadafe;
    assert input[117] = 0x17bfd815;
    assert input[118] = 0x13ea5b29;
    assert input[119] = 0xc3037865;
    assert input[120] = 0xc4223350;
    assert input[121] = 0x9a47eeb7;
    assert input[122] = 0xecd3e16e;
    assert input[123] = 0xb7b3c769;
    assert input[124] = 0x500275d1;
    assert input[125] = 0xf3f2e199;
    assert input[126] = 0xde966b6b;
    assert input[127] = 0x81326f1b;
    assert input[128] = 0xce47692b;
    assert input[129] = 0x0ec2d831;
    assert input[130] = 0xcf03e523;
    assert input[131] = 0xefbc49ab;
    assert input[132] = 0x7989235e;
    assert input[133] = 0x16d6b043;
    assert input[134] = 0xdffb4bf6;
    assert input[135] = 0xf9bba735;
    assert input[136] = 0x175acd69;
    assert input[137] = 0x7b8b0523;
    assert input[138] = 0x72cd90e7;
    assert input[139] = 0x74484f90;
    assert input[140] = 0x3aae0054;
    assert input[141] = 0x771fea33;
    assert input[142] = 0x5b3e93cb;
    assert input[143] = 0x31f36bdc;
    assert input[144] = 0x46a8079b;
    assert input[145] = 0x1d382962;
    assert input[146] = 0xb7f16de7;
    assert input[147] = 0xd301e745;
    assert input[148] = 0xd66e64bf;
    assert input[149] = 0x45fc04f0;
    assert input[150] = 0x76568287;
    assert input[151] = 0x0ab87fd4;
    assert input[152] = 0x9d610f1f;
    assert input[153] = 0xfe9d920a;
    assert input[154] = 0x7106ca31;
    assert input[155] = 0xd5516fca;
    assert input[156] = 0x61c332f5;
    assert input[157] = 0x6d072b95;
    assert input[158] = 0x297e20bd;
    assert input[159] = 0x112aca5e;
    assert input[160] = 0xd5d4aef9;
    assert input[161] = 0x469fa7a0;
    assert input[162] = 0xaf935b40;
    assert input[163] = 0x803c123f;
    assert input[164] = 0x9a8b43fa;
    assert input[165] = 0xd6ae8b39;
    assert input[166] = 0xcc452072;
    assert input[167] = 0x3bc0ebb2;
    assert input[168] = 0xe888887f;
    assert input[169] = 0x9fb03be6;
    assert input[170] = 0x7fc88ac1;
    assert input[171] = 0xc6977034;
    assert input[172] = 0x676a40dc;
    assert input[173] = 0xf0aa2d09;
    assert input[174] = 0x181e247a;
    assert input[175] = 0xbf09c313;
    assert input[176] = 0x2937f1c4;
    assert input[177] = 0x8a2e29d5;
    assert input[178] = 0xcdfd41b8;
    assert input[179] = 0xd6227cf3;
    assert input[180] = 0x95a6d7b0;
    assert input[181] = 0x00822505;
    assert input[182] = 0x797ce6ca;
    assert input[183] = 0xeae7b9a1;
    assert input[184] = 0xbdcb7af5;
    assert input[185] = 0xae08e00a;
    assert input[186] = 0x0c9b315f;
    assert input[187] = 0x817a6303;
    assert input[188] = 0x58720d1e;
    assert input[189] = 0x9ce826cd;
    assert input[190] = 0x7d38df77;
    assert input[191] = 0x74bcfa6c;
    assert input[192] = 0xab494d43;
    assert input[193] = 0x7f26a6bf;
    assert input[194] = 0xbc15b23f;
    assert input[195] = 0xa68fc382;
    assert input[196] = 0x040b56d9;
    assert input[197] = 0x357b2547;
    assert input[198] = 0xdc6d142e;
    assert input[199] = 0xa93a1b00;
    assert input[200] = 0xa84019d9;
    assert input[201] = 0x1c5892b9;
    assert input[202] = 0xabfdc220;
    assert input[203] = 0xfcd6c148;
    assert input[204] = 0x9e7b08a6;
    assert input[205] = 0xa11167f9;
    assert input[206] = 0x03044670;
    assert input[207] = 0xd0234603;
    assert input[208] = 0xb7d72401;
    assert input[209] = 0x36440b00;
    assert input[210] = 0xd67fac33;
    assert input[211] = 0x3614e80d;
    assert input[212] = 0xf3696373;
    assert input[213] = 0x2f54721d;
    assert input[214] = 0xa1250c58;
    assert input[215] = 0x47a7b5b4;
    assert input[216] = 0x5afaa625;
    assert input[217] = 0x61d3ac26;
    assert input[218] = 0x01c779cd;
    assert input[219] = 0xc1571056;
    assert input[220] = 0xfa08af80;
    assert input[221] = 0xc403afb7;
    assert input[222] = 0x20fbe850;
    assert input[223] = 0x98d4bf39;
    assert input[224] = 0x77737453;
    assert input[225] = 0xe7f6e4e2;
    assert input[226] = 0xf3a0b490;
    assert input[227] = 0xd3b4bf10;
    assert input[228] = 0x04a299b3;
    assert input[229] = 0x0e5b3d38;
    assert input[230] = 0x2b0f7b41;
    assert input[231] = 0xec952bbf;
    assert input[232] = 0xc42d60bd;
    assert input[233] = 0x228b3448;
    assert input[234] = 0xcf4e2a60;
    assert input[235] = 0x4cbea9c8;
    assert input[236] = 0x426422f3;
    assert input[237] = 0xf06ca9d1;
    assert input[238] = 0x88c7ba78;
    assert input[239] = 0x41e6e061;
    assert input[240] = 0x97da3f95;
    assert input[241] = 0x7ddd6787;
    assert input[242] = 0x7f086a7f;
    assert input[243] = 0x82182b0d;
    assert input[244] = 0x7faaa7ac;
    assert input[245] = 0x8058c679;
    assert input[246] = 0x395fb392;
    assert input[247] = 0xe64eda52;
    assert input[248] = 0x93d3a935;
    assert input[249] = 0x05172c80;
    assert input[250] = 0x34a091ac;
    assert input[251] = 0x84c86aa7;
    assert input[252] = 0x302e3f84;
    assert input[253] = 0x949f49d4;
    assert input[254] = 0x16e864a1;
    assert input[255] = 0xf8ddde2d;
    assert input[256] = 0x17fd5cc0;
    assert input[257] = 0x45daa511;
    assert input[258] = 0x0f4d6d9c;
    assert input[259] = 0xa1ce4629;
    assert input[260] = 0x2be79f26;
    assert input[261] = 0x0e05bcd9;
    assert input[262] = 0x95949010;
    assert input[263] = 0x30dcf64a;
    assert input[264] = 0xc29234bd;
    assert input[265] = 0x338601cd;
    assert input[266] = 0x655886c2;
    assert input[267] = 0x9d8c2180;
    assert input[268] = 0xc8b8be02;
    assert input[269] = 0xda756313;
    assert input[270] = 0x00fd53af;
    assert input[271] = 0x91e46904;
    assert input[272] = 0xbbab306c;
    assert input[273] = 0x2031873f;
    assert input[274] = 0x1443fc58;
    assert input[275] = 0x6dfd0ad3;
    assert input[276] = 0xe0ab47e1;
    assert input[277] = 0xeeb0c7e5;
    assert input[278] = 0xdc13e5e5;
    assert input[279] = 0x0f0b58fb;
    assert input[280] = 0x62351103;
    assert input[281] = 0xeeed8ffb;
    assert input[282] = 0x6a1eb8c0;
    assert input[283] = 0x9520fd79;
    assert input[284] = 0x5e2dbadf;
    assert input[285] = 0x5ca8e143;
    assert input[286] = 0xb9992a40;
    assert input[287] = 0x2a5bac12;
    assert input[288] = 0x285c6d2d;
    assert input[289] = 0x0b32992b;
    assert input[290] = 0x0dadd5aa;
    assert input[291] = 0xa557aa90;
    assert input[292] = 0x727d058f;
    assert input[293] = 0x249e1e57;
    assert input[294] = 0x82bab0b1;
    assert input[295] = 0x1c0311f7;
    assert input[296] = 0xa9aca441;
    assert input[297] = 0xc3895253;
    assert input[298] = 0x6f0fc075;
    assert input[299] = 0x6018ae39;
    assert input[300] = 0xe4d2b1d2;
    assert input[301] = 0x8030113a;
    assert input[302] = 0x99c4574d;
    assert input[303] = 0xe59b6646;
    assert input[304] = 0x6e86808d;
    assert input[305] = 0xee84bc34;
    assert input[306] = 0x00360158;
    assert input[307] = 0x29e73b2c;
    assert input[308] = 0xa05b92ba;
    assert input[309] = 0x6bcec2b7;
    assert input[310] = 0xbfd30d65;
    assert input[311] = 0x76bceae7;
    assert input[312] = 0x877d148c;
    assert input[313] = 0x5a722fc2;
    assert input[314] = 0x692f7295;
    assert input[315] = 0x684b1185;
    assert input[316] = 0xedf2457c;
    assert input[317] = 0x0b9852f6;
    assert input[318] = 0x97180ef1;
    assert input[319] = 0x4723282c;
    assert input[320] = 0xa947ce58;
    assert input[321] = 0xb04a64f4;
    assert input[322] = 0xfd5f522a;
    assert input[323] = 0x575c91c7;
    assert input[324] = 0x7a8c760e;
    assert input[325] = 0x1991ea4c;
    assert input[326] = 0x0834d7c5;
    assert input[327] = 0x2dfad064;
    assert input[328] = 0xe7602b63;
    assert input[329] = 0x97975e76;
    assert input[330] = 0xe0da6e97;
    assert input[331] = 0x6e5ea73b;
    assert input[332] = 0xb4b7ddf8;
    assert input[333] = 0x6f4a0eff;
    assert input[334] = 0x9d6ad8e0;
    assert input[335] = 0x900d5d44;
    assert input[336] = 0x6f8a10e1;
    assert input[337] = 0xff4eda5d;
    assert input[338] = 0xbbf0be1b;
    assert input[339] = 0x29483761;
    assert input[340] = 0x1695516b;
    assert input[341] = 0x4c305944;
    assert input[342] = 0x4b4018c7;
    assert input[343] = 0xc3d7f2f4;
    assert input[344] = 0xe2f08f39;
    assert input[345] = 0x88517e9a;
    assert input[346] = 0xba672408;
    assert input[347] = 0x49aac7a3;
    assert input[348] = 0xd908f63c;
    assert input[349] = 0xadfa9b76;
    assert input[350] = 0xfcd0c3c9;
    assert input[351] = 0x03b6f2b2;
    assert input[352] = 0xcddee9b7;
    assert input[353] = 0x5f0cf8d6;
    assert input[354] = 0x6fbe8acc;
    assert input[355] = 0x2a7aa0cc;
    assert input[356] = 0xf4095335;
    assert input[357] = 0xf3d15f0b;
    assert input[358] = 0xaca73900;
    assert input[359] = 0x4ebee15b;
    assert input[360] = 0x4b7405b9;
    assert input[361] = 0x16339256;
    assert input[362] = 0xc6396164;
    assert input[363] = 0xe6c9313c;
    assert input[364] = 0xda7e5cdb;
    assert input[365] = 0x149dc149;
    assert input[366] = 0x60b2ab56;
    assert input[367] = 0xf2a3af75;
    assert input[368] = 0xc04c053e;
    assert input[369] = 0xe432cb9f;
    assert input[370] = 0xf34f4ebe;
    assert input[371] = 0xec662032;
    assert input[372] = 0xa6dd5582;
    assert input[373] = 0xfbb794bf;
    assert input[374] = 0x0675cbad;
    assert input[375] = 0xff8cdfd0;
    assert input[376] = 0x9f26ca3f;
    assert input[377] = 0x1dc66f49;
    assert input[378] = 0x4f84eca5;
    assert input[379] = 0xa37a61d6;
    assert input[380] = 0xcbf57c2f;
    assert input[381] = 0x7379c207;
    assert input[382] = 0x8117eae5;
    assert input[383] = 0xeb5aaba3;
    assert input[384] = 0x9529844e;
    assert input[385] = 0x62d6f95b;
    assert input[386] = 0x7660b237;
    assert input[387] = 0xb8b23453;
    assert input[388] = 0x132f6b5e;
    assert input[389] = 0x857748ed;
    assert input[390] = 0x6cfa26eb;
    assert input[391] = 0x901cabf6;
    assert input[392] = 0xf26cd9b9;
    assert input[393] = 0xbe9bc62c;
    assert input[394] = 0xc345b26e;
    assert input[395] = 0x4d552773;
    assert input[396] = 0x484381bd;
    assert input[397] = 0x849a7127;
    assert input[398] = 0x67677199;
    assert input[399] = 0xb2fb7bbc;
    assert input[400] = 0x78ebb84f;
    assert input[401] = 0xae3d45ab;
    assert input[402] = 0xbe016b40;
    assert input[403] = 0x1e1fa8b5;
    assert input[404] = 0x843ec4ea;
    assert input[405] = 0x3bb25b19;
    assert input[406] = 0x6324f524;
    assert input[407] = 0x29d2698e;
    assert input[408] = 0xb714d46d;
    assert input[409] = 0xdce4f4ce;
    assert input[410] = 0xac90a294;
    assert input[411] = 0xfd152981;
    assert input[412] = 0x16f53d59;
    assert input[413] = 0xadecc12a;
    assert input[414] = 0x88c38851;
    assert input[415] = 0x254e8b21;
    assert input[416] = 0x8ce7caa3;
    assert input[417] = 0x5b01a7ce;
    assert input[418] = 0x785d1b73;
    assert input[419] = 0x72e7b624;
    assert input[420] = 0xd7066184;
    assert input[421] = 0x5ff03a85;
    assert input[422] = 0xea8e5b73;
    assert input[423] = 0x573c3255;
    assert input[424] = 0x458c77d4;
    assert input[425] = 0xfb33beb5;
    assert input[426] = 0x49edc2b5;
    assert input[427] = 0x860c2d9d;
    assert input[428] = 0x45ba4ac6;
    assert input[429] = 0x05bac4bf;
    assert input[430] = 0xf587e8ac;
    assert input[431] = 0x0f959132;
    assert input[432] = 0xa6c713e2;
    assert input[433] = 0x4c7a66da;
    assert input[434] = 0x493ed543;
    assert input[435] = 0x52726c61;
    assert input[436] = 0x794d2686;
    assert input[437] = 0x6f542e97;
    assert input[438] = 0xd76e6816;
    assert input[439] = 0x3f5620a3;
    assert input[440] = 0x36cdec8c;
    assert input[441] = 0xac31260f;
    assert input[442] = 0x4fd2e965;
    assert input[443] = 0xe09e7132;
    assert input[444] = 0xa7fc68d1;
    assert input[445] = 0x9cd4a1ea;
    assert input[446] = 0x138cd677;
    assert input[447] = 0xc7d4cf63;
    assert input[448] = 0xd1abf21a;
    assert input[449] = 0x973a80f7;
    assert input[450] = 0xb0042f68;
    assert input[451] = 0x67413e1d;
    assert input[452] = 0x5ea08407;
    assert input[453] = 0x95b3cfe2;
    assert input[454] = 0xd97c8c46;
    assert input[455] = 0x443cf2ec;
    assert input[456] = 0x3d5989c7;
    assert input[457] = 0x1e97a2f5;
    assert input[458] = 0xe86aac4f;
    assert input[459] = 0x0b14ad48;
    assert input[460] = 0xfb5fc824;
    assert input[461] = 0xb225a967;
    assert input[462] = 0x422bc102;
    assert input[463] = 0x456e6fc4;
    assert input[464] = 0xada94801;
    assert input[465] = 0xdbe5cbcd;
    assert input[466] = 0x19b95eb8;
    assert input[467] = 0xf0c1a1be;
    assert input[468] = 0x06586e25;
    assert input[469] = 0x6b13a19b;
    assert input[470] = 0x9694b7da;
    assert input[471] = 0xe190efa5;
    assert input[472] = 0x0d29f414;
    assert input[473] = 0x01b6d051;
    assert input[474] = 0xf9ca4097;
    assert input[475] = 0xe517ae20;
    assert input[476] = 0x5fbbd65a;
    assert input[477] = 0xfe9874ae;
    assert input[478] = 0x164ef42a;
    assert input[479] = 0x889544cb;
    assert input[480] = 0xc3a21c8a;
    assert input[481] = 0x714d4569;
    assert input[482] = 0x95202f6e;
    assert input[483] = 0x3c520660;
    assert input[484] = 0x1eb1e3f8;
    assert input[485] = 0x01b83c7d;
    assert input[486] = 0x8682389f;
    assert input[487] = 0xe0d0409c;
    assert input[488] = 0xeda25e96;
    assert input[489] = 0xe0b904d7;
    assert input[490] = 0xeafa8a97;
    assert input[491] = 0x576622a5;
    assert input[492] = 0xc2d21711;
    assert input[493] = 0xa9f5d6e8;
    assert input[494] = 0xba0abd4c;
    assert input[495] = 0xe79db133;
    assert input[496] = 0xdd85ce56;
    assert input[497] = 0x8f889689;
    assert input[498] = 0xcc3275e7;
    assert input[499] = 0xa3f76523;
    assert input[500] = 0x4f26e0c0;
    assert input[501] = 0x5e3bebb9;
    assert input[502] = 0xfc1996ed;
    assert input[503] = 0x5a5ff7e0;
    assert input[504] = 0x00e6f06a;
    assert input[505] = 0x6e4ecce1;
    assert input[506] = 0x0c5b08b8;
    assert input[507] = 0x944fb4b9;
    assert input[508] = 0x862e9cfe;
    assert input[509] = 0xe15979ed;
    assert input[510] = 0x9a2e9505;
    assert input[511] = 0x08c1c183;
    return ();
}
