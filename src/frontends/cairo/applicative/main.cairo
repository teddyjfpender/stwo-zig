%builtins output pedersen range_check ecdsa bitwise ec_op keccak poseidon range_check96 add_mod mul_mod

from circuit_tree import CircuitUnpackerConfig, unpack_circuit_tree
from registry import assert_production_registry
from starkware.cairo.bootloaders.simple_bootloader.execute_task import BLAKE_HASH
from starkware.cairo.bootloaders.simple_bootloader.run_simple_bootloader import run_simple_bootloader
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_blake2s.blake2s import (
    blake_with_opcode,
    encode_felt252_data_and_calc_blake_hash,
)
from starkware.cairo.common.cairo_builtins import (
    BitwiseBuiltin,
    EcOpBuiltin,
    HashBuiltin,
    KeccakBuiltin,
    ModBuiltin,
    PoseidonBuiltin,
    SignatureBuiltin,
)
from starkware.cairo.common.math import assert_nn_le
from starkware.cairo.common.memcpy import memcpy

// The old Apollo Starknet aggregator and pinned Scarb 2.18.0 circuit verifier.
// The Cairo verifier executable is SHA-256
// 1453cfbe841451c49750d873babc2dd6e8a63f3e4194a4f1108d1273d21403ff.
const AGGREGATOR_PROGRAM_HASH = 0x3e4ce8340259e374200ed856e597a0c0b268d1021119d33573d7c759c5320f9;
const CIRCUIT_VERIFIER_PROGRAM_HASH = 0x32cfde0ff6a3ee75c324573fead7cf7b4393636639523ddf11aa3b61016b25c;
// SHA-256 of production.json, reduced modulo the Stark field prime.
const PRODUCTION_REGISTRY_COMMITMENT = 0x2503220947f14bd85a4f5160fd5953db92f6aec0055367830ebc8a65187eaab;
const AGGREGATOR_CONSTANT = 'AGGREGATOR';

func modified_aggregator_hash{range_check_ptr}(program_hash: felt) -> (hash: felt) {
    let (input: felt*) = alloc();
    assert input[0] = AGGREGATOR_CONSTANT;
    assert input[1] = program_hash;
    let (hash) = encode_felt252_data_and_calc_blake_hash(data_len=2, data=input);
    return (hash=hash);
}

// Run the actual aggregator and the pinned circuit verifier as Cairo tasks.
// Independently unfold the circuit tree inside Cairo; its root digest must be
// what the verifier proved, and its ordered task outputs must be exactly the
// input the aggregator consumed. The final output is one applicative statement.
func main{
    output_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
    ecdsa_ptr: SignatureBuiltin*,
    bitwise_ptr: BitwiseBuiltin*,
    ec_op_ptr: EcOpBuiltin*,
    keccak_ptr: KeccakBuiltin*,
    poseidon_ptr: PoseidonBuiltin*,
    range_check96_ptr,
    add_mod_ptr: ModBuiltin*,
    mul_mod_ptr: ModBuiltin*,
}() {
    alloc_locals;
    local aggregator_output_ptr: felt*;
    %{ LOAD_CIRCUIT_APPLICATIVE_BOOTLOADER_INPUT %}
    let aggregator_output_start = aggregator_output_ptr;
    run_simple_bootloader{output_ptr=aggregator_output_ptr}();
    local aggregator_output_end: felt* = aggregator_output_ptr;
    assert aggregator_output_start[0] = 1;
    assert aggregator_output_start[1] = aggregator_output_end - aggregator_output_start - 1;
    assert aggregator_output_start[2] = AGGREGATOR_PROGRAM_HASH;
    let aggregator_input_ptr = aggregator_output_start + 3;

    local verifier_output_ptr: felt*;
    %{ CIRCUIT_APPLICATIVE_SETUP_VERIFIER_RUN %}
    let verifier_output_start = verifier_output_ptr;
    run_simple_bootloader{output_ptr=verifier_output_ptr}();
    local verifier_output_end: felt* = verifier_output_ptr;
    assert verifier_output_start[0] = 1;
    assert verifier_output_start[1] = 10;
    assert verifier_output_start[1] = verifier_output_end - verifier_output_start - 1;
    assert verifier_output_start[2] = CIRCUIT_VERIFIER_PROGRAM_HASH;

    // Preserve the builtin pointers returned by the two task executions.
    local pedersen_ptr: HashBuiltin* = pedersen_ptr;
    local range_check_ptr = range_check_ptr;
    local ecdsa_ptr: SignatureBuiltin* = ecdsa_ptr;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    local ec_op_ptr: EcOpBuiltin* = ec_op_ptr;
    local keccak_ptr: KeccakBuiltin* = keccak_ptr;
    local poseidon_ptr: PoseidonBuiltin* = poseidon_ptr;
    local range_check96_ptr = range_check96_ptr;
    local add_mod_ptr: ModBuiltin* = add_mod_ptr;
    local mul_mod_ptr: ModBuiltin* = mul_mod_ptr;

    local config: CircuitUnpackerConfig*;
    local bootloader_tasks_output_ptr: felt*;
    %{ CIRCUIT_APPLICATIVE_SETUP_UNPACK %}
    assert_production_registry(config=config);
    let (root_hash, root_digest, unpacked_end, n_leaves) = unpack_circuit_tree(
        config=config, tasks_output_ptr=bootloader_tasks_output_ptr + 1
    );
    %{ CIRCUIT_UNPACK_EXIT_SCOPE %}
    assert_nn_le(n_leaves, 4096);
    assert bootloader_tasks_output_ptr[0] = n_leaves;
    local tasks_output_end: felt* = unpacked_end;

    // The terminal circuit is the production multiverifier.
    assert root_hash[0] = 0xa5989715;
    assert root_hash[1] = 0x2377c07a;
    assert root_hash[2] = 0xc6d1e844;
    assert root_hash[3] = 0x54f0a04d;
    assert root_hash[4] = 0x8be65a7d;
    assert root_hash[5] = 0xfd73c261;
    assert root_hash[6] = 0x9078e728;
    assert root_hash[7] = 0x973f680f;

    let (local verification_preimage: felt*) = alloc();
    memcpy(dst=verification_preimage, src=root_hash, len=8);
    memcpy(dst=verification_preimage + 8, src=root_digest, len=8);
    let (local expected_verifier_output: felt*) = alloc();
    blake_with_opcode(len=16, data=verification_preimage, out=expected_verifier_output);
    memcpy(dst=verifier_output_start + 3, src=expected_verifier_output, len=8);

    // Cairo memory is write-once: copying the unpacked task output over the
    // aggregator's input asserts equality of every cell, including task order.
    let tasks_output_length = tasks_output_end - bootloader_tasks_output_ptr;
    memcpy(dst=aggregator_input_ptr, src=bootloader_tasks_output_ptr, len=tasks_output_length);
    let aggregated_output_ptr = aggregator_input_ptr + tasks_output_length;
    let aggregated_output_length = aggregator_output_end - aggregated_output_ptr;

    local output_start: felt* = output_ptr;
    tempvar aggregator_program_hash_function = nondet %{ aggregator_program_hash_function %};
    assert aggregator_program_hash_function = BLAKE_HASH;
    let (aggregator_hash) = modified_aggregator_hash(program_hash=AGGREGATOR_PROGRAM_HASH);
    assert output_ptr[0] = aggregator_hash;
    assert output_ptr[1] = PRODUCTION_REGISTRY_COMMITMENT;
    memcpy(dst=output_ptr + 2, src=aggregated_output_ptr, len=aggregated_output_length);
    let output_ptr = output_ptr + 2 + aggregated_output_length;
    %{ CIRCUIT_APPLICATIVE_WRITE_FACT_TOPOLOGY %}
    return ();
}
