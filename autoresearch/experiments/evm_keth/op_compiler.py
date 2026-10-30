"""Compile the OP overlay with explicit, hash-checked Keth adaptations.

The reference checkout remains clean. A module reader applies narrowly scoped
adaptations in memory, and records the effective source digest. An unexpected
upstream file, duplicate replacement, or missing adaptation fails compilation.

Transaction-local transient dictionaries must have no parent at finalization
and every first value must equal the constrained zero default. Dictionary
consistency alone does not establish that initialization rule.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

try:
    from .bridge import PINS, authenticate
except ImportError:
    from bridge import PINS, authenticate


STATE_SHA256 = '10d49ed8f18c9baf4c0ee5f2a244b97e5290a732c62eaf6d814dffb5de175119'
TRIE_SHA256 = '3fa26e7ca7ac40ffb93a4fa426b8e80a2691cc47da3a1134253a86f99fc40bc7'
MESSAGE_SHA256 = 'b9d911da552c78dd0bc630334d3374683d890c8a2bff7d551889babb7c1b7dbe'
BLOCK_INSTRUCTIONS_SHA256 = '7b8dc8b494885fee5e6b79f623e80aede32c39c367fe843ec3c06858b32631a6'
RLP_SHA256 = '74bb736b7b19fcf5195a888e82c9695ebd4f2785674a8bae070494a6290604ab'
MPT_UTILS_SHA256 = 'cf8640fdda307f36643ca3e3bcc3e13b973738a8408f9c2013a8070480814217'
MPT_DIFF_SHA256 = '7721fd03e7047e943a4377324a2666a0203a0d2514ee1ac0e3144c0401787703'
INTERPRETER_SHA256 = '77705e78d13e09833fdfaa1392544095dca1bf003a5d02dea285d2f6ef02a5dc'


def adapt_state(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != STATE_SHA256:
        raise ValueError('unexpected Keth state source')
    head, body = source.split('func finalize_transient_storage', 1)
    old = ') = dict_squash(transient_storage_tries_start, transient_storage_tries_end);'
    new = ''') = default_dict_finalize(
        transient_storage_tries_start, transient_storage_tries_end,
        cast(transient_storage_tries.value.default.value, felt)
    );
    assert cast(transient_storage_tries.value._data.value.parent_dict, felt) = 0;
    assert transient_storage_tries.value.default.value.low = 0;
    assert transient_storage_tries.value.default.value.high = 0;'''
    if body.count(old) != 1:
        raise ValueError('transient finalizer adaptation no longer matches')
    return head + 'func finalize_transient_storage' + body.replace(old, new)


def adapt_trie(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != TRIE_SHA256:
        raise ValueError('unexpected Keth trie source')
    start = source.index('func bytes_to_nibble_list{')
    end = source.index('\nfunc _prepare_trie', start)
    # Division bounds each nibble and constrains the byte reconstruction.
    # This replaces a witness decomposition with explicit arithmetic bounds.
    replacement = '''func bytes_to_nibble_list{range_check_ptr, bitwise_ptr: BitwiseBuiltin*}(bytes_: Bytes) -> Bytes {
    alloc_locals;
    let (buffer) = alloc();
    _op_split_bytes(bytes_.value.data, buffer, bytes_.value.len);
    tempvar result = Bytes(new BytesStruct(buffer, bytes_.value.len * 2));
    return result;
}

func _op_split_bytes{range_check_ptr}(source: felt*, target: felt*, n: felt) {
    alloc_locals;
    if (n == 0) {
        return ();
    }
    _op_assert_nn_le(source[0], 255);
    let (high, low) = _op_divmod(source[0], 16);
    assert target[0] = high;
    assert target[1] = low;
    return _op_split_bytes(source + 1, target + 2, n - 1);
}
'''
    imports = ('from starkware.cairo.common.math import assert_nn_le as _op_assert_nn_le\n'
               'from ethereum.utils.numeric import divmod as _op_divmod\n')
    return imports + source[:start] + replacement + source[end:]


def adapt_message(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != MESSAGE_SHA256:
        raise ValueError('unexpected Keth message source')
    old = 'let nonce = Uint(caller_account.value.nonce.value - 1);'
    new = ('let (_, previous_nonce) = _op_message_divmod(caller_account.value.nonce.value + 2 ** 64 - 1, 2 ** 64);\n'
           '        let nonce = Uint(previous_nonce);')
    if source.count(old) != 1:
        raise ValueError('creation nonce adaptation no longer matches')
    return ('from ethereum.utils.numeric import divmod as _op_message_divmod\n' +
            source.replace(old, new).replace(
                    '    dict_write(0x1100000000000000000000000000000000000000, 1);',
                    '    dict_write(0x1100000000000000000000000000000000000000, 1);\n'
                    '    dict_write(2 ** 144, 1);'))


def adapt_interpreter(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != INTERPRETER_SHA256:
        raise ValueError('unexpected Keth interpreter source')
    old = '''    if (cast(evm.value.message.value.code_address.value, felt) != 0) {
        let (local precompile_address, precompile_fn) = precompile_table_lookup('''
    new = '''    local _op_guard_evm: Evm = evm;
    if (cast(evm.value.message.value.code_address.value, felt) != 0) {
        if (evm.value.message.value.disable_precompiles.value == 0) {
            let oversized = _op_precompile_exceeds_limit([evm.value.message.value.code_address.value], evm.value.message.value.data.value.len);
            if (oversized != 0) {
                let evm = _op_guard_evm;
                EvmImpl.set_gas_left{evm=evm}(Uint(0));
                tempvar error = new EthereumException(OutOfGasError);
                EvmImpl.set_error{evm=evm}(error);
                return evm;
            }
            tempvar range_check_ptr = range_check_ptr;
        } else {
            tempvar range_check_ptr = range_check_ptr;
        }
        let range_check_ptr = [ap - 1];
        let evm = _op_guard_evm;
        let (local precompile_address, precompile_fn) = _op_precompile_lookup('''
    if source.count(old) != 1:
        raise ValueError('OP precompile admission adaptation no longer matches')
    return ('from op_stack.precompile_admission import exceeds_limit as _op_precompile_exceeds_limit\n'
            'from op_stack.precompile_dispatch import lookup as _op_precompile_lookup\n' +
            source.replace(old, new).replace('    // Execute bytecode recursively',
                '    let evm = _op_guard_evm;\n    // Execute bytecode recursively'))


def adapt_block_instructions(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != BLOCK_INSTRUCTIONS_SHA256:
        raise ValueError('unexpected Keth block instruction source')
    old = 'let block_hash_at_index = block_env.value.block_hashes.value.data[index_from_start];'
    new = ('_op_block_assert_nn_le(index_from_start, block_env.value.block_hashes.value.len - 1);\n'
           '        ' + old)
    if source.count(old) != 1:
        raise ValueError('BLOCKHASH bounds adaptation no longer matches')
    return ('from starkware.cairo.common.math import assert_nn_le as _op_block_assert_nn_le\n' +
            source.replace(old, new))


def adapt_rlp(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != RLP_SHA256:
        raise ValueError('unexpected Keth RLP source')
    start = source.index('func U256_from_rlp{')
    end = source.index('// @notice Decodes the RLP encoded representation of an account.', start)
    integer = source[start:end]
    integer = integer.replace('    return res;', '''    local res: U256 = res;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    let canonical = encode_u256(res);
    let equal = Bytes__eq__(canonical, encoding);
    assert equal.value = 1;
    return res;''')
    source = source[:start] + integer + source[end:]
    start = source.index('func Account_from_rlp{')
    account = source[start:]
    account = account.replace('    return (res, storage_root_bytes);', '''    local res: Account = res;
    local storage_root_bytes: Bytes = storage_root_bytes;
    local bitwise_ptr: BitwiseBuiltin* = bitwise_ptr;
    let canonical = encode_account(res, storage_root_bytes);
    let equal = Bytes__eq__(canonical, encoding);
    assert equal.value = 1;
    return (res, storage_root_bytes);''')
    return source[:start] + account


def adapt_mpt_utils(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != MPT_UTILS_SHA256:
        raise ValueError('unexpected Keth MPT utilities source')
    source = ('from starkware.cairo.common.math import assert_nn_le as _op_mpt_nn_le\n'
              'from ethereum.utils.bytes import Bytes__eq__ as _op_mpt_bytes_equal\n'
              'from ethereum_rlp.rlp import encode as _op_mpt_encode\n' + source)
    old = '    let extended = ExtendedImpl.from_simple(decoded);\n    return deserialize_to_internal_node(extended);'
    new = '''    local range_check_ptr = range_check_ptr;
    let extended = ExtendedImpl.from_simple(decoded);
    local extended: Extended = extended;
    let canonical = _op_mpt_encode(extended);
    let equal = _op_mpt_bytes_equal(canonical, node);
    assert equal.value = 1;
    return deserialize_to_internal_node(extended);'''
    if source.count(old) != 1:
        raise ValueError('MPT canonical decoder adaptation no longer matches')
    source = source.replace(old, new)
    source = source.replace('    let nibbles = bytes_to_nibble_list(prefix);',
        '    _op_mpt_nn_le(1, prefix.value.len);\n    let nibbles = bytes_to_nibble_list(prefix);')
    source = source.replace('    let prefix = items[0].value.bytes;',
        '    assert cast(items[0].value.sequence.value, felt) = 0;\n'
        '    let prefix = items[0].value.bytes;')
    source = source.replace('    let first_nibble = nibbles.value.data[0];',
        '    let first_nibble = nibbles.value.data[0];\n    _op_mpt_nn_le(first_nibble, 3);')
    source = source.replace('// Else this means the real key is even length',
        'assert nibbles.value.data[1] = 0;\n        // Else this means the real key is even length')
    return source


def adapt_mpt_diff(source: str) -> str:
    if hashlib.sha256(source.encode()).hexdigest() != MPT_DIFF_SHA256:
        raise ValueError('unexpected Keth MPT diff source')
    source = ('from starkware.cairo.common.math import assert_nn_le as _op_mpt_ref_nn_le\n'
              'from ethereum_rlp.rlp import encode as _op_mpt_ref_encode\n' + source)
    source = source.replace('    let hash = keccak256(encoded_node);',
        '    _op_mpt_ref_nn_le(32, encoded_node.value.len);\n'
        '    _op_mpt_ref_nn_le(encoded_node.value.len, 600);\n    let hash = keccak256(encoded_node);')
    source = source.replace('        let internal_node = deserialize_to_internal_node(sequence);',
        '        let encoded = _op_mpt_ref_encode(sequence);\n'
        '        _op_mpt_ref_nn_le(encoded.value.len, 31);\n'
        '        let internal_node = deserialize_to_internal_node(sequence);')
    return source


def compile_owned(source: Path, *, proof_mode: bool = True, adaptations: dict | None = None,
                  keth_checkout: Path | None = None):
    from dotenv import load_dotenv
    from starkware.cairo.lang.cairo_constants import DEFAULT_PRIME
    from starkware.cairo.lang.compiler.cairo_compile import compile_cairo, get_module_reader
    from starkware.cairo.lang.compiler.preprocessor.default_pass_manager import default_pass_manager

    directory = Path(__file__).resolve().parent
    checkout = (keth_checkout or directory.parents[3] / 'keth-pinned').resolve()
    authenticate(checkout, PINS['keth'])
    source = source.resolve()
    source.relative_to(directory / 'cairo')
    load_dotenv(checkout / '.env')
    reader = get_module_reader([str(directory / 'cairo'), str(checkout / 'cairo'),
                                *os.environ.get('CAIRO_PATH', '').split(':')])

    def read(module):
        text, filename = reader.read(module)
        adapted = {'ethereum.prague.state': (STATE_SHA256, adapt_state, 'transaction-local-transient-default-v1'),
                   'ethereum.prague.trie': (TRIE_SHA256, adapt_trie, 'bounded-byte-nibble-decomposition-v1'),
                   'ethereum.prague.utils.message': (MESSAGE_SHA256, adapt_message, 'uint64-creation-sender-nonce-v1'),
                   'ethereum.prague.vm.instructions.block': (BLOCK_INSTRUCTIONS_SHA256,
                       adapt_block_instructions, 'authenticated-history-read-bounds-v1'),
                   'ethereum_rlp.rlp': (RLP_SHA256, adapt_rlp, 'canonical-account-storage-leaves-v1'),
                   'mpt.utils': (MPT_UTILS_SHA256, adapt_mpt_utils, 'canonical-secure-trie-nodes-v1'),
                   'mpt.trie_diff': (MPT_DIFF_SHA256, adapt_mpt_diff, 'canonical-trie-child-references-v1')}
        adapted['ethereum.prague.vm.interpreter'] = (INTERPRETER_SHA256, adapt_interpreter, 'op-jovian-precompiles-v2')
        if module in adapted:
            expected, transform, name = adapted[module]
            if Path(filename).resolve() != (checkout / 'cairo' / (module.replace('.', '/') + '.cairo')).resolve():
                raise ValueError('Keth module resolved outside authenticated checkout')
            text = transform(text)
            if adaptations is not None:
                adaptations[module] = dict(original_sha256=expected,
                    effective_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    adaptation=name)
        return text, filename

    return compile_cairo(source.read_text(),
        pass_manager=default_pass_manager(prime=DEFAULT_PRIME, read_module=read),
        debug_info=False, add_start=proof_mode)
