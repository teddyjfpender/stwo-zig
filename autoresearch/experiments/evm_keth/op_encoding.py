"""Host OP encodings checked against observed consensus roots, not Cairo proofs.

The measured historical workload uses post-Isthmus deposits and Canyon receipt
encoding. Other deposit receipt versions and L1-info formats fail closed.
Run in the pinned Keth Python environment (rlp, eth-hash and EELS).
"""
from __future__ import annotations

import rlp
from eth_hash.auto import keccak

if __package__:
    from .check_fixture import transaction_bytes
else:
    from check_fixture import transaction_bytes


def hex_bytes(value: str, length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value.startswith('0x'):
        raise ValueError('expected hex bytes')
    result = bytes.fromhex(value[2:])
    if length is not None and len(result) != length:
        raise ValueError(f'expected {length} bytes')
    return result


def quantity(value: str, bits: int = 256) -> int:
    if not isinstance(value, str) or not value.startswith('0x'):
        raise ValueError('expected hex quantity')
    result = int(value, 16)
    if not 0 <= result < 1 << bits:
        raise ValueError('quantity out of range')
    return result


def op_transaction_bytes(tx: dict) -> bytes:
    if quantity(tx['type'], 8) != 0x7e:
        return transaction_bytes(tx)
    system = tx.get('isSystemTx', False)
    if type(system) is not bool:
        raise ValueError('expected boolean system flag')
    to = hex_bytes(tx['to'], 20) if tx.get('to') else b''
    return b'\x7e' + rlp.encode([
        hex_bytes(tx['sourceHash'], 32), hex_bytes(tx['from'], 20), to,
        quantity(tx.get('mint') or '0x0'), quantity(tx['value']),
        quantity(tx['gas'], 64), int(system), hex_bytes(tx['input'])])


def receipt_bytes(receipt: dict) -> bytes:
    kind = quantity(receipt['type'], 8)
    if kind not in (0, 1, 2, 3, 4, 0x7e):
        raise ValueError('unsupported receipt type')
    status = quantity(receipt['status'], 8)
    if status not in (0, 1):
        raise ValueError('invalid receipt status')
    logs = [[hex_bytes(log['address'], 20),
             [hex_bytes(topic, 32) for topic in log['topics']],
             hex_bytes(log['data'])] for log in receipt['logs']]
    fields = [status, quantity(receipt['cumulativeGasUsed'], 64),
              hex_bytes(receipt['logsBloom'], 256), logs]
    if kind == 0x7e:
        if quantity(receipt['depositReceiptVersion'], 64) != 1:
            raise ValueError('only Canyon version-1 deposit receipts are admitted')
        fields += [quantity(receipt['depositNonce'], 64), 1]
    elif any(receipt.get(k) is not None for k in ('depositNonce', 'depositReceiptVersion')):
        raise ValueError('deposit fields on sequencer receipt')
    return (bytes([kind]) if kind else b'') + rlp.encode(fields)


def ordered_trie_root(values: list[bytes]) -> str:
    # Use the independent Ethereum execution-spec trie implementation pinned by
    # Keth, with raw consensus bytes (not Ethereum Receipt dataclasses).
    from ethereum.prague.trie import Trie, root, trie_set
    from ethereum_types.bytes import Bytes
    trie = Trie(secured=False, default=Bytes(b''))
    for index, value in enumerate(values):
        trie_set(trie, Bytes(rlp.encode(index)), Bytes(value))
    return '0x' + root(trie).hex()


def isthmus_l1_info(tx: dict) -> dict:
    if quantity(tx['type'], 8) != 0x7e:
        raise ValueError('first transaction is not a deposit')
    if tx['from'].lower() != '0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001':
        raise ValueError('invalid L1-info depositor')
    if (tx.get('to') or '').lower() != '0x4200000000000000000000000000000000000015':
        raise ValueError('invalid L1-info destination')
    if (quantity(tx.get('mint') or '0x0') or quantity(tx['value'])
            or quantity(tx['gas'], 64) != 1_000_000 or tx.get('isSystemTx', False)):
        raise ValueError('unexpected post-Regolith L1-info envelope')
    raw = hex_bytes(tx['input'])
    if len(raw) != 176 or raw[:4] != keccak(b'setL1BlockValuesIsthmus()')[:4]:
        raise ValueError('expected exact Isthmus L1-info calldata')
    if raw[132:144] != bytes(12):
        raise ValueError('nonzero batcher address padding')
    number = lambda a, b: int.from_bytes(raw[a:b], 'big')
    info = dict(base_fee_scalar=number(4, 8), blob_base_fee_scalar=number(8, 12),
                sequence_number=number(12, 20), timestamp=number(20, 28),
                number=number(28, 36), base_fee=number(36, 68),
                blob_base_fee=number(68, 100), block_hash='0x' + raw[100:132].hex(),
                batcher_address='0x' + raw[144:164].hex(),
                operator_fee_scalar=number(164, 168), operator_fee_constant=number(168, 176))
    deposit_id = keccak(raw[100:132] + info['sequence_number'].to_bytes(32, 'big'))
    if '0x' + keccak((1).to_bytes(32, 'big') + deposit_id).hex() != tx['sourceHash']:
        raise ValueError('L1-info source hash mismatch')
    return info
