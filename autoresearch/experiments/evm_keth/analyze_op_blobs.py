#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["ckzg==2.0.1", "brotli==1.2.0", "rlp==4.1.0"]
# ///
"""Verify archived L1 blobs and inspect OP frame/channel/span metadata.

Encoding reference: ethereum-optimism/optimism at
8aa2479d99d928d3adbb65f88975aa81cc009a1e, op-service/eth/blob.go and
op-node/rollup/derive/{frame,span_batch}.go. Transaction bodies and derivation
validity are deliberately not inferred from span metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import zlib

TRUSTED_SETUP_SHA256 = 'd39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7'



def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def blob_data(blob: bytes) -> bytes:
    if len(blob) != 131072 or blob[1] != 0:
        raise ValueError('unsupported blob length or OP encoding version')
    decoded = bytearray()
    for index in range(0, len(blob), 128):
        a, b, c, d = (blob[index+i:index+i+32] for i in (0, 32, 64, 96))
        if any(value[0] >= 64 for value in (a, b, c, d)):
            raise ValueError('invalid OP field element')
        x, y, z = a[0] | ((b[0] & 48) << 2), (b[0] & 15) | ((d[0] & 15) << 4), c[0] | ((d[0] & 48) << 2)
        decoded += a[1:] + bytes([x]) + b[1:] + bytes([y]) + c[1:] + bytes([z]) + d[1:]
    size = int.from_bytes(decoded[1:4], 'big')
    if size > 130044 or any(decoded[4+size:]):
        raise ValueError('invalid OP blob length or nonzero padding')
    return bytes(decoded[4:4+size])


def frames(data: bytes):
    if not data or data[0] != 0:
        raise ValueError('unsupported frame version')
    offset = 1
    while offset < len(data):
        if len(data) - offset < 23:
            raise ValueError('truncated frame header')
        channel = data[offset:offset+16].hex()
        number = int.from_bytes(data[offset+16:offset+18], 'big')
        size = int.from_bytes(data[offset+18:offset+22], 'big')
        end = offset + 22 + size
        if size > 1_000_000 or end >= len(data) or data[end] not in (0, 1):
            raise ValueError('invalid frame size or final marker')
        yield channel, number, data[offset+22:end], bool(data[end])
        offset = end + 1


def decompress(data: bytes, limit: int) -> tuple[str, bytes]:
    if not data:
        raise ValueError('empty channel')
    if data[0] == 1:
        import brotli
        decoder = brotli.Decompressor()
        chunks, size = [], 0
        for offset in range(1, len(data), 4096):
            chunk = decoder.process(data[offset:offset+4096])
            size += len(chunk)
            if size > limit:
                raise ValueError('decompressed channel exceeds limit')
            chunks.append(chunk)
        if not decoder.is_finished():
            raise ValueError('truncated Brotli channel')
        return 'brotli', b''.join(chunks)
    if data[0] & 15 == 8:
        decoder = zlib.decompressobj()
        plain = decoder.decompress(data, limit + 1)
        if len(plain) > limit or not decoder.eof or decoder.unused_data:
            raise ValueError('invalid or oversized zlib channel')
        return 'zlib', plain
    raise ValueError('unsupported channel compression')


def batches(plain: bytes):
    offset = 0
    while offset < len(plain):
        prefix = plain[offset]
        if prefix < 0x80:
            size, header = 1, 0
        elif prefix <= 0xb7:
            size, header = prefix - 0x80, 1
        elif prefix <= 0xbf:
            count = prefix - 0xb7
            if offset + 1 + count > len(plain) or plain[offset+1] == 0:
                raise ValueError('invalid batch RLP length')
            size, header = int.from_bytes(plain[offset+1:offset+1+count], 'big'), 1 + count
            if size < 56:
                raise ValueError('noncanonical batch RLP length')
        else:
            raise ValueError('batch envelope must be RLP bytes')
        end = offset + header + size
        if size == 0 or end > len(plain):
            raise ValueError('truncated or empty batch')
        if header == 1 and size == 1 and plain[offset+1] < 128:
            raise ValueError('noncanonical batch RLP string')
        yield plain[offset+header:end]
        offset = end


def span_metadata(raw: bytes) -> dict:
    offset = 1

    def uvarint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            if offset >= len(raw):
                raise ValueError('truncated span integer')
            byte = raw[offset]
            offset += 1
            if shift == 63 and byte > 1:
                raise ValueError('span integer overflows uint64')
            value |= (byte & 127) << shift
            if byte < 128:
                return value
        raise ValueError('span integer overflows uint64')

    if raw[0] == 0:
        import rlp
        value = rlp.decode(raw[1:])
        if not isinstance(value, list) or len(value) != 5:
            raise ValueError('invalid singular batch')
        return {'type': 'singular', 'block_count': 1, 'sequencer_transactions': len(value[4])}
    if raw[0] != 1:
        raise ValueError('unsupported batch type')
    timestamp, origin = uvarint(), uvarint()
    if offset + 40 > len(raw):
        raise ValueError('truncated span checks')
    parent_check, origin_check = raw[offset:offset+20].hex(), raw[offset+20:offset+40].hex()
    offset += 40
    count = uvarint()
    if not 1 <= count <= min(10_000_000, len(raw)):
        raise ValueError('invalid span block count')
    bits = (count + 7) // 8
    if offset + bits > len(raw) or int.from_bytes(raw[offset:offset+bits], 'big').bit_length() > count:
        raise ValueError('invalid span origin bits')
    offset += bits
    counts = [uvarint() for _ in range(count)]
    if sum(counts) > 10_000_000:
        raise ValueError('span transaction count too large')
    return {'type': 'span', 'relative_timestamp': timestamp, 'last_l1_origin_number': origin,
            'parent_check': parent_check, 'l1_origin_check': origin_check,
            'block_count': count, 'block_transaction_counts': counts,
            'sequencer_transactions': sum(counts), 'transaction_section_bytes': len(raw) - offset}


def analyze(fixture: Path, index: int, directory: Path, setup: Path, out: Path, limit: int):
    import ckzg
    if index < 0 or limit < 1:
        raise ValueError('transaction index must be nonnegative and output limit positive')
    if sha(setup) != TRUSTED_SETUP_SHA256:
        raise ValueError('Ethereum KZG trusted setup identity mismatch')
    tx = json.loads(fixture.read_text())['blocks'][0]['transaction'][index]
    settings = ckzg.load_trusted_setup(str(setup), 0)
    channels, verified = {}, []
    for versioned_hash in tx['blobVersionedHashes']:
        stem = directory / versioned_hash
        blob = stem.with_suffix('.blob').read_bytes()
        metadata = json.loads(stem.with_suffix('.json').read_text())
        commitment, proof = (bytes.fromhex(metadata[key].removeprefix('0x')) for key in ('commitment', 'proof'))
        if metadata['versionedHash'] != versioned_hash or '0x01' + hashlib.sha256(commitment).hexdigest()[2:] != versioned_hash:
            raise ValueError('blob commitment differs from signed L1 transaction')
        if not ckzg.verify_blob_kzg_proof(blob, commitment, proof, settings) or ckzg.blob_to_kzg_commitment(blob, settings) != commitment:
            raise ValueError('KZG verification failed')
        decoded = blob_data(blob)
        for channel, number, payload, last in frames(decoded):
            parts = channels.setdefault(channel, {})
            if number in parts:
                raise ValueError('duplicate frame')
            parts[number] = (payload, last)
        verified.append({'versioned_hash': versioned_hash, 'blob_sha256': sha(stem.with_suffix('.blob')),
                         'metadata_sha256': sha(stem.with_suffix('.json')), 'kzg_verified': True})
    output_channels = []
    for channel, parts in channels.items():
        numbers = sorted(parts)
        if numbers != list(range(len(numbers))) or [n for n in numbers if parts[n][1]] != [numbers[-1]]:
            raise ValueError('incomplete or conflicting channel')
        encoded = b''.join(parts[n][0] for n in numbers)
        compression, plain = decompress(encoded, limit)
        decoded_batches = [span_metadata(batch) for batch in batches(plain)]
        output_channels.append({'channel': channel, 'frame_count': len(parts), 'compression': compression,
            'compressed_bytes': len(encoded), 'uncompressed_bytes': len(plain), 'uncompressed_sha256': hashlib.sha256(plain).hexdigest(),
            'batches': decoded_batches, 'encoded_l2_blocks': sum(b['block_count'] for b in decoded_batches),
            'encoded_sequencer_transactions': sum(b['sequencer_transactions'] for b in decoded_batches)})
    result = {'schema': 'keth-op-blob-characterization-v1', 'fixture_sha256': sha(fixture),
        'transaction_index': index, 'transaction_hash': tx['hash'], 'trusted_setup_sha256': sha(setup),
        'reference_revision': '8aa2479d99d928d3adbb65f88975aa81cc009a1e', 'blobs': verified,
        'channels': output_channels, 'scope': 'host KZG verification, framing and encoded batch metadata',
        'transaction_bodies_decoded': False, 'batch_authorization_verified': False,
        'derivation_validated': False, 'derivation_proved': False, 'l2_execution_proved': False}
    with out.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'blob-directory', 'trusted-setup', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--transaction-index', type=int, required=True)
    parser.add_argument('--max-output-bytes', type=int, default=100_000_000)
    args = parser.parse_args()
    result = analyze(args.fixture, args.transaction_index, args.blob_directory, args.trusted_setup, args.out, args.max_output_bytes)
    print(json.dumps(result, indent=2))
