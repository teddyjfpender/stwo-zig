"""Framing/cap/parity tests only; no implicit native or guest execution."""
import importlib.util
from pathlib import Path
import struct
import unittest
import zlib

spec = importlib.util.spec_from_file_location('raw_input', Path(__file__).parents[1]/'capture_host/raw_input.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
C = R.C
CLAIM = {'anchor': {'number': 2, 'hash': '11'*32}, 'previous_number': 3,
         'previous_root': '22'*32, 'next_number': 4, 'next_root': '33'*32,
         'next_origin': {'number': 1, 'hash': '44'*32}}


def sample(payload=b''):
    count = int(bool(payload))
    size = 24+40*count+len(payload)
    body = b'STWOPX01'+struct.pack('<IIII', 0, count, size, 0)
    if payload:
        body += b'\x01'*32+struct.pack('<II', 0, len(payload))+payload
    header = C.claim_header(CLAIM)+struct.pack('<II', size, 0)
    return b'STWOPDZ1'+header+zlib.compress(body), b'STWOPD01'+header+body


class RawInput(unittest.TestCase):
    def test_existing_raw_format_exact_bytes_and_idempotence(self):
        packed, expected = sample(b'zero-copy input'*100)
        raw, report = R.raw_variant(packed, CLAIM)
        self.assertEqual(raw, expected)
        self.assertEqual(C.inspect_container(raw, CLAIM)['records'], 1)
        self.assertTrue(report['guest_inflation_removed'])
        self.assertFalse(report['native_derivation_accepted'])
        self.assertFalse(report['proof_verified'])
        again, report2 = R.raw_variant(raw, CLAIM)
        self.assertEqual(again, raw)
        self.assertFalse(report2['guest_inflation_removed'])

    def test_rejects_trailing_truncated_or_declared_expansion_mismatch(self):
        packed, _ = sample()
        for data in (packed+b'x', packed[:-1], packed[:C.HEADER]+b'bad zlib', packed[:168]+struct.pack('<II', 25, 0)+packed[C.HEADER:]):
            with self.assertRaises(ValueError):
                R.raw_variant(data, CLAIM)

    def test_refuses_raw_expansion_beyond_selected_transport(self):
        packed, _ = sample(bytes(4096))
        self.assertLess(len(packed), C.HEADER+256)
        with self.assertRaisesRegex(ValueError, 'exceeds selected transport'):
            R.raw_variant(packed, CLAIM, C.HEADER+256)

    def test_claim_identity_and_capacity_are_not_rewritten(self):
        packed, _ = sample()
        wrong = dict(CLAIM, next_root='55'*32)
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            R.raw_variant(packed, wrong)
        for maximum in (True, 0, C.MAX_INPUT+1):
            with self.assertRaisesRegex(ValueError, 'transport cap'):
                R.raw_variant(packed, CLAIM, maximum)
