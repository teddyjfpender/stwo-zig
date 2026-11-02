"""OP framing checks on KZG-verified, retained Base submission blobs."""
from __future__ import annotations

import json
import gzip
import hashlib
from pathlib import Path
import unittest

from autoresearch.experiments.evm_keth.analyze_op_blobs import blob_data, frames, batches, span_metadata, TRUSTED_SETUP_SHA256
from autoresearch.experiments.evm_keth.bridge import digest

EVIDENCE = Path(__file__).resolve().parents[1] / 'experiments/evm_keth/evidence/2026-10-29-m5-max/base-l1-batch'


class OpBlobTests(unittest.TestCase):
    def test_real_blob_frames_cover_one_complete_channel(self):
        receipt = json.loads((EVIDENCE / 'batch-characterization.json').read_text())
        found = []
        for value in receipt['blobs']:
            stem = EVIDENCE / value['versioned_hash']
            self.assertEqual(digest(stem.with_suffix('.blob')), value['blob_sha256'])
            self.assertEqual(digest(stem.with_suffix('.json')), value['metadata_sha256'])
            found.extend(frames(blob_data(stem.with_suffix('.blob').read_bytes())))
        self.assertEqual([f[1] for f in found], [0, 1, 2])
        self.assertEqual([f[3] for f in found], [False, False, True])
        self.assertEqual(len({f[0] for f in found}), 1)
        self.assertEqual(sum(len(f[2]) for f in found), 372931)

    def test_field_bits_padding_and_frame_bounds_are_checked(self):
        receipt = json.loads((EVIDENCE / 'batch-characterization.json').read_text())
        blob = bytearray((EVIDENCE / (receipt['blobs'][-1]['versioned_hash'] + '.blob')).read_bytes())
        for kind in ('length', 'field', 'padding', 'version'):
            with self.subTest(kind=kind):
                bad = blob.copy()
                if kind == 'length':
                    bad = bad[:-1]
                elif kind == 'field':
                    bad[0] = 128
                elif kind == 'padding':
                    bad[-1] = 1
                else:
                    bad[1] = 1
                with self.assertRaises(ValueError):
                    blob_data(bytes(bad))
        for bad in (b'', b'\x01', b'\0\0', b'\0' + bytes(22) + b'\x02'):
            with self.assertRaises(ValueError):
                list(frames(bad))

    def test_batch_envelopes_and_span_integer_overflow_rejected(self):
        self.assertEqual(list(batches(b'\x81\x80')), [b'\x80'])
        for bad in (b'\x80', b'\x81\x01', b'\xb8\x01x', b'\xc0', b'\xb9\0\x38'):
            with self.assertRaises(ValueError):
                list(batches(bad))
        for bad in (b'\x01', b'\x01' + b'\xff' * 10, b'\x02'):
            with self.assertRaises(ValueError):
                span_metadata(bad)

    def test_encoded_counts_do_not_imply_execution_or_derivation(self):
        receipt = json.loads((EVIDENCE / 'batch-characterization.json').read_text())
        self.assertEqual(sum(c['encoded_l2_blocks'] for c in receipt['channels']), 12)
        self.assertEqual(sum(c['encoded_sequencer_transactions'] for c in receipt['channels']), 2437)
        for key in ('transaction_bodies_decoded', 'batch_authorization_verified', 'derivation_validated', 'derivation_proved', 'l2_execution_proved'):
            self.assertIs(receipt[key], False)

    def test_retained_setup_matches_pinned_official_source(self):
        source = json.loads((EVIDENCE / 'trusted-setup-source.json').read_text())
        self.assertEqual(source['sha256'], TRUSTED_SETUP_SHA256)
        self.assertEqual(digest(EVIDENCE / 'trusted_setup.txt'), TRUSTED_SETUP_SHA256)

    def test_official_decoder_bodies_match_observed_span_counts(self):
        receipt = json.loads((EVIDENCE / 'official-codec-validation.json').read_text())
        archive = EVIDENCE / 'official-decoded-channel.json.gz'
        self.assertEqual(digest(archive), receipt['retained_gzip_sha256'])
        raw = gzip.decompress(archive.read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), receipt['decoded_channel_sha256'])
        channel = json.loads(raw)
        self.assertTrue(channel['is_ready'])
        self.assertFalse(channel['invalid_frames'])
        self.assertFalse(channel['invalid_batches'])
        blocks = [block for batch in channel['batches'] for block in batch['span_batch_elements']]
        self.assertEqual(len(blocks), 12)
        self.assertEqual(sum(len(b['Transactions']) for b in blocks), 2437)
        self.assertIs(receipt['transaction_bodies_decoded'], True)
        self.assertIs(receipt['l2_execution_proved'], False)
        self.assertEqual(receipt['unprotected_legacy_transactions'], 2)
        hashes = json.loads((EVIDENCE / 'official-decoded-transaction-hashes.json').read_text())
        self.assertEqual(hashlib.sha256(('\n'.join(hashes) + '\n').encode()).hexdigest(), receipt['transaction_hashes_sha256'])


if __name__ == '__main__':
    unittest.main()
