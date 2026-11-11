"""Independent output authority and bounded offline verifier process controls."""
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

spec=importlib.util.spec_from_file_location('verify_export',Path(__file__).parents[1]/'capture_host/verify_export.py')
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)

class NativeExport(unittest.TestCase):
    def test_historical_public_output_and_independent_claim(self):
        pinned=json.loads((Path(__file__).parents[1]/'transition-159257842-receipt.json').read_text())
        s=pinned['statement'];claim={'anchor':{'number':s['anchor_number'],'hash':s['anchor_hash']},'previous_number':s['previous_number'],'previous_root':s['previous_root'],'next_number':s['next_number'],'next_root':s['next_root'],'next_origin':{'number':s['next_origin_number'],'hash':s['next_origin_hash']}}
        self.assertEqual(V.expected_statement(s,claim,s['block_hash']).hex(),pinned['od_public_output'])
        for field in s:
            bad=dict(s)
            if field=='payload_commitment':continue # independently recomputed by the native verifier
            bad[field]=bad[field]+1 if isinstance(bad[field],int) else ('bad' if field=='schema' else '00'*32)
            with self.subTest(field=field),self.assertRaises(ValueError):V.expected_statement(bad,claim,s['block_hash'])
        with self.assertRaises(ValueError):V.expected_statement(dict(s,extra=True),claim,s['block_hash'])

    def test_native_failure_and_expired_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);host=root/'host';host.write_text('#!/bin/sh\nexit 7\n');host.chmod(0o700)
            with self.assertRaisesRegex(ValueError,'deadline'):V.run_native(host,root/'a.opd',root/'reads',root,time.monotonic()-1)
            self.assertFalse((root/'a-stdout.json').exists())
            with self.assertRaisesRegex(ValueError,'rejected'):V.run_native(host,root/'a.opd',root/'reads',root,time.monotonic()+2)
            self.assertFalse((root/'verified.json').exists())
