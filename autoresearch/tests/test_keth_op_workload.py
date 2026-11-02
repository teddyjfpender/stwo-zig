"""Real OP consensus-encoding and workload-boundary regressions.

Run with the pinned Keth Python environment used by check_op_workload.py.
"""
from __future__ import annotations

import copy
from pathlib import Path
import unittest

from autoresearch.experiments.evm_keth.check_op_workload import check, check_block, load
from autoresearch.experiments.evm_keth.op_encoding import isthmus_l1_info, op_transaction_bytes, receipt_bytes

EVIDENCE = Path(__file__).resolve().parents[1] / 'experiments/evm_keth/evidence/2026-10-29-m5-max'
BLOCKS = EVIDENCE / 'base-historical-blocks'
BATCH = EVIDENCE / 'base-l1-batch'


class OpWorkloadTests(unittest.TestCase):
    def fixtures(self):
        directory = BLOCKS / '31028358'
        return [load(directory / (name + '.gz'))['result'] for name in
                ('block.json', 'parent.json', 'receipts.json', 'independent-block.json')]

    def test_entire_recovered_channel_matches_headers_roots_receipts_and_l1_origins(self):
        result = check(BATCH / 'official-decoded-channel.json.gz', BLOCKS,
                       BATCH / 'official-rollup-config.json', BLOCKS / 'l1-origins')
        self.assertEqual(result['l2_blocks'], 12)
        self.assertEqual(result['sequencer_transactions'], 2437)
        self.assertEqual(result['total_gas_used'], 826763923)
        self.assertEqual(sum(b['failed_transactions'] for b in result['blocks']), 101)
        for key in ('consensus_authenticated', 'dynamic_batcher_authorization_verified',
                    'op_stack_derivation_proved', 'l2_execution_proved', 'ethereum_settlement_compatible'):
            self.assertIs(result[key], False)

    def test_tampered_transaction_receipt_and_header_inputs_rejected(self):
        for mutation in ('header', 'deposit', 'receipt', 'gas', 'order', 'independent', 'metadata'):
            with self.subTest(mutation=mutation):
                b, parent, receipts, other = copy.deepcopy(self.fixtures())
                if mutation == 'header':
                    b['stateRoot'] = '0x' + '00' * 32
                elif mutation == 'deposit':
                    b['transactions'][0]['mint'] = '0x1'
                elif mutation == 'receipt':
                    receipts[1]['status'] = '0x0' if receipts[1]['status'] == '0x1' else '0x1'
                elif mutation == 'gas':
                    receipts[1]['gasUsed'] = '0x0'
                elif mutation == 'order':
                    b['transactions'][1:3] = reversed(b['transactions'][1:3])
                elif mutation == 'independent':
                    other['transactions'][1] = '0x' + '00' * 32
                else:
                    receipts[1]['blockNumber'] = '0x1'
                with self.assertRaises(ValueError):
                    check_block(b, parent, receipts, other)

    def test_l1_info_source_domain_and_envelope_are_checked(self):
        tx = self.fixtures()[0]['transactions'][0]
        info = isthmus_l1_info(tx)
        self.assertEqual(info['number'], 22615228)
        self.assertEqual(info['sequence_number'], 4)
        for field, value in [('sourceHash', '0x' + '00' * 32), ('gas', '0x1'),
                             ('from', '0x' + '00' * 20), ('isSystemTx', True),
                             ('input', tx['input'] + '00')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                isthmus_l1_info(dict(tx, **{field: value}))

    def test_deposit_rpc_nonce_is_not_in_wire_transaction(self):
        # Regolith nonce belongs to the receipt, and is not an eighth deposit
        # transaction field. It must never accidentally alter transaction hashes.
        tx = self.fixtures()[0]['transactions'][0]
        self.assertEqual(op_transaction_bytes(tx), op_transaction_bytes(dict(tx, nonce='0xdead')))
        receipt = self.fixtures()[2][0]
        self.assertNotEqual(receipt_bytes(receipt), receipt_bytes(dict(receipt, depositNonce='0xdead')))
        with self.assertRaises(ValueError):
            receipt_bytes(dict(receipt, depositReceiptVersion='0x2'))


if __name__ == '__main__':
    unittest.main()
