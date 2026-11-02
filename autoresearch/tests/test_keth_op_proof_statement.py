import copy
import hashlib
import struct
import unittest

from autoresearch.experiments.evm_keth.proof_statement import (
    PRIME, CANONICAL_CONFIG, program_claim, assert_program, assert_parameters,
)


class OpProofStatementTests(unittest.TestCase):
    def test_program_claim_word_encoding(self):
        compiled = dict(data=['0x0', hex(2**251), hex(PRIME - 1)])
        words = []
        for raw in compiled['data']:
            value = int(raw, 16)
            for _ in range(28):
                words.append(value % 512)
                value //= 512
        expected = dict(count=84, sha256_le=hashlib.sha256(struct.pack('<84I', *words)).hexdigest())
        self.assertEqual(program_claim(compiled), expected)
        assert_program(dict(program_len=3, program_claim_words=expected), compiled)
        with self.assertRaises(ValueError):
            assert_program(dict(program_len=3, program_claim_words=expected), dict(data=['0x1', hex(2**251), hex(PRIME - 1)]))

    def test_weak_or_different_protocol_rejects(self):
        proof = dict(stark_proof=dict(config=CANONICAL_CONFIG), channel_salt=0, preprocessed_trace_variant='canonical_small')
        assert_parameters(proof)
        assert_parameters({**proof, 'preprocessed_trace_variant': 'canonical'})
        with self.assertRaises(ValueError):
            assert_parameters({**proof, 'preprocessed_trace_variant': 'untrusted'})
        for field, value in [('pow_bits', 0), ('min_lifting_log_size', 1)]:
            changed = copy.deepcopy(proof)
            changed['stark_proof']['config'][field] = value
            with self.assertRaises(ValueError):
                assert_parameters(changed)
        for field, value in [('n_queries', 1), ('log_blowup_factor', 0), ('fold_step', 4)]:
            changed = copy.deepcopy(proof)
            changed['stark_proof']['config']['fri_config'][field] = value
            with self.assertRaises(ValueError):
                assert_parameters(changed)

    def test_noncanonical_program_cells_reject(self):
        for value in (-1, PRIME, True):
            with self.assertRaises(ValueError):
                program_claim(dict(data=[value]))


if __name__ == '__main__':
    unittest.main()
