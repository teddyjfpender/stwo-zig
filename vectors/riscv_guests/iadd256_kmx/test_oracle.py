import hashlib
import unittest

import oracle


class OracleTests(unittest.TestCase):
    def test_fixture_shape_and_sha256(self):
        circuit = oracle.fixture()
        self.assertEqual(hashlib.sha256(circuit).hexdigest(), oracle.EXPECTED_SHA256)
        self.assertEqual(len(oracle.parse(circuit)), 2547)

    def test_first_and_last_batch_match_adder_relation(self):
        circuit = oracle.fixture()
        gates = oracle.parse(circuit)
        vectors = oracle.test_vectors(circuit, 9024)
        self.assertEqual(vectors[0][0].to_bytes(32, "little").hex(),
                         "d03c72e0d9b2d714381b4f91b45359b421749386473c66bb5bc8c60a70f45ecf")
        self.assertEqual(vectors[8960][0].to_bytes(32, "little").hex(),
                         "09cf8056e8bb5d7ea9a1adc0d76af2575e818a90e87ae33ae965ab7da02c5146")
        self.assertEqual(oracle.check_batch(gates, vectors, 4, 0)["shot_count"], 64)
        self.assertEqual(oracle.check_batch(gates, vectors, 4, 140)["shot_count"], 64)

    def test_changed_fixture_fails_pin(self):
        circuit = bytearray(oracle.fixture())
        circuit[-1] ^= 1
        self.assertNotEqual(hashlib.sha256(circuit).hexdigest(), oracle.EXPECTED_SHA256)

    def test_partial_batch_is_rejected(self):
        with self.assertRaises(ValueError):
            oracle.test_vectors(oracle.fixture(), 65)


if __name__ == "__main__":
    unittest.main()
