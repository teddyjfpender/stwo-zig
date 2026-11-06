"""Compile-time threshold identities cannot inherit hidden environment state."""

import unittest

from opstack.build import bulk_environment


class BuildEnvironment(unittest.TestCase):
    def test_explicit_thresholds_and_ambient_cleanup(self):
        env, thresholds = bulk_environment(
            {
                "PATH": "test",
                "STWO_ADMITTED_COPY_MIN": "0",
                "STWO_ADMITTED_EXTRA": "bad",
            }
        )
        self.assertEqual(
            thresholds, {"COPY": "16", "UCOPY": "16", "SET": "16", "CMP": "8"}
        )
        self.assertEqual(env["PATH"], "test")
        self.assertNotIn("STWO_ADMITTED_EXTRA", env)
        for value in ["8", "1048576", "off"]:
            _, thresholds = bulk_environment({}, value)
            self.assertEqual(set(thresholds.values()), {value})
        for value in ["0", "7", "1048577", "-8", "", "1.5"]:
            with self.assertRaises(ValueError):
                bulk_environment({}, value)
