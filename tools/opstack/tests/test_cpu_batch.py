"""Resident telemetry cannot change expected order or claim fresh acceptance."""

import copy
import unittest

from opstack.cpu import PROFILE
from opstack.cpu_batch import reports_from_stream, validate_index
from opstack.native_profiles import D2_NATIVE_PROFILE


class CpuResidentIndex(unittest.TestCase):
    def test_closed_order_profile_and_nonaccepting_index(self):
        names = ["120794432", "121057303"]
        index = {
            "schema": "rv64-cpu-resident-batch/v1",
            "security_profile": PROFILE,
            "security_qualified": False,
            "independent_reception": False,
            "requests": [
                {"ordinal": i, "repeat": i // 2, "name": names[i % 2], "wall_ns": i + 1}
                for i in range(4)
            ],
        }
        validate_index(index, names, 2)
        d2_index = {**index, "security_profile": D2_NATIVE_PROFILE}
        with self.assertRaises(ValueError):
            validate_index(d2_index, names, 2)
        validate_index(d2_index, names, 2, profile=D2_NATIVE_PROFILE)
        for key, value in [
            ("security_profile", "other"),
            ("security_qualified", True),
            ("independent_reception", True),
            ("requests", []),
        ]:
            bad = copy.deepcopy(index)
            bad[key] = value
            with self.assertRaises(ValueError):
                validate_index(bad, names, 2)
        for key, value in [
            ("name", "unrequested"),
            ("ordinal", 8),
            ("repeat", 0),
            ("wall_ns", True),
            ("wall_ns", -1),
        ]:
            bad = copy.deepcopy(index)
            bad["requests"][3][key] = value
            with self.assertRaises(ValueError):
                validate_index(bad, names, 2)


class ReceiverStreamTests(unittest.TestCase):
    def test_accepts_exact_count_of_complete_json_values(self):
        first = {"accepted": True, "ordinal": 0}
        second = {"accepted": True, "ordinal": 1}
        self.assertEqual(
            reports_from_stream(
                '{"accepted":true,"ordinal":0}\n  {"accepted":true,"ordinal":1}', 2
            ),
            [first, second],
        )
        for bad in ('{"accepted":true}', '{"accepted":true} {"accepted":', "{} {} {}"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                reports_from_stream(bad, 2)
