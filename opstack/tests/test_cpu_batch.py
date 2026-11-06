"""Resident telemetry cannot change expected order or claim fresh acceptance."""

import copy
import unittest

from opstack.cpu import PROFILE
from opstack.cpu_batch import validate_index


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
