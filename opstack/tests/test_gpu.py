import json
import tempfile
import unittest
from pathlib import Path

from opstack import gpu


class ResidentCudaAdmissionTests(unittest.TestCase):
    def test_historical_heavy_shape_needs_two_scope_tables(self):
        evidence = (
            gpu.ROOT
            / "vectors/reports/rv64-opstack-cpu-20261107/heavy-mainnet-plan.json"
        )
        heavy = json.loads(evidence.read_text())
        census = {
            "schema": "rv64-native-plan-cost/v1",
            "proof_generated": False,
            "prefix_count": 0,
            "total_steps": heavy["total_steps"],
            "final_pc": heavy["final_pc"],
            "cpu": [None] * heavy["cpu_proofs_planned"],
        }
        endpoint = (heavy["total_steps"], heavy["final_pc"])
        self.assertEqual(gpu.census_coverage(census, *endpoint, [0]), (102, False))
        self.assertEqual(gpu.census_coverage(census, *endpoint, [0, 1]), (102, True))
        for altered in (
            dict(census, prefix_count=1),
            dict(census, total_steps=census["total_steps"] - 1),
            dict(census, final_pc=0),
        ):
            with self.assertRaisesRegex(ValueError, "complete independent execution"):
                gpu.census_coverage(altered, *endpoint, [0, 1])

    def test_resident_admission_cannot_fall_back_to_host_parked_main(self):
        preset = gpu.ROOT / "opstack/presets/cuda-resident-8workers.json"
        resources = gpu.resources_for(preset, 4)
        self.assertEqual(resources["schedule"]["lane_workers"], [2, 2, 2, 2])
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / "resources.json"
            altered.write_text(json.dumps(dict(resources, park_main=True)))
            with self.assertRaisesRegex(ValueError, "park_main=false"):
                gpu.resources_for(altered, 4)
