from __future__ import annotations

import copy
import hashlib
import unittest

from scripts.benchmark_product_contract_lib import (
    ProductEvidenceError,
    build_receipt,
    validate_receipt,
)
from scripts.tests import test_benchmark_product_contract as support
from scripts.tests.native_proof_matrix_support import product_identity


class ExactAirBenchmarkProductContractTests(unittest.TestCase):
    def test_receipt_binds_exact_state_machine_geometry_and_identity(self) -> None:
        state = support.measurement()
        parameters = {"log_n_rows": 5, "initial_x": 9, "initial_y": 3}
        state["workload"] = {
            "name": "state_machine",
            "parameters": parameters,
            "trace_log_rows": 5,
            "trace_rows": 32,
            "committed_trees": 3,
            "committed_columns": 12,
            "committed_trace_cells": 288,
            "native_unit": "state_transitions",
            "native_units": 48,
            "descriptor_sha256": support.functional_descriptor(
                "state_machine",
                parameters,
            ),
        }
        state["numerator"] = {"unit": "state_transitions", "units": 48}
        identity = product_identity("cpu")
        host_device = {"machine": "test"}
        receipt = build_receipt(
            lane="cpu",
            evidence_kind="benchmark",
            product_identity=identity,
            executable_sha256="6" * 64,
            measurement_policy=support.benchmark_policy(),
            host_device=host_device,
            measurements=[state],
            promotion_eligible=True,
        )
        validate_receipt(
            receipt,
            lane="cpu",
            evidence_kind="benchmark",
            expected_identity=identity,
            expected_executable_sha256="6" * 64,
            expected_host_device=host_device,
        )

        mutations = (
            ("committed_trees", 2),
            ("committed_columns", 3),
            ("committed_trace_cells", 96),
            ("native_units", 32),
        )
        for field, value in mutations:
            changed = copy.deepcopy(receipt)
            changed["measurements"][0]["workload"][field] = value
            if field == "native_units":
                changed["measurements"][0]["numerator"]["units"] = value
            support.resign(changed)
            with self.subTest(field=field), self.assertRaises(ProductEvidenceError):
                validate_receipt(
                    changed,
                    lane="cpu",
                    evidence_kind="benchmark",
                    expected_identity=identity,
                    expected_executable_sha256="6" * 64,
                    expected_host_device=host_device,
                )

        stale_descriptor = copy.deepcopy(receipt)
        descriptor_fields = [
            "native-proof-workload-v3",
            "example=state_machine",
            "log_n_rows=5",
            "initial_x=9",
            "initial_y=3",
            "protocol=functional",
            "pow_bits=10",
            "log_blowup_factor=1",
            "log_last_layer_degree_bound=0",
            "n_queries=3",
            "fold_step=1",
        ]
        stale_descriptor["measurements"][0]["workload"]["descriptor_sha256"] = (
            hashlib.sha256("|".join(descriptor_fields).encode("ascii")).hexdigest()
        )
        support.resign(stale_descriptor)
        with self.assertRaisesRegex(ProductEvidenceError, "descriptor is inconsistent"):
            validate_receipt(
                stale_descriptor,
                lane="cpu",
                evidence_kind="benchmark",
                expected_identity=identity,
                expected_executable_sha256="6" * 64,
                expected_host_device=host_device,
            )

        oversized = copy.deepcopy(receipt)
        oversized["measurements"][0]["workload"]["trace_log_rows"] = 64
        oversized["measurements"][0]["workload"]["parameters"]["log_n_rows"] = 64
        support.resign(oversized)
        with self.assertRaisesRegex(ProductEvidenceError, "exceeds the product limit"):
            validate_receipt(
                oversized,
                lane="cpu",
                evidence_kind="benchmark",
                expected_identity=identity,
                expected_executable_sha256="6" * 64,
                expected_host_device=host_device,
            )


if __name__ == "__main__":
    unittest.main()
