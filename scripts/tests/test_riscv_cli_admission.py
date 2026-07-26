from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_cli_admission as admission


def registry(*, promoted: bool, focused: bool = False) -> dict[str, object]:
    released = {
        "adapter": admission.ADAPTER,
        "air": admission.AIR,
        "status": "release_gated",
        "isa": admission.ISA,
        "backends": ["cpu"],
    }
    deferred = {
        "adapter": admission.ADAPTER,
        "status": "not_release_gated",
        "isa": admission.ISA,
        "backends": ["cpu"],
        "reason": "release contract pending",
    }
    result = {
        "schema_version": 1,
        "backend_availability": {"cpu": True, "metal-hybrid": False},
        "product_matrix": {},
        "applications": [released] if promoted else [],
        "deferred_adapters": [] if promoted else [deferred],
    }
    if focused:
        result["deferred_adapters"] = [
            {**entry, "air": admission.AIR}
            for entry in result["deferred_adapters"]
        ]
        result["backend_availability"] = {"cpu": True}
        result["product"] = {
            "schema_version": 2,
            "name": "stwo-riscv-cpu",
            "frontend": "sail-rv32im-zkvm",
            "backend": "cpu",
            "role": "cli",
            "protocol_features": "rv32im-zkvm-v1+sail-authoritative+lifted-pcs-v1",
            "protocol_manifest_sha256": "1" * 64,
            "identity_sha256": "2" * 64,
            "source": {},
            "zig_version": "0.15.2",
            "target": {},
            "optimize": "ReleaseFast",
            "runtime": {},
        }
        del result["product_matrix"]
    return result


class AdmissionContractTests(unittest.TestCase):
    def test_candidate_requires_the_experimental_flag(self) -> None:
        value = admission.parse(json.dumps(registry(promoted=False)))
        self.assertEqual("candidate", value.phase)
        self.assertEqual("not_release_gated", value.release_status)
        self.assertIs(value.experimental, True)
        self.assertEqual(("--experimental",), value.arguments)

    def test_promoted_forbids_the_experimental_flag(self) -> None:
        value = admission.parse(json.dumps(registry(promoted=True)))
        self.assertEqual("promoted", value.phase)
        self.assertEqual("release_gated", value.release_status)
        self.assertIs(value.experimental, False)
        self.assertEqual((), value.arguments)

    def test_focused_product_registry_is_an_equivalent_authority(self) -> None:
        for promoted in (False, True):
            aggregate = admission.parse(json.dumps(registry(promoted=promoted)))
            focused = admission.parse(json.dumps(registry(
                promoted=promoted, focused=True,
            )))
            self.assertEqual(aggregate, focused)

    def test_focused_product_identity_is_exact(self) -> None:
        payload = registry(promoted=False, focused=True)
        payload["product"]["frontend"] = "native-examples"
        with self.assertRaisesRegex(admission.AdmissionError, "identity drifted"):
            admission.parse(json.dumps(payload))

    def test_duplicate_adapter_placement_fails_closed(self) -> None:
        payload = registry(promoted=True)
        payload["deferred_adapters"] = registry(promoted=False)["deferred_adapters"]
        with self.assertRaisesRegex(admission.AdmissionError, "exactly one"):
            admission.parse(json.dumps(payload))

    def test_malformed_promoted_entry_fails_closed(self) -> None:
        payload = registry(promoted=True)
        payload["applications"][0]["status"] = "not_release_gated"
        with self.assertRaisesRegex(admission.AdmissionError, "declaration drifted"):
            admission.parse(json.dumps(payload))

    def test_duplicate_json_fields_fail_closed(self) -> None:
        with self.assertRaisesRegex(admission.AdmissionError, "repeats JSON field"):
            admission.parse('{"schema_version":1,"schema_version":1}')

    def test_resolve_uses_the_exact_cli_and_rejects_stderr(self) -> None:
        completed = subprocess.CompletedProcess(
            ["candidate", "applications"], 0,
            json.dumps(registry(promoted=True)).encode(), b"",
        )
        with mock.patch.object(subprocess, "run", return_value=completed) as run:
            value = admission.resolve(Path("candidate"), cwd=Path("repo"))
        self.assertEqual("promoted", value.phase)
        run.assert_called_once_with(
            ["candidate", "applications"], cwd=Path("repo"), check=False,
            capture_output=True, timeout=30,
        )
        completed.stderr = b"warning\n"
        with mock.patch.object(subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(admission.AdmissionError, "unexpected stderr"):
                admission.resolve(Path("candidate"))


if __name__ == "__main__":
    unittest.main()
