#!/usr/bin/env python3
"""Unit tests for focused/aggregate Native registry parity."""

from __future__ import annotations

import unittest

from scripts.check_registry_parity import native_applications


class RegistryParityTests(unittest.TestCase):
    def test_native_applications_excludes_released_frontend_adapters(self) -> None:
        registry = {
            "applications": [
                {
                    "air": "state_machine",
                    "status": "release_gated",
                    "backends": ["cpu"],
                },
                {
                    "adapter": "sail-rv32im-zkvm-elf",
                    "air": "sail_rv32im_zkvm_v1",
                    "status": "release_gated",
                    "backends": ["cpu"],
                },
            ]
        }

        self.assertEqual(
            [
                {
                    "air": "state_machine",
                    "status": "release_gated",
                    "cpu": True,
                }
            ],
            native_applications(registry),
        )


if __name__ == "__main__":
    unittest.main()
