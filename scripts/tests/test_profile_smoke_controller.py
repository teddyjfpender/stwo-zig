#!/usr/bin/env python3
"""Unit tests for the profile smoke controller."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.bench.profile_smoke_lib import controller


class ProfileSmokeControllerTests(unittest.TestCase):
    def test_each_profile_sample_retires_the_previous_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "proof.json"

            def publish(_cmd, _env):
                self.assertFalse(artifact.exists())
                artifact.write_text("proof", encoding="utf-8")
                return {"seconds": 1.0}

            with mock.patch.object(controller, "run_profiled_once", side_effect=publish):
                runs = controller.run_profiled_samples(
                    ["prover"],
                    repeats=3,
                    artifact_path=artifact,
                )

            self.assertEqual(len(runs), 3)
            self.assertTrue(artifact.exists())


if __name__ == "__main__":
    unittest.main()
