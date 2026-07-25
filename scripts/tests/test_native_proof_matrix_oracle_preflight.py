from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from scripts.native_proof_matrix_lib import artifacts, controller
from scripts.native_proof_matrix_lib.model import (
    AIR_PROTOCOLS,
    INTEROP_UPSTREAM_COMMIT,
    MatrixError,
    RUST_ORACLE_CAPABILITY_PROTOCOL,
    RUST_ORACLE_SHA256,
)


def capability_manifest() -> dict[str, object]:
    return {
        "schema_version": 1,
        "protocol": RUST_ORACLE_CAPABILITY_PROTOCOL,
        "upstream_commit": INTEROP_UPSTREAM_COMMIT,
        "exact_air_protocols": {
            "poseidon": AIR_PROTOCOLS["poseidon"],
            "state_machine": AIR_PROTOCOLS["state_machine"],
            "xor": AIR_PROTOCOLS["xor"],
        },
    }


class NativeProofMatrixOraclePreflightTests(unittest.TestCase):
    def test_exact_state_adapter_capability_is_required(self) -> None:
        binary = Path("/tmp/pinned-rust-oracle")
        completed = subprocess.CompletedProcess(
            args=[str(binary), "--mode", "capabilities"],
            returncode=0,
            stdout=json.dumps(capability_manifest()).encode(),
            stderr=b"",
        )
        with (
            mock.patch.object(artifacts, "require_binary", return_value=binary),
            mock.patch.object(
                artifacts,
                "sha256_file",
                return_value=RUST_ORACLE_SHA256,
            ),
            mock.patch.object(artifacts.subprocess, "run", return_value=completed),
        ):
            self.assertEqual(
                artifacts.preflight_rust_oracle_adapter(binary, 5.0),
                capability_manifest(),
            )

        stale = subprocess.CompletedProcess(
            args=[str(binary), "--mode", "capabilities"],
            returncode=1,
            stdout=b"",
            stderr=b"invalid mode capabilities",
        )
        with (
            mock.patch.object(artifacts, "require_binary", return_value=binary),
            mock.patch.object(
                artifacts,
                "sha256_file",
                return_value=RUST_ORACLE_SHA256,
            ),
            mock.patch.object(artifacts.subprocess, "run", return_value=stale),
            self.assertRaisesRegex(MatrixError, "required exact AIR adapter"),
        ):
            artifacts.preflight_rust_oracle_adapter(binary, 5.0)

    def test_preflight_runs_before_benchmark_binary_admission(self) -> None:
        args = SimpleNamespace(
            rust_oracle_bin=Path("/tmp/pinned-rust-oracle"),
            timeout_seconds=5.0,
            cpu_bin=Path("/tmp/cpu"),
            metal_bin=Path("/tmp/metal"),
        )
        with (
            mock.patch.object(controller, "require_unprofiled_environment"),
            mock.patch.object(
                controller,
                "require_binary",
                return_value=args.rust_oracle_bin,
            ) as require_binary,
            mock.patch.object(
                controller,
                "preflight_rust_oracle_adapter",
                side_effect=MatrixError("stale exact AIR adapter"),
            ),
            self.assertRaisesRegex(MatrixError, "stale exact AIR adapter"),
        ):
            controller.run_matrix(args)
        require_binary.assert_called_once_with(args.rust_oracle_bin, "Rust oracle")


if __name__ == "__main__":
    unittest.main()
