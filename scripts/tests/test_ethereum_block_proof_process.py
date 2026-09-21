from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from scripts import ethereum_block_proof_process as subject
from scripts import ethereum_block_proof_protocol as protocol


def executable(path: Path, source: str) -> dict:
    path.write_text("#!/usr/bin/env python3\n" + source)
    path.chmod(0o700)
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


class EthereumBlockProofProcessTests(unittest.TestCase):
    def test_clean_process_has_exact_empty_transport_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tool = root / "tool"
            identity = executable(tool, "raise SystemExit(0)\n")
            receipt = subject.run_process(
                [str(tool), "clean"], identity, "proof_producer", 2, cwd=root,
            )
            self.assertEqual(receipt["exit_code"], 0)
            self.assertEqual(receipt["stdout_bytes"], 0)
            self.assertEqual(receipt["stderr_bytes"], 0)

    def test_wrapper_exit_with_surviving_descendant_is_killed_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tool = root / "tool"
            pid_path = root / "descendant.pid"
            identity = executable(tool, (
                "import pathlib, subprocess, sys\n"
                f"pid_path = pathlib.Path({str(pid_path)!r})\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(60)'])\n"
                "pid_path.write_text(str(child.pid))\n"
            ))
            with self.assertRaisesRegex(protocol.ProofProtocolError, "live descendant"):
                subject.run_process(
                    [str(tool), "descendant"], identity, "proof_producer", 2,
                    cwd=root,
                )
            pid = int(pid_path.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_timeout_terminates_the_whole_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tool = root / "tool"
            identity = executable(tool, "import time\ntime.sleep(60)\n")
            with self.assertRaisesRegex(protocol.ProofProtocolError, "timed out"):
                subject.run_process(
                    [str(tool), "timeout"], identity, "fresh_verifier", 1, cwd=root,
                )

    def test_transport_is_file_backed_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            tool = root / "tool"
            identity = executable(
                tool, f"import os\nos.write(1, b'x' * {subject.MAX_TRANSPORT_BYTES + 1})\n",
            )
            with self.assertRaisesRegex(protocol.ProofProtocolError, "transport bound"):
                subject.run_process(
                    [str(tool), "output"], identity, "proof_producer", 2, cwd=root,
                )


if __name__ == "__main__":
    unittest.main()
