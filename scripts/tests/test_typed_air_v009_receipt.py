from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.typed_air_r006_capture_lib.codec import canonical_bytes, content_digest
from scripts.typed_air_v009_receipt import (
    REQUIRED_ARTIFACTS,
    ReceiptError,
    mint_receipt,
    validate_receipt,
)


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "1" * 40
TREE = "2" * 40


class V009ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in REQUIRED_ARTIFACTS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((relative + "\n").encode("ascii"))
        self.log = self.root / "multilevel.log"
        self.log.write_text(
            "SEGMENT_V2_OUTER status=verified rows=39 domains=47 "
            "proof_size_estimate_bytes=1 canonical_proof_bytes=90000 "
            "canonicalize_ms=1.000 prove_ms=2.000 verify_ms=3.000 "
            "publication_ms=1.000 draws=1 cols=1/1/1 workers=1\n" * 4 +
            "TEMPORAL_PARENT_REAL_PROOF bytes=94731 prove_ms=4.000 "
            "verify_ms=5.000 rows=36 pair_poseidon=0\n" +
            "TEMPORAL_PARENT_REAL_PROOF bytes=94732 prove_ms=4.100 "
            "verify_ms=5.100 rows=36 pair_poseidon=0\n" +
            "TEMPORAL_MULTILEVEL_REAL leaves=4 verified_parents=2 "
            "root_height=2 parent_bytes=189463 root_bytes=93507 "
            "root_prove_ms=11071.974 root_verify_ms=4842.995 "
            f"root_sha256={'3' * 64} root_proof=true\n" +
            "      120.25 real 100.00 user 10.00 sys\n" +
            "  123456789 maximum resident set size\n",
            encoding="ascii",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _run(workflow: str, ordinal: int) -> dict[str, object]:
        return {
            "workflow": workflow,
            "run_id": ordinal,
            "head_sha": COMMIT,
            "conclusion": "success",
            "url": f"https://github.com/teddyjfpender/stwo-zig/actions/runs/{ordinal}",
        }

    def _receipt(self) -> dict[str, object]:
        workflows = (
            "CI",
            "RISC-V formal refinement",
            "RISC-V Sail differential",
            "RISC-V Sail formal provisioning",
        )
        runs = [self._run(workflow, index + 1) for index, workflow in enumerate(workflows)]

        def git(_root: Path, *arguments: str) -> str:
            if arguments[0] == "status":
                return ""
            if arguments[:2] == ("branch", "--show-current"):
                return "main"
            if arguments[:2] == ("rev-parse", "HEAD"):
                return COMMIT
            if arguments[:2] == ("rev-parse", f"{COMMIT}^{{tree}}"):
                return TREE
            raise AssertionError(arguments)

        with (
            mock.patch("scripts.typed_air_v009_receipt._git", side_effect=git),
            mock.patch(
                "scripts.typed_air_v009_receipt._github_run", side_effect=runs
            ),
            mock.patch(
                "scripts.typed_air_v009_receipt._tool_version", return_value="0.15.2"
            ),
            mock.patch("platform.python_version", return_value="3.14.6"),
            mock.patch("platform.system", return_value="Darwin"),
            mock.patch("platform.machine", return_value="arm64"),
        ):
            return mint_receipt(self.root, "HEAD", ["1", "2", "3", "4"], self.log)

    def _write(self, receipt: dict[str, object], name: str = "receipt.json") -> Path:
        path = self.root / name
        path.write_bytes(canonical_bytes(receipt))
        return path

    def test_mint_and_replay_bind_clean_main_artifacts_and_height_two(self) -> None:
        receipt = self._receipt()
        self.assertEqual(receipt["recursion"]["root_height"], 2)
        self.assertEqual(receipt["recursion"]["root_proof_bytes"], 93507)
        self.assertEqual(receipt["recursion"]["peak_rss_bytes"], 123456789)
        self.assertEqual(
            receipt["recursion"]["crossover"]["direct_leaf_proof_bytes"],
            360000,
        )
        self.assertFalse(receipt["claim_boundary"]["proof_system_soundness"])
        with mock.patch(
            "scripts.typed_air_v009_receipt._git", return_value=TREE
        ):
            self.assertEqual(validate_receipt(self.root, self._write(receipt)), receipt)

    def test_mutations_and_noncanonical_encoding_fail_closed(self) -> None:
        receipt = self._receipt()
        mutations = (
            ("run", lambda value: value["hosted_runs"][0].__setitem__("head_sha", "4" * 40)),
            ("artifact", lambda value: value["artifacts"][0].__setitem__("bytes", 0)),
            ("security", lambda value: value["recursion"].__setitem__("target_security_bits", 128)),
            ("claim", lambda value: value["claim_boundary"].__setitem__("proof_system_soundness", True)),
        )
        for name, mutate in mutations:
            changed = copy.deepcopy(receipt)
            mutate(changed)
            changed["content_sha256"] = content_digest(changed)
            with self.subTest(name=name), mock.patch(
                "scripts.typed_air_v009_receipt._git", return_value=TREE
            ), self.assertRaises(ReceiptError):
                validate_receipt(self.root, self._write(changed, f"{name}.json"))

        pretty = self.root / "pretty.json"
        pretty.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        with mock.patch(
            "scripts.typed_air_v009_receipt._git", return_value=TREE
        ), self.assertRaisesRegex(ReceiptError, "canonical JSON"):
            validate_receipt(self.root, pretty)

    def test_mint_rejects_dirty_source_incomplete_runs_and_ambiguous_log(self) -> None:
        with mock.patch(
            "scripts.typed_air_v009_receipt._git", return_value="dirty"
        ), self.assertRaisesRegex(ReceiptError, "clean worktree"):
            mint_receipt(self.root, "HEAD", ["1", "2", "3", "4"], self.log)

        self.log.write_text(self.log.read_text() * 2, encoding="ascii")
        receipt = self._receipt
        with self.assertRaisesRegex(ReceiptError, "exactly one terminal"):
            receipt()


if __name__ == "__main__":
    unittest.main()
