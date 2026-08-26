from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.typed_air_c013_capture_lib.codec import canonical_bytes
from scripts.typed_air_c013_capture_lib.journal import AttemptJournal
from scripts.typed_air_c013_capture_lib.model import CaptureError


class AttemptJournalTests(unittest.TestCase):
    def test_journal_is_append_only_durable_and_retains_empty_stderr(self) -> None:
        plan = {
            "session_id": "fixture",
            "content_sha256": "ab" * 32,
            "attempts": [{}, {}],
        }
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            journal = AttemptJournal(bundle, plan, canonical_bytes(plan))
            streams = journal.retain_attempt_streams(0, b'{"ok":true}\n', b"")
            self.assertEqual(streams["stderr"]["bytes"], 0)
            record = journal.append(
                {
                    "schema": "fixture-attempt-v1",
                    "global_ordinal": 0,
                    "streams": streams,
                }
            )
            self.assertRegex(record["content_sha256"], r"^[0-9a-f]{64}$")
            identity = journal.close()
            self.assertEqual(identity["records"], 2)
            self.assertEqual(identity["path"], "journal.ndjson")
            lines = (bundle / "journal.ndjson").read_bytes().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[1])["global_ordinal"], 0)
            self.assertEqual((bundle / "attempts/0000.stderr.bin").read_bytes(), b"")
            with self.assertRaisesRegex(CaptureError, "closed more than once"):
                journal.close()

    def test_existing_bundle_and_duplicate_attempt_stream_refuse_replacement(self) -> None:
        plan = {
            "session_id": "fixture",
            "content_sha256": "ab" * 32,
            "attempts": [{}],
        }
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            journal = AttemptJournal(bundle, plan, canonical_bytes(plan))
            journal.retain_attempt_streams(0, b"first", b"")
            with self.assertRaisesRegex(CaptureError, "refusing to replace"):
                journal.retain_attempt_streams(0, b"second", b"")
            journal.abandon()
            with self.assertRaisesRegex(CaptureError, "exclusive capture bundle"):
                AttemptJournal(bundle, plan, canonical_bytes(plan))


if __name__ == "__main__":
    unittest.main()
