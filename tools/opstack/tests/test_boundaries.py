import copy
import tarfile
import unittest

from opstack.capture import validate_capture
from opstack.prepare_fixtures import MAX_EXPANDED, MAX_MEMBERS, validate_members


def member(path, size=0, kind=tarfile.REGTYPE):
    value = tarfile.TarInfo(path)
    value.size, value.type = size, kind
    return value


class ArchiveBoundaries(unittest.TestCase):
    def test_single_root_and_regular_files_are_admitted(self):
        rows = [
            member("block", kind=tarfile.DIRTYPE),
            member("block/kv/000001.sst", 123),
        ]
        self.assertEqual(validate_members(rows), rows)

    def test_traversal_absolute_links_and_multiple_roots_reject(self):
        cases = [
            [member("/tmp/escape")],
            [member("block/../escape")],
            [member("block/link", kind=tarfile.SYMTYPE)],
            [member("block/hard", kind=tarfile.LNKTYPE)],
            [member("block/pipe", kind=tarfile.FIFOTYPE)],
            [member("one/file"), member("two/file")],
            [member("block/file"), member("block/file")],
            [member("block/file", -1)],
        ]
        for rows in cases:
            with (
                self.subTest(rows=[r.name for r in rows]),
                self.assertRaises(ValueError),
            ):
                validate_members(rows)

    def test_uncompressed_size_and_member_count_reject_before_extraction(self):
        with self.assertRaises(ValueError):
            validate_members([member("block/huge", MAX_EXPANDED + 1)])
        with self.assertRaises(ValueError):
            validate_members([member(f"block/{n}") for n in range(MAX_MEMBERS + 1)])


class CaptureBoundaries(unittest.TestCase):
    def setUp(self):
        self.report = {
            "security_qualified": False,
            "capture_source": "in_process_execution",
            "total_steps": 100,
            "final_pc": 4096,
            "captured_values_sha256": "ab" * 32,
        }

    def test_complete_capture_digest_is_returned_without_proof_acceptance(self):
        self.assertEqual(validate_capture(self.report, 100, 4096), "ab" * 32)

    def test_prefix_other_terminal_and_missing_or_noncanonical_digest_reject(self):
        for key, value in [
            ("total_steps", 99),
            ("final_pc", 4100),
            ("security_qualified", True),
            ("capture_source", "packet_directory"),
            ("captured_values_sha256", "AB" * 32),
            ("captured_values_sha256", "ab"),
        ]:
            report = copy.deepcopy(self.report)
            report[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_capture(report, 100, 4096)


if __name__ == "__main__":
    unittest.main()
