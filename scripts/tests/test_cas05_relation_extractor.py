import unittest

from scripts.check_cas05_relation_extractor import RELATION, ROOT, WIRE, audit


class Cas05RelationExtractorSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {
            path: (ROOT / path).read_text() for path in (RELATION, WIRE)
        }

    def test_pinned_sources(self):
        self.assertEqual([], audit(self.sources))

    def test_complete_verifier_cannot_be_skipped(self):
        changed = dict(self.sources)
        changed[RELATION] = changed[RELATION].replace(
            "try cascade.verifyAgainstStatement(a, proof, &staged, statement);",
            "// removed complete verifier",
        )
        self.assertTrue(audit(changed))

    def test_source_authentication_cannot_be_skipped(self):
        changed = dict(self.sources)
        changed[RELATION] = changed[RELATION].replace(
            "const opened = try xdm.verifyAndCollect(",
            "const opened = undefined; // removed source opening",
        )
        self.assertTrue(audit(changed))

    def test_line_authentication_cannot_be_skipped(self):
        changed = dict(self.sources)
        changed[RELATION] = changed[RELATION].replace(
            "try verifier.verify(a, rows, &columns, .{ .hash_witness = opening.hash_witness });",
            "// removed line opening",
        )
        self.assertTrue(audit(changed))

    def test_publishing_before_check_rejected(self):
        changed = dict(self.sources)
        changed[RELATION] = changed[RELATION].replace(
            "try relation.check(a);\n",
            "channel.* = staged;\n    try relation.check(a);\n",
        )
        self.assertTrue(audit(changed))

    def test_transcript_equality_cannot_be_skipped(self):
        changed = dict(self.sources)
        changed[RELATION] = changed[RELATION].replace(
            "if (!std.meta.eql(replay, staged))",
            "if (false)",
        )
        self.assertTrue(audit(changed))

    def test_fold_and_terminal_checks_cannot_be_skipped(self):
        for marker in (
            "if (!folded.eql(self.forwarded[height][query])) return error.InvalidFoldRelation;",
            "return error.InvalidTerminalRelation;",
        ):
            with self.subTest(marker=marker):
                changed = dict(self.sources)
                changed[RELATION] = changed[RELATION].replace(marker, "// removed relation check")
                self.assertTrue(audit(changed))

    def test_outer_wire_must_keep_decoder_alive_through_extraction(self):
        changed = dict(self.sources)
        changed[WIRE] = changed[WIRE].replace(
            "defer decoded.deinit();\n    return relation.verifyAndExtract",
            "decoded.deinit();\n    return relation.verifyAndExtract",
        )
        self.assertTrue(audit(changed))


if __name__ == "__main__":
    unittest.main()
