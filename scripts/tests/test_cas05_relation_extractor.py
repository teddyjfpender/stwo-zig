import unittest

from scripts.check_cas05_relation_extractor import (
    BATCH, CASCADE, INSERTION, RELATION, ROOT, WIRE, audit,
)


class Cas05RelationExtractorSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {
            path: (ROOT / path).read_text()
            for path in (RELATION, WIRE, BATCH, CASCADE, INSERTION)
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

    def test_own_quotient_power_order_cannot_change(self):
        changes = (
            ("pair[1] = power;", "pair[1] = QM31.one();"),
            ("const original = opened.at(height, query, j, col);",
             "const original = opened.at(height, query, j, 0);"),
            ("const quotient = numerator.mulCM31(inverse);",
             "const quotient = QM31.zero();"),
            (".add(pair[1].mul(quotient));",
             ".add(pair[0].mul(quotient));"),
        )
        for before, after in changes:
            with self.subTest(before=before):
                changed = dict(self.sources)
                changed[BATCH] = changed[BATCH].replace(before, after)
                self.assertTrue(audit(changed))

    def test_authenticated_batch_must_feed_folds(self):
        changed = dict(self.sources)
        changed[CASCADE] = changed[CASCADE].replace(
            "try verifyFolds(allocator, proof, raw, answers.values, alphas);",
            "try verifyFolds(allocator, proof, raw, fake_answers, alphas);",
        )
        self.assertTrue(audit(changed))

    def test_inserted_weight_and_order_cannot_change(self):
        changed = dict(self.sources)
        changed[INSERTION] = changed[INSERTION].replace(
            "return previous.add(alpha.square().mul(inserted));",
            "return inserted.add(alpha.square().mul(previous));",
        )
        self.assertTrue(audit(changed))

    def test_normalized_height_scaling_cannot_change(self):
        for before, after in (
            ("try inserted_even.div(scale),", "inserted_even,"),
            ("try previous[query * 2].div(scale),", "previous[query * 2],"),
            ("if (!folded.eql(two.mul(scale).mul(normalized)))",
             "if (!folded.eql(two.mul(normalized)))"),
            ("scale = scale.mul(two);", "scale = scale;"),
        ):
            with self.subTest(before=before):
                changed = dict(self.sources)
                changed[RELATION] = changed[RELATION].replace(before, after)
                self.assertTrue(audit(changed))


if __name__ == "__main__":
    unittest.main()
