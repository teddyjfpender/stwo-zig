import copy
import unittest

from scripts import riscv_frontend_work_ledger as ledger


class FrontendWorkLedgerTest(unittest.TestCase):
    def fixture(self):
        families = [dict(name=name, authority_digest="12" * 32, main_columns=width,
                         direct_constraints=3, lookup_events=4,
                         compatibility_interaction_columns=8)
                    for name, width in (("alu", 10), ("memory", 20))]
        metadata = dict(schema="stwo.riscv.typed-encoding-work-metadata.v1",
                        proof_authority=False, families=families)
        segments = [dict(index=i, first_cycle=1 + 4 * i, entry_pc=100 + i,
                         exit_pc=101 + i, terminal="halt_flag" if i else None,
                         counts=dict(cycles=4, core_rows=3, families=[2, 1]))
                    for i in range(2)]
        summary = dict(schema="stwo-retained-ethereum-bounded-execution-census-v1",
                       scope="full_guest_execution_census_without_proving",
                       proof_verified=False, family_names=["alu", "memory"],
                       segments=2, segment_cycles=4, expected_cycles=8,
                       counts=dict(cycles=8, families=[4, 2]))
        return summary, segments, metadata

    def test_shard_boundaries_and_integer_domains(self):
        for count, expected in ((0, (0, 0)), (1, (1, 2)), (65535, (1, 65536)),
                                (65536, (1, 65536)), (65537, (2, 65538)),
                                (131073, (3, 131074))):
            self.assertEqual(expected, ledger.shard_geometry(count, 65536))
        for cap in (0, 1, 3, -1, True):
            with self.assertRaises(ValueError):
                ledger.shard_geometry(10, cap)

    def test_coalescing_preserves_work_population_and_width(self):
        summary, segments, metadata = self.fixture()
        families = ledger.validate(summary, segments, metadata)
        separate = ledger.account(segments, families, 1, 65536)
        combined = ledger.account(segments, families, 2, 65536)
        self.assertEqual([4, 2], [row["rows"] for row in combined])
        self.assertEqual([40, 80], [row["main_cells"] for row in separate])
        self.assertEqual([40, 40], [row["main_cells"] for row in combined])
        self.assertEqual([16, 8], [row["lookup_requests"] for row in combined])

    def test_reject_incomplete_reordered_or_inconsistent_census(self):
        mutations = (
            lambda s, r, m: r.reverse(),
            lambda s, r, m: r.pop(),
            lambda s, r, m: r[1].update(first_cycle=4),
            lambda s, r, m: r[1].update(entry_pc=900),
            lambda s, r, m: r[0].update(terminal="halt_flag"),
            lambda s, r, m: r[1].update(terminal=None),
            lambda s, r, m: r[1].update(terminal="unexpected_stop"),
            lambda s, r, m: r[0]["counts"].update(families=[True, 2]),
            lambda s, r, m: r[0]["counts"].update(core_rows=4),
            lambda s, r, m: s.update(expected_cycles=9),
            lambda s, r, m: m["families"].reverse(),
            lambda s, r, m: s.update(proof_verified=True),
            lambda s, r, m: m.update(proof_authority=True),
            lambda s, r, m: m["families"][0].update(candidate_main_columns=11),
        )
        for mutate in mutations:
            values = copy.deepcopy(self.fixture())
            mutate(*values)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                ledger.validate(*values)


if __name__ == "__main__":
    unittest.main()
