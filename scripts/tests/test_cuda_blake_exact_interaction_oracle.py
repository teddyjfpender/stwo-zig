from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Sequence

from scripts.tests.blake_exact_interaction_oracle import (
    P,
    QM31,
    base,
    batch_inverse,
    bit_reverse,
    build,
    columns_sha256,
    paired_fraction,
    synthetic_rows,
    weighted_negative_fraction,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = (
    ROOT / "tests/fixtures/cuda/blake_exact_interaction_log4.json"
)
NAMES = [
    "scheduler",
    "round_split_3",
    "round_split_1",
    "xor_12",
    "xor_9",
    "xor_8",
    "xor_7",
    "xor_4",
]
LOGS = [4, 7, 5, 16, 14, 12, 10, 8]
SECURE_WIDTHS = [6, 65, 65, 128, 8, 8, 8, 1]
PUBLIC_FROM_COMPONENT = [0, 3, 4, 5, 6, 7, 1, 2]
COMPONENT_FROM_PUBLIC = [0, 6, 7, 1, 2, 3, 4, 5]


class CudaBlakeExactInteractionOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_full_cpu_fixture_seals_all_mixed_height_components(self) -> None:
        self.assertEqual(1, self.fixture["schema_version"])
        components = self.fixture["components"]
        self.assertEqual(NAMES, [item["name"] for item in components])
        self.assertEqual(LOGS, [item["log_rows"] for item in components])
        self.assertEqual(
            SECURE_WIDTHS,
            [item["secure_columns"] for item in components],
        )
        self.assertEqual(
            [4 * width for width in SECURE_WIDTHS],
            [item["base_columns"] for item in components],
        )
        self.assertEqual(
            34_285_568,
            sum(
                item["base_columns"] * (1 << item["log_rows"])
                for item in components
            ),
        )
        self.assertEqual(
            len(components),
            len({item["trace_sha256"] for item in components}),
        )
        self.assertTrue(
            all(len(item["trace_sha256"]) == 64 for item in components)
        )
        relations = self.fixture["relations"]
        self.assertEqual(
            ["blake", "round", "xor_12", "xor_9", "xor_8", "xor_7", "xor_4"],
            [item["name"] for item in relations],
        )
        for relation in relations:
            self.assertEqual(4, len(relation["z"]))
            self.assertEqual(4, len(relation["alpha"]))
            self.assertNotEqual(relation["z"], relation["alpha"])
            self.assertTrue(
                all(
                    0 <= value < P
                    for value in relation["z"] + relation["alpha"]
                )
            )

    def test_claims_close_and_public_statement_mapping_is_exact(self) -> None:
        claims = [item["claim"] for item in self.fixture["components"]]
        self.assertEqual(
            [0, 0, 0, 0],
            [sum(claim[index] for claim in claims) % P for index in range(4)],
        )
        statement = self.fixture["statement1"]
        self.assertEqual(
            PUBLIC_FROM_COMPONENT,
            statement["public_order_from_component"],
        )
        self.assertEqual(
            COMPONENT_FROM_PUBLIC,
            statement["component_order_from_public"],
        )
        public = [claims[index] for index in PUBLIC_FROM_COMPONENT]
        recovered = [public[index] for index in COMPONENT_FROM_PUBLIC]
        self.assertEqual(claims, recovered)
        self.assertNotEqual(claims, public)

    def test_scalar_builder_matches_frozen_vectors_for_all_components(
        self,
    ) -> None:
        synthetic = self.fixture["synthetic_builder"]
        self.assertEqual(NAMES, [item["name"] for item in synthetic])
        for item in synthetic:
            rows = synthetic_rows(
                1 << item["log_rows"],
                item["secure_columns"],
                item["seed"],
            )
            columns, claim = build(rows)
            self.assertEqual(item["trace_sha256"], columns_sha256(columns))
            self.assertEqual(tuple(item["claim"]), claim.to_coordinates())

    def test_batch_inversion_and_pairing_identities_are_independent(self) -> None:
        denominators = [
            QM31.coordinates((index + 2, index * 3 + 5, index * 7 + 9, 11))
            for index in range(19)
        ]
        inverses = batch_inverse(denominators)
        for denominator, inverse in zip(
            denominators,
            inverses,
            strict=True,
        ):
            self.assertEqual(QM31.one(), denominator * inverse)

        p0 = denominators[3]
        p1 = denominators[11]
        pair = paired_fraction(p0, p1)
        pair_value = pair.numerator * pair.denominator.inverse()
        self.assertEqual(p0.inverse() + p1.inverse(), pair_value)
        self.assertNotEqual(
            pair_value,
            (p0 - p1) * pair.denominator.inverse(),
        )

        weighted = weighted_negative_fraction(p0, p1, 17, 29)
        weighted_value = (
            weighted.numerator * weighted.denominator.inverse()
        )
        self.assertEqual(
            -(base(17) * p0.inverse() + base(29) * p1.inverse()),
            weighted_value,
        )

    def test_prefix_and_tail_mutations_change_every_component_digest(
        self,
    ) -> None:
        for item in self.fixture["synthetic_builder"]:
            rows = synthetic_rows(
                1 << item["log_rows"],
                item["secure_columns"],
                item["seed"],
            )
            expected = item["trace_sha256"]
            no_shift, _ = build(rows, shift_tail=False)
            storage_order, _ = build(rows, prefix=storage_prefix)
            exclusive, _ = build(rows, prefix=exclusive_circle_prefix)
            self.assertNotEqual(expected, columns_sha256(no_shift))
            self.assertNotEqual(expected, columns_sha256(storage_order))
            self.assertNotEqual(expected, columns_sha256(exclusive))


def storage_prefix(values: Sequence[int]) -> list[int]:
    output: list[int] = []
    total = 0
    for value in values:
        total = (total + value) % P
        output.append(total)
    return output


def exclusive_circle_prefix(values: Sequence[int]) -> list[int]:
    circle = bit_reverse(values)
    coset: list[int] = []
    for index in range(len(circle) // 2):
        coset.extend((circle[index], circle[-1 - index]))
    total = 0
    for index, value in enumerate(coset):
        coset[index] = total
        total = (total + value) % P
    circle = [0] * len(coset)
    for index in range(len(circle) // 2):
        circle[index] = coset[2 * index]
        circle[-1 - index] = coset[2 * index + 1]
    return bit_reverse(circle)


if __name__ == "__main__":
    unittest.main()
