"""Tests for the Team B production-AIR witness cross-check."""

from __future__ import annotations

import unittest

from scripts.tests._riscv_team_b_witnesses_arithmetic_tests import (
    DivisionWitnessTest,
    MultiplyAndShiftWitnessTest,
    RegisterShiftWitnessTest,
    RemainderWitnessTest,
)
from scripts.tests._riscv_team_b_witnesses_core_tests import (
    EvaluatorTest,
    ExportProvenanceTest,
    MutationBatteryTest,
    SchemaAuditTest,
)
from scripts.tests._riscv_team_b_witnesses_memory_tests import (
    AddressAliasingRegressionTest,
    LoadHalfwordWitnessTest,
    PerOpcodeLoadWitnessTest,
    StoreWitnessTest,
)
from scripts.tests._riscv_team_b_witnesses_support import (
    EXPORT_DIRECTORY,
    REPOSITORY_ROOT,
    export_air,
)

_TEST_CASES = (
    AddressAliasingRegressionTest,
    DivisionWitnessTest,
    EvaluatorTest,
    ExportProvenanceTest,
    LoadHalfwordWitnessTest,
    MultiplyAndShiftWitnessTest,
    MutationBatteryTest,
    PerOpcodeLoadWitnessTest,
    RegisterShiftWitnessTest,
    RemainderWitnessTest,
    SchemaAuditTest,
    StoreWitnessTest,
)
for _test_case in _TEST_CASES:
    _test_case.__module__ = __name__
del _test_case, _TEST_CASES


if __name__ == "__main__":
    unittest.main()
