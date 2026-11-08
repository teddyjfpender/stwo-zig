#!/usr/bin/env python3
"""Run authority-owned Python tests against candidate-owned implementation modules."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import unittest
from pathlib import Path


AUTHORITY_ROOT = Path(__file__).resolve().parents[1]


class AuthorityTestError(ValueError):
    pass


def _test_path(module: str) -> Path:
    prefix = "scripts.tests."
    if not module.startswith(prefix):
        raise AuthorityTestError(f"authority test module is outside scripts.tests: {module}")
    relative = module.removeprefix(prefix).replace(".", "/") + ".py"
    path = (AUTHORITY_ROOT / "scripts/tests" / relative).resolve()
    if not path.is_relative_to((AUTHORITY_ROOT / "scripts/tests").resolve()):
        raise AuthorityTestError(f"authority test path escapes test root: {module}")
    if not path.is_file():
        raise AuthorityTestError(f"authority test module is missing: {module}")
    return path


def run(candidate_root: Path, modules: list[str]) -> unittest.result.TestResult:
    candidate_root = candidate_root.resolve(strict=True)
    os.environ["STWO_ZIG_EXECUTION_ROOT"] = str(candidate_root)
    sys.path.insert(0, str(candidate_root))
    suite = unittest.TestSuite()
    for index, module in enumerate(modules):
        path = _test_path(module)
        spec = importlib.util.spec_from_file_location(f"_authority_test_{index}", path)
        if spec is None or spec.loader is None:
            raise AuthorityTestError(f"cannot load authority test: {module}")
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(loaded))
    return unittest.TextTestRunner(verbosity=2).run(suite)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("modules", nargs="+")
    args = parser.parse_args(argv)
    try:
        result = run(args.candidate_root, args.modules)
    except (OSError, AuthorityTestError) as error:
        print(f"architecture authority tests: FAIL: {error}", file=sys.stderr)
        return 2
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
