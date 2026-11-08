#!/usr/bin/env python3
"""Proof-independent source coverage for the four canonical SN PIEs."""
if __package__ in (None, ""):  # run as a file: make `scripts.*` importable
    __import__("sys").path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
from scripts.cairo.cairo_four_pie_source_coverage_lib.controller import main


if __name__ == "__main__":
    raise SystemExit(main())
