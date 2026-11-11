"""Reusable Metal profile event parser and aggregator."""

from .report import ProfileError, build_report, format_text, load_events, main

__all__ = ["ProfileError", "build_report", "format_text", "load_events", "main"]
