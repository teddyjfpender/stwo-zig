"""Authoritative focused-product source and linkage closure checks."""

from .graph import ClosureError, SourceGraph, inspect_sources
from .model import Manifest, NamedImport

__all__ = [
    "ClosureError",
    "Manifest",
    "NamedImport",
    "SourceGraph",
    "inspect_sources",
]
