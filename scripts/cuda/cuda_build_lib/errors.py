"""Shared fail-closed CUDA build errors."""


class BuildError(RuntimeError):
    """A deterministic CUDA build or source-closure rejection."""
