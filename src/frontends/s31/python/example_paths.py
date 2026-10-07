"""Find named example fixtures after grouping them by subject.

This helper is for documentation, tests, and benchmarks. Production packages
receive explicit source paths and never resolve a fixture by name.
"""

from pathlib import Path


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def example_path(filename: str) -> Path:
    if not filename or Path(filename).name != filename or filename in {".", ".."}:
        raise ValueError(f"expected an example filename: {filename!r}")
    matches = [folder / filename for folder in EXAMPLES.iterdir()
               if folder.is_dir() and (folder / filename).is_file()]
    if len(matches) != 1:
        raise FileNotFoundError(f"expected one example named {filename!r}; found {len(matches)}")
    return matches[0]
