"""Product catalog fixtures for focused CI policy tests."""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile


@contextmanager
def git_repository(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        for arguments in (("init", "-q", "--template="), ("add", "."), ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture")):
            subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True)
        yield root

PROVER_PREFIXES = ("src/core", "src/backend", "src/prover", "src/prover_api")


def product(scope: str, *prefixes: str, state: str = "released") -> dict[str, object]:
    return {
        "scope": scope,
        "state": state,
        "module_roots": [],
        "allowed_files": [],
        "configure_allowed_files": [],
        "allowed_prefixes": list(prefixes),
        "configure_allowed_prefixes": [],
    }


def catalog_fixture() -> dict[str, object]:
    return {
        "schema": "stwo-product-catalog-v2",
        "products": [
            product(
                "aggregate",
                *PROVER_PREFIXES,
                "src/backends/cpu_scalar",
                "src/frontends/riscv",
                "src/integrations/riscv_cpu",
            ),
            product("core", "src/core"),
            product("prover", *PROVER_PREFIXES),
            product(
                "native_cpu",
                *PROVER_PREFIXES,
                "src/backends/cpu_scalar",
                "src/products/native_cpu",
            ),
            product(
                "riscv_cpu",
                *PROVER_PREFIXES,
                "src/backends/cpu_scalar",
                "src/frontends/riscv",
                "src/integrations/riscv_cpu",
            ),
            product(
                "cairo_cpu",
                *PROVER_PREFIXES,
                "src/backends/cpu_scalar",
                "src/frontends/cairo",
                "src/integrations/cairo_cpu",
                "src/products/cairo_cpu",
            ),
            product(
                "cairo_metal",
                *PROVER_PREFIXES,
                "src/backends/cpu_scalar",
                "src/backends/metal",
                "src/frontends/cairo",
                "src/integrations/cairo_metal",
                "src/products/cairo_metal",
            ),
            product(
                "native_metal",
                *PROVER_PREFIXES,
                "src/backends/cpu_scalar",
                "src/backends/metal",
            ),
            product(
                "riscv_metal",
                *PROVER_PREFIXES,
                "src/backends/cpu_scalar",
                "src/backends/metal",
                "src/frontends/riscv",
                "src/integrations/riscv_metal",
                "src/products/riscv_metal",
            ),
            product(
                "native_cuda",
                *PROVER_PREFIXES,
                "src/backends/cuda",
                "src/backends/cpu_scalar",
                "src/backends/metal",
                "src/frontends/cairo",
                "src/frontends/riscv",
                "src/integrations/native_cuda",
                "src/products/native_cuda",
                state="staged",
            ),
            product(
                "cairo_cuda",
                "src/backends/cuda",
                "src/prover_api",
                "src/frontends/cairo",
                "src/integrations/cairo_cuda",
                "src/products/cairo_cuda",
                state="staged",
            ),
        ],
    }
