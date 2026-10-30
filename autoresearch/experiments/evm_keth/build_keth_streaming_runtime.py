"""Build a serialization-only Keth runtime adaptation in an isolated worktree.

The Cairo VM, execution rules, adapter and proof parameters remain pinned. The
adaptation writes legacy witness JSON through a bounded buffer instead of first
constructing the complete JSON string. The reference checkout is untouched.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from .bridge import PINS, authenticate, digest, write_new
from .keth_trace_ownership import consume_trace, consume_adapter_trace
from .keth_memory_instrumentation import instrument_runner
from .keth_streamed_relocation import adapt_runner

ORIGINAL = '''        std::fs::write(&output_path, sonic_rs::to_string_pretty(&prover_input_info).unwrap())?;'''
STREAMING = '''        let file = std::fs::File::create(&output_path)?;
        let mut writer = sonic_rs::writer::BufferedWriter::new(
            io::BufWriter::with_capacity(3 * 1024 * 1024, file));
        sonic_rs::to_writer_pretty(&mut writer, &prover_input_info)
            .map_err(|error| to_pyerr(error.to_string()))?;
        writer.flush()?;'''


def build(reference: Path, out: Path, consume_vm_trace: bool = False, profile_memory: bool = False,
          stream_relocation: bool = False):
    reference, out = reference.resolve(), out.resolve()
    identity = authenticate(reference, PINS['keth'])
    out.mkdir(parents=True, exist_ok=False)
    checkout, target, shadow = (out / name for name in ('source', 'target', 'python'))
    subprocess.run(['git', '-C', str(reference), 'worktree', 'add', '--detach', str(checkout),
                    PINS['keth']['revision']], check=True)
    source = checkout / 'crates/cairo-addons/src/vm/runner.rs'
    original_hash = digest(source)
    original = source.read_text()
    if original != (reference / source.relative_to(checkout)).read_text() or original.count(ORIGINAL) != 1:
        raise ValueError('unexpected pinned witness serializer')
    adapted = original.replace(ORIGINAL, STREAMING)
    vm_adaptation = None
    if consume_vm_trace:
        vm_adaptation = consume_trace(checkout, reference, out, stream_relocation)
        adapted = consume_adapter_trace(adapted)
    if profile_memory:
        if not consume_vm_trace:
            raise ValueError('memory profiling requires the owned VM buffer accessor')
        adapted = instrument_runner(adapted)
    if stream_relocation:
        if not profile_memory:
            raise ValueError('streamed relocation experiment requires memory diagnostics')
        adapted = adapt_runner(adapted)
    source.write_text(adapted)
    patch = subprocess.check_output(['git', '-C', str(checkout), 'diff', '--',
                                    str(source.relative_to(checkout))])
    (out / 'serialization.patch').write_bytes(patch)
    if (reference / 'target').is_dir():
        # APFS clone keeps cached build products isolated without duplicating
        # their physical data. Builds never replace reference runtime binaries.
        subprocess.run(['cp', '-cR', str(reference / 'target'), str(target)], check=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), PYO3_PYTHON=str(reference / '.venv/bin/python'),
               CARGO_BUILD_JOBS='4')
    subprocess.run(['cargo', '+nightly-2025-04-06', 'build', '--release', '--locked', '-p', 'cairo_addons'],
                   cwd=checkout, env=env, check=True)
    package = shadow / 'cairo_addons'
    package.mkdir(parents=True)
    python_source = reference / 'python/cairo-addons/src/cairo_addons'
    for path in python_source.iterdir():
        if path.name == '__pycache__' or path.suffix == '.so':
            continue
        (package / path.name).symlink_to(path, target_is_directory=path.is_dir())
    binary = package / 'rust_bindings.abi3.so'
    shutil.copy2(target / 'release/libvm.dylib', binary)
    result = dict(schema='keth-streaming-runtime-build-v1', keth_source=identity,
                  original_runner_sha256=original_hash, adapted_runner_sha256=digest(source),
                  patch_sha256=digest(out / 'serialization.patch'), binary_sha256=digest(binary),
                  python_path=str(shadow), toolchain='nightly-2025-04-06',
                  adaptation='stream witness serialization; identical VM and witness semantics',
                  source_diff=patch.decode(), trace_ownership_adaptation=vm_adaptation,
                  memory_instrumentation=profile_memory, streamed_relocation=stream_relocation)
    if authenticate(reference, PINS['keth']) != identity:
        raise ValueError('reference checkout changed during isolated build')
    write_new(out / 'build.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keth-checkout', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--consume-vm-trace', action='store_true')
    parser.add_argument('--profile-memory', action='store_true')
    parser.add_argument('--stream-relocation', action='store_true')
    args = parser.parse_args()
    print(json.dumps(build(args.keth_checkout, args.out, args.consume_vm_trace, args.profile_memory,
                          args.stream_relocation), indent=2))
