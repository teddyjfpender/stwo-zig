#!/usr/bin/env python3
"""Rebuild both CSP recovery guests; --write refreshes authenticated fixtures."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / 'vectors/riscv_guests/ecdsa_secp256k1_precompile'
MANIFEST = ROOT / 'vectors/riscv_csp/ecdsa-precompile-v1.json'


def entry(path):
    return {'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    guests = {}
    with tempfile.TemporaryDirectory(prefix='csp-ecdsa-guests-') as directory:
        for parity, suffix in enumerate(('even', 'odd')):
            command = ['cargo', 'build', '--release', '--locked', '--target-dir', directory]
            if parity:
                command += ['--features', 'recovery-odd']
            subprocess.run(command, cwd=CRATE, check=True)
            elf = Path(directory) / 'riscv32im-unknown-none-elf/release/ecdsa_secp256k1_precompile'
            destination = ROOT / f'vectors/riscv_csp/guests/ecdsa_secp256k1_precompile_{suffix}.elf'
            if args.write:
                destination.write_bytes(elf.read_bytes())
            elif elf.read_bytes() != destination.read_bytes():
                raise SystemExit(f'guest binary drift: {destination}')
            guests[str(parity)] = entry(destination)
    sources = [CRATE / name for name in ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml',
                                        '.cargo/config.toml', 'linker.ld', 'src/main.rs')]
    sources.append(Path(__file__).resolve())
    manifest = {'schema': 'stwo.csp.ecdsa-precompile-guests.v1',
                'implementation': 'typed_recovery_key_match_low_s_v1',
                'sources': [entry(path) for path in sources], 'guests': guests}
    if args.write:
        MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n')
    elif json.loads(MANIFEST.read_text()) != manifest:
        raise SystemExit('guest manifest drift')
    print('Both CSP ECDSA guests and their source manifest match.')


if __name__ == '__main__':
    main()
