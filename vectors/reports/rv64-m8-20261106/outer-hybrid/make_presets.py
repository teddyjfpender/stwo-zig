#!/usr/bin/env python3
"""Derive the outer-hybrid A/B presets from the canonical integration preset.

baseline  = the canonical baseline arm (what rv64_gate.sh proves: D2 + coalescing,
            auto arena, lanes 1, sessions 0, pending 17).
fullstack = the SAME environment plus the candidate's STWO_RV64_M8_* flags.
No arm holds the physical canary (physical_guard_arms = []), so both arms keep
the original auto arena and the only difference is the M8 flag set.
usage: make_presets.py <canonical preset> <out dir> <addon.so> <outer-fs.so> [native env KEY=VALUE ...]
"""
import json, sys
from pathlib import Path

src, out, addon, fs, *native = sys.argv[1:]
base = json.loads(Path(src).read_text())
outer = {'STWO_RV64_M8_OUTER_JOBS': '1', 'STWO_RV64_M8_JOBS_LIBRARY': addon,
         'STWO_RV64_M8_OUTER_FS_LIBRARY': fs, 'STWO_RV64_M8_JOBS_PINNED_BYTES': '2365587456'}
arms = {'outer': outer}
if native:
    arms['composed'] = dict(outer, **dict(kv.split('=', 1) for kv in native))
for name, extra in arms.items():
    p = json.loads(json.dumps(base))
    p['schema'] = 'rv64-m8-outer-hybrid-ab/v1'
    p['arms']['fullstack'] = dict(p['arms']['baseline'], **extra)
    p['operational']['fullstack'] = dict(p['operational']['baseline'])
    p['measurement']['physical_guard_arms'] = []
    p['measurement']['memory_claim'] = 'Neither arm holds a physical canary; both keep the original auto arena. No 28 GB claim.'
    p['measurement']['timed_scope'] = f'fullstack = baseline + {sorted(extra)}; everything else identical (pending 17, lanes 1, sessions 0).'
    Path(out, f'preset-{name}.json').write_text(json.dumps(p, indent=2) + '\n')
    print(Path(out, f'preset-{name}.json'))
