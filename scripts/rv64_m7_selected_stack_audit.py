#!/usr/bin/env python3
"""Read-only selected-kernel/cubin stack census; never creates a CUDA context."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess


def sha(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True)
    parser.add_argument('--cuobjdump', default='/usr/local/cuda/bin/cuobjdump')
    parser.add_argument('--sqlite', required=True)
    parser.add_argument('--phase-receipt', required=True,
                        help='Existing after-native ownership JSON with request_window_ns')
    args = parser.parse_args()
    ownership = json.loads(Path(args.phase_receipt).read_text())
    assert sha(args.library) == ownership['assets']['library']
    assert sha(args.sqlite) == ownership['sqlite_sha256']
    text = subprocess.run([args.cuobjdump, '-res-usage', args.library],
                          capture_output=True, text=True, check=True).stdout
    frames, function = {}, None
    for line in text.splitlines():
        match = re.search(r'Function (\S+):', line)
        if match:
            function = match.group(1)
        match = re.search(r'STACK:(\d+)', line)
        if match and function:
            frames[function] = max(frames.get(function, 0), int(match.group(1)))
    connection = sqlite3.connect(Path(args.sqlite).resolve().as_uri() + '?mode=ro', uri=True)
    output = {'library_sha256': sha(args.library), 'sqlite_sha256': sha(args.sqlite),
              'resource_sha256': hashlib.sha256(text.encode()).hexdigest(), 'phases': []}
    windows = [('all-recorded', 0, (1 << 63) - 1)]
    for index, request in enumerate(ownership['requests']):
        assert request['kernel_activity_complete'] is True
        windows.append((f'after-native-{index}', *request['request_window_ns']))
    for label, start, end in windows:
        rows = connection.execute('''
            SELECT coalesce(m.value,d.value),d.value,count(*),sum(k.end-k.start)*1e-9
            FROM CUPTI_ACTIVITY_KIND_KERNEL k
            JOIN StringIds d ON d.id=k.demangledName
            LEFT JOIN StringIds m ON m.id=k.mangledName
            WHERE k.start>=? AND k.end<=? GROUP BY k.demangledName
        ''', (start, end)).fetchall()
        missing = [mangled for mangled, *_ in rows if mangled not in frames]
        assert not missing, missing
        selected = sorted(({'mangled': mangled, 'name': name,
                            'stack_bytes': frames[mangled], 'calls': calls,
                            'gpu_seconds': seconds}
                           for mangled, name, calls, seconds in rows),
                          key=lambda row: row['stack_bytes'], reverse=True)
        output['phases'].append({'label': label, 'window_ns': [start, end],
                                 'kernel_names': len(rows), 'selected': selected})
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
