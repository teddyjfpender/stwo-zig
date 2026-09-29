"""Compare terminal-only CUDA source snapshots against pinned Rust base traces."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

p = argparse.ArgumentParser()
p.add_argument('directory', type=Path)
p.add_argument('--oracle', type=Path, default=Path('vectors/cairo/official/all_opcodes.base_trace_checkpoint.json'))
p.add_argument('--output', type=Path, required=True)
p.add_argument('--seed-public-memory', type=Path,
               help='Offline diagnosis only: add omitted statement uses to copied counters')
a = p.parse_args()
meta = json.loads((a.directory / 'sources.json').read_text())
assert meta['full_proof_verified'] is False and meta['accepted_benchmark'] is False
oracle = json.loads(a.oracle.read_text())
components = {c['label']: c for c in oracle['components']}
seed = json.loads(a.seed_public_memory.read_text()) if a.seed_public_memory else None
results = []
for s in meta['sources']:
    b = (a.directory / s['file']).read_bytes()
    assert len(b) == s['rows'] * s['columns'] * 4
    if seed is not None and s['layout'].startswith('memory_'):
        # Never rewrite the device snapshot or a proof. This predicts the
        # counter repair against every canonical column's independent digest.
        values = list(struct.unpack('<%dI' % (len(b)//4), b))
        for address in seed['public_memory_addresses']:
            assert 0 < address < len(seed['memory']['address_to_id'])
            encoded = seed['memory']['address_to_id'][address]
            tag, index = encoded >> 30, encoded & 0x3fffffff
            assert tag in (0, 1)
            if s['layout'] == 'memory_address':
                chunk, row = divmod(address - 1, s['rows'])
                offset = (2*chunk + 1)*s['rows'] + row
            elif s['layout'] == 'memory_big' and tag == 1:
                chunk, row = divmod(index, 1 << 24)
                if chunk != s['instance']: continue
                offset = (s['columns']-1)*s['rows'] + row
            elif s['layout'] == 'memory_small' and tag == 0:
                offset = (s['columns']-1)*s['rows'] + index
            else:
                continue
            assert 0 <= offset < len(values) and values[offset] < 0xffffffff
            values[offset] += 1
        b = struct.pack('<%dI' % len(values), *values)
    name = s['component'] + (f"[{s['instance']}]" if s['component'] == 'memory_id_to_big' else '')
    c = components[name]
    # The terminal snapshots retain the implicit interaction pointer order.
    if s['layout'] in ('memory_big', 'memory_small'):
        order = [s['columns']-1, *range(s['columns']-1)]
    elif s['layout'] == 'memory_address':
        order = list(range(s['columns']))
    elif name == 'blake_round_sigma':
        order = [18]
    elif name == 'range_check_11':
        order = [2]
    else:
        raise ValueError('unsupported diagnostic component ' + name)
    assert len(order) == len(c['columns'])
    columns = []
    for expected, index in zip(c['columns'], order):
        assert expected['row_count'] == s['rows']
        values = b[index*s['rows']*4:(index+1)*s['rows']*4]
        label = name.encode()
        h = hashlib.sha256(b'STWO_CAIRO_BASE_COLUMN_V1\0' + struct.pack('<II', c['ordinal'],len(label)) + label + struct.pack('<IQ',expected['ordinal'],s['rows']) + values).hexdigest()
        columns.append({'ordinal':expected['ordinal'],'matches':h==expected['sha256'], 'expected_sha256':expected['sha256'],'actual_sha256':h,'prefix':list(struct.unpack('<%dI'%min(16,s['rows']),values[:min(16,s['rows'])*4]))})
    results.append({'component':name,'all_columns_match':all(c['matches'] for c in columns),'columns':columns})
    print(name, sum(c['matches'] for c in columns),'/',len(columns),'columns match')
    for v in columns:
        if not v['matches']: print('  column',v['ordinal'],'prefix',v['prefix'])
    if name == 'blake_round_sigma':
        print('  sequence',list(struct.unpack('<16I',b[s['rows']*4:2*s['rows']*4])))
        print('  sigma0',list(struct.unpack('<16I',b[2*s['rows']*4:3*s['rows']*4])))
report={'schema':'stwo-cairo-cuda-source-comparison-v1','full_proof_verified':False,'accepted_benchmark':False,'oracle_sha256':hashlib.sha256(a.oracle.read_bytes()).hexdigest(),'terminal_sha256':hashlib.sha256((a.directory/'terminal.bin').read_bytes()).hexdigest(),'sources':results}
if seed is not None:
    report['offline_public_memory_seed_input_sha256'] = hashlib.sha256(a.seed_public_memory.read_bytes()).hexdigest()
    report['diagnostic_only'] = True
with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
