#!/usr/bin/env python3
"""Compare every artifact of a daemon run to the admitted M6 default receipts."""
import hashlib
import json
from pathlib import Path
import sys

receipt_path = Path(sys.argv[1])
root = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(root / 'scripts'))
import rv64_resident_basket as R

receipt = json.loads(receipt_path.read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
rows = []
for request in receipt['requests']:
    block = request['block']
    reference_path = root / 'vectors/reports/rv64-m6-20261105/integrate' / f'{block}-2gpu-c1-bench.json'
    reference = json.loads(reference_path.read_text())['proof_sha256']
    proof = Path(request['proof'])
    actual = {'native': {p.name: sha(p) for p in sorted(proof.glob('*.bin'))},
              'bundle': sha(proof / 'bundle.json'),
              'recursive': R.recursive_snapshot(proof, request['leaves'])}
    matches = {name: actual[name] == reference[name] for name in actual}
    rows.append({'block': block, 'trial': request['trial'], 'stages': request['stages'],
                 'proof_bytes_root': request['proof_bytes_root'], 'reference': str(reference_path),
                 'matches': matches, 'byte_identical': all(matches.values())})
result = {'schema': 'rv64-m7-byte-identity/v1', 'label': 'M', 'receipt': str(receipt_path),
          'assets': receipt['assets'], 'source_commit': receipt['source_commit'],
          'load_avg_before': receipt['load_avg_before'], 'load_avg_after': receipt['load_avg_after'],
          'producer_process': receipt['producer_process'], 'physical_gpu_memory': receipt['physical_gpu_memory'],
          'receivers': receipt.get('receivers', []), 'requests': rows,
          'all_byte_identical': all(row['byte_identical'] for row in rows)}
output = Path(sys.argv[2])
output.write_text(json.dumps(result, indent=2) + '\n')
for row in rows:
    print(row['block'], row['trial'], row['byte_identical'], row['stages'])
if not result['all_byte_identical']:
    raise SystemExit('M6 DEFAULT BYTE IDENTITY FAILED')
