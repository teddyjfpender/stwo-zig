#!/usr/bin/env python3
"""Profile complete CSP executions and prove deterministic partial windows.

No whole-guest proof or linear throughput extrapolation is claimed. Every measured
window must pass fresh native verification; admission failures remain in evidence.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.riscv64_csp_compare import ISA, BINARIES, elf_info

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execution-report', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    execution = json.loads(args.execution_report.read_text())
    if not execution['complete'] or execution['oracle'] != 'Unicorn 2.1.4':
        raise ValueError('Requires complete independently checked execution receipt')
    executable = ROOT / 'zig-out/bin/rv64-csp-windows'
    report = {'schema': 'rv64-csp-complete-cost-and-partial-proofs-v1', 'complete': False,
              'whole_guest_proof': False, 'execution_report_sha256': digest(args.execution_report),
              'binary_sha256': digest(executable), 'cases': [],
              'scope': 'One capture pass per case; hints built once per selected window; per-window local proof only. Aggregate cell counts are model bounds, exclude global RAM/continuation/recursion, and include inadmissible windows.'}
    manifest = json.loads((ROOT / 'vectors/riscv_csp/manifest-v2.json').read_text())
    for row in execution['rows']:
        matches = list(manifest['targets'][row['target']]['cases']) + [case for case in manifest['negative_fixtures'] if case['target'] == row['target']]
        case = next(case for case in matches if case['input_sha256'] == row['input_sha256'])
        elf = args.work_dir / 'target' / ISA[1] / 'release' / BINARIES[row['target']]
        if digest(elf) != row['elf_sha256'][ISA[1]]:
            raise ValueError('Guest binary differs from execution receipt')
        _, symbols, _ = elf_info(elf)
        names = ('input_start','input_end','halt_flag','output_len','output_data','output_end','stack_bottom','stack_top')
        starts = sorted({0, (row['rv64_instructions']//2//256)*256})
        artifacts = args.work_dir / 'proof-artifacts' / f"{row['target']}-{row['size']}-{int(row['negative'])}"
        config = {'artifact_dir': str(artifacts), 'guest': {'elf': str(elf), 'input': str(ROOT/case['input_path']), 'expected_digest': row['output'],
                            'symbols': {name: symbols['__'+name] for name in names}},
                  'expected_steps': row['rv64_instructions'], 'sample_starts': starts}
        path = args.work_dir / 'proof-window-case.json'
        path.write_text(json.dumps(config))
        print(f"Profile/prove {row['target']}/{row['size']} negative={row['negative']}", flush=True)
        run = subprocess.run([executable,path], capture_output=True, timeout=600)
        if run.returncode:
            raise RuntimeError(run.stderr.decode(errors='replace')[-4000:])
        measured = json.loads(run.stdout)
        if measured['instructions'] != row['rv64_instructions'] or len(measured['samples']) != len(starts):
            raise ValueError('Incomplete capture/sample coverage')
        for sample in measured['samples']:
            if sample['status'] != 'verified_partial_window':
                continue
            stem = str(sample['start'])
            paths = [artifacts / (stem + suffix) for suffix in ('.statement.json', '.metadata.json', '.proof.bin')]
            result = subprocess.run([ROOT / 'zig-out/bin/rv64-window-verify', *paths], capture_output=True, timeout=120)
            if result.returncode:
                raise RuntimeError(result.stderr.decode(errors='replace')[-4000:])
            sample['fresh_process'] = json.loads(result.stdout)
            sample['artifact_sha256'] = {path.name: digest(path) for path in paths}
        report['cases'].append({'target': row['target'], 'size': row['size'], 'negative': row['negative'], 'input_sha256': row['input_sha256'], **measured})
        args.report.write_text(json.dumps(report,indent=2)+'\n')
    report['complete'] = True
    args.report.write_text(json.dumps(report,indent=2)+'\n')
if __name__ == '__main__':
    main()
