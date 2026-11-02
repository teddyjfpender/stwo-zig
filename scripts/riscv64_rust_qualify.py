#!/usr/bin/env python3
"""Verify genuine RV64 fixtures and deliberate forgeries using the pinned Rust adapter."""
import argparse
import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PIN = 'a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2'
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--fixtures',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    def run(expected,bundle,repeats=1):
        return subprocess.run([binary,expected,bundle,str(repeats)],capture_output=True,text=True,timeout=60)
    valid_expected = args.fixtures/'valid-expected.json'
    valid_bundle = args.fixtures/'valid-bundle.json'
    result = run(valid_expected,valid_bundle,7)
    if result.returncode:
        raise RuntimeError(result.stderr)
    receipt = {'schema':'rv64-independent-rust-qualification-v1','upstream_pin':PIN,
               'binary_sha256':sha(binary),'cargo_lock_sha256':sha(ROOT/'tools/stwo-interop-rs/Cargo.lock'),
               'scope':'Dense v2 five-instruction fixture; pinned PCS/FRI with explicit four-way adapter; no witness replay. Other programs and sparse v3 are not qualified.',
               'valid':json.loads(result.stdout),'rejections':[],
               'adapter_source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/'tools/stwo-interop-rs/src/rv64_qualification').glob('*.rs'))}}
    for kind in ('source','ram','permission'):
        result = run(args.fixtures/f'{kind}-expected.json',args.fixtures/f'{kind}-bundle.json')
        if result.returncode==0 or 'OodsNotMatching' not in result.stderr:
            raise ValueError(f'Captured {kind} forgery was not rejected correctly: {result.stderr}')
        receipt['rejections'].append({'kind':f'captured_{kind}_forgery','rejected':True,'reason':'OodsNotMatching'})
    original = json.loads(valid_expected.read_text())
    bundle = json.loads(valid_bundle.read_text())
    mutants=[]
    expected=copy.deepcopy(original)
    expected['initial_registers'][10]=99
    expected['final_registers'][10]=99
    mutants.append(('unchanged_unaccessed_register_identity',expected,bundle))
    expected=copy.deepcopy(original)
    expected['memory'][0]['address'] ^= 1<<40
    mutants.append(('upper_address_bits',expected,bundle))
    expected=copy.deepcopy(original)
    expected['program_addresses']=[expected['program_base']+4*i for i in range(5)]
    mutants.append(('unsupported_sparse_scope',expected,bundle))
    for kind in ('root','weakened_config','noncanonical_field','missing_tree','changed_path'):
        changed=copy.deepcopy(bundle)
        if kind=='root':changed['proof']['commitments'][0][0]^=1
        elif kind=='weakened_config':changed['proof']['config']['fri_config']['n_queries']=1
        elif kind=='noncanonical_field':changed['proof']['sampled_values'][1][0][0][0]=2147483647
        elif kind=='missing_tree':changed['proof']['sampled_values'].pop()
        else:changed['metadata']['path'][1]+=4
        mutants.append((kind,original,changed))
    with tempfile.TemporaryDirectory(prefix='stwo-rv64-rust-negative-') as temporary:
        expected_path=Path(temporary)/'expected.json'
        proof_path=Path(temporary)/'bundle.json'
        for kind,expected,proof in mutants:
            expected_path.write_text(json.dumps(expected));proof_path.write_text(json.dumps(proof))
            result=run(expected_path,proof_path)
            if result.returncode==0:raise ValueError(f'Accepted mutant {kind}')
            if 'panicked' in result.stderr:raise ValueError(f'Panicked on mutant {kind}: {result.stderr}')
            receipt['rejections'].append({'kind':kind,'rejected':True,'reason':result.stderr.strip()})
    args.report.write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
