#!/usr/bin/env python3
"""Overlay only affected Keccak prefix TUs, preserving qualified kernel symbols.

The lowerer retains every original root and reverse RLC index. This packaging
step preserves the admitted dispatch catalogue and checks unchanged functions.
"""
import argparse, hashlib, json, re
from pathlib import Path

def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()

def bounds(text, group):
    begin=f'// RV64_KECCAK_PREFIX_GROUP_BEGIN {group}\n'
    if begin in text:
        start=text.index(begin);end=text.index(f'// RV64_KECCAK_PREFIX_GROUP_END {group}\n',start)
        return start,end+len(f'// RV64_KECCAK_PREFIX_GROUP_END {group}\n')
    marker=f'__device__ __noinline__ void rv64_truth_domain_0_part_{group}('
    start=text.index(marker)
    after=start+len(marker)
    match=re.search(r'__device__ __noinline__ void |extern "C" __global__ void ',text[after:])
    if not match:raise ValueError('missing next function boundary')
    end=after+match.start()
    next_marker=text.find('// RV64_KECCAK_PREFIX_GROUP_BEGIN ',after)
    if next_marker>=0:end=min(end,next_marker)
    return start,end

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lowered',type=Path,required=True)
    p.add_argument('--catalog',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();lowered=args.lowered.read_text();catalog=json.loads((args.catalog/'partition.json').read_text())
    args.output.mkdir(parents=True,exist_ok=True);receipt=[]
    for module in catalog['roles'][0]['modules']:
        groups=range(module['first_group'],module['first_group']+module['groups'])
        if not set(groups).intersection(range(170,175)):continue
        original=args.catalog/'role-0'/Path(module['source']).name;text=original.read_text()
        if digest(text)!=module['sha256']:raise ValueError('qualified source digest mismatch')
        updated=text
        for group in groups:
            start,end=bounds(updated,group);new_start,new_end=bounds(lowered,group)
            if group not in range(170,175):
                if updated[start:end]!=lowered[new_start:new_end]:raise ValueError('unaffected function changed')
                continue
            updated=updated[:start]+lowered[new_start:new_end]+updated[end:]
        path=args.output/original.name;path.write_text(updated)
        receipt.append({'source':str(path),'symbol':module['symbol'],'first_group':module['first_group'],'groups':module['groups'],'old_source_sha256':digest(text),'new_source_sha256':digest(updated),'private_bank':False})
    if len(receipt)!=4:raise ValueError('unexpected qualified partition geometry')
    (args.output/'patch.json').write_text(json.dumps({'scope':'AOT-only packaging; proof qualification separate','original_prefix_root':5596,'affected_groups':list(range(170,175)),'modules':receipt},indent=2)+'\n')
    print(json.dumps(receipt))
if __name__=='__main__':main()
