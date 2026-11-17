#!/usr/bin/env python3
"""Attribute an existing VM PC census to its exact ELF; never replay/prove."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def report(elf,execution,nm):
    value=json.loads(execution.read_text());profile=value['pc_profile'];counts=profile['counts'];start,end=profile['start'],profile['end']
    if start&3 or end&3 or not 0<end-start<=8<<20 or len(counts)!=(end-start)//4:raise ValueError('PC range/layout mismatch')
    if hashlib.sha256(elf.read_bytes()).hexdigest()!=value['elf_sha256']:raise ValueError('PC profile ELF identity mismatch')
    if any(type(n)is not int or n<0 for n in counts)or sum(counts)+profile['outside']!=value['instructions']:raise ValueError('PC coverage/count mismatch')
    rows=subprocess.run([str(nm),'-n','-S','--defined-only','--demangle',str(elf)],capture_output=True,text=True,check=True,timeout=30).stdout
    symbols=[]
    for line in rows.splitlines():
        parts=line.split(maxsplit=3)
        # LLVM .Lpcrel/.LBB labels can sit inside real functions with size0;
        # treating them as functions silently steals the enclosing attribution.
        if len(parts)==4 and parts[2]in('t','T')and not parts[3].startswith('.L'):
            symbols.append((int(parts[0],16),int(parts[1],16),parts[3]))
    addresses=[s[0]for s in symbols];totals={};unmapped=0
    for i,n in enumerate(counts):
        if not n:continue
        pc=start+4*i;index=bisect.bisect_right(addresses,pc)-1
        if index<0 or(symbols[index][1]and pc>=symbols[index][0]+symbols[index][1]):unmapped+=n;continue
        name=symbols[index][2];totals[name]=totals.get(name,0)+n
    return {'schema':'op-pc-profile-attribution-v1','elf_sha256':value['elf_sha256'],'input_sha256':value['input_sha256'],'execution_status':value['status'],'verified_output':value['verified_output'],'instructions':value['instructions'],'outside':profile['outside'],'unmapped':unmapped,'attributed':sum(totals.values()),'top_symbols':[{'symbol':k,'instructions':n}for k,n in sorted(totals.items(),key=lambda item:-item[1])[:30]],'scope':'Existing exact-ELF PC counts; partial runs are not completed execution or proof','proof_verified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--elf',type=Path,required=True);p.add_argument('--execution',type=Path,required=True);p.add_argument('--nm',type=Path,default=Path(shutil.which('llvm-nm')or'/opt/homebrew/opt/llvm/bin/llvm-nm'));a=p.parse_args();print(json.dumps(report(a.elf,a.execution,a.nm),indent=2))
