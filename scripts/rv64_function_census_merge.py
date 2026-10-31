#!/usr/bin/env python3
"""Exact bounded merge of independently admitted NativeStep48 function runs.

No VM execution, no proof acceptance, no global in-memory tuple map. Each input
is sorted by (global function ID,A,B,C); its count is an exact per-packet mass.
"""
import argparse
from collections import Counter
import hashlib
import heapq
import json
from pathlib import Path
import struct
import time

ROW = struct.Struct('<QQQII')
NAMES = {0:'ADD',1:'SUB',2:'ADDW',3:'SUBW',4:'SLT',5:'SLTU',6:'EQ',7:'NE',8:'GE',9:'GEU',16:'AND',17:'OR',18:'XOR',32:'SLL',33:'SRL',34:'SRA',35:'SLLW',36:'SRLW',37:'SRAW'}
def family(op):
    if 0 <= op <= 9: return 'alu'
    if 16 <= op <= 18: return 'binary'
    if 32 <= op <= 37: return 'shift'
    raise ValueError(f'invalid global function ID {op}')
def fact(key, count):
    op,a,b,c = key
    return dict(global_id=op,operation=NAMES[op],a=f'{a:016x}',b=f'{b:016x}',c=f'{c:016x}',occurrences=count)
class Stats:
    def __init__(self, top=32):
        self.n=0; self.mass=0; self.hist=Counter(); self.top=[]; self.limit=top
    def add(self,key,count):
        if count <= 0: raise ValueError('nonpositive source mass')
        self.n+=1;self.mass+=count;self.hist[count]+=1
        item=(count,key)
        if len(self.top)<self.limit: heapq.heappush(self.top,item)
        elif item>self.top[0]: heapq.heapreplace(self.top,item)
    def json(self):
        return dict(occurrences=self.mass,unique_tuples=self.n,duplicate_occurrences=self.mass-self.n,
                    repeated_unique_tuples=self.n-self.hist[1],singleton_unique_tuples=self.hist[1],
                    multiplicity_histogram=dict(sorted(self.hist.items())),
                    top_facts=[fact(k,n) for n,k in sorted(self.top,reverse=True)])
def run(path,meta,stats,groups):
    with path.open('rb',buffering=65536) as f:
        sha=hashlib.file_digest(f,'sha256').hexdigest()
        if sha != meta['run_sha256']: raise ValueError(f'run digest mismatch {path}')
        f.seek(0);prev=None;size=0
        while raw:=f.read(65536):
            if len(raw)%ROW.size: raise ValueError('truncated run')
            for a,b,c,op,count in ROW.iter_unpack(raw):
                key=(op,a,b,c)
                if prev is not None and key<=prev: raise ValueError(f'unsorted run {path}')
                prev=key;size+=1
                stats.add(key,count);groups[family(op)].add(key,count)
                yield key,count
        if size!=meta['unique']: raise ValueError('run size mismatch')
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory',type=Path);p.add_argument('pinned_opcode_census',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();begin=time.monotonic()
    metas=[json.loads((a.directory/f'job-{i:06}.json').read_text()) for i in range(25)]
    locals_=[Stats() for _ in metas]
    localgroups=[{f:Stats(8) for f in ('alu','binary','shift')} for _ in metas]
    streams=[];opcode_total=None
    for i,m in enumerate(metas):
        pin=json.loads((a.pinned_opcode_census/f'job-{i:06}.json').read_text())
        if m['opcode_counts']!=pin['opcode_counts'] or m['steps']!=pin['steps'] or m['index']!=i: raise ValueError(f'opcode census mismatch {i}')
        if opcode_total is None: opcode_total=[0]*len(m['opcode_counts'])
        opcode_total=[x+y for x,y in zip(opcode_total,m['opcode_counts'])]
        streams.append(run(a.directory/f'job-{i:06}.run',m,locals_[i],localgroups[i]))
    glob=Stats(100);groups={f:Stats(32) for f in ('alu','binary','shift')};byop={op:Stats(8) for op in NAMES}
    prev=None;mass=0
    for key,count in heapq.merge(*streams):
        if key==prev:mass+=count
        else:
            if prev is not None:
                glob.add(prev,mass);groups[family(prev[0])].add(prev,mass);byop[prev[0]].add(prev,mass)
            prev=key;mass=count
    if prev is not None:
        glob.add(prev,mass);groups[family(prev[0])].add(prev,mass);byop[prev[0]].add(prev,mass)
    for i,m in enumerate(metas):
        if locals_[i].n!=m['unique'] or [localgroups[i][f].mass for f in ('alu','binary','shift')]!=m['families']: raise ValueError(f'family mismatch {i}')
    if glob.mass!=sum(s.mass for s in locals_) or glob.n!=sum(s.n for s in groups.values()): raise ValueError('global merge conservation mismatch')
    total_steps=sum(m['steps'] for m in metas)
    if total_steps!=104253913 or sum(opcode_total)!=total_steps: raise ValueError('pinned instruction count mismatch')
    result=dict(schema='rv64-exact-function-census-v1',scope='read-only accepted packet advice, immutable ROM classification; no VM replay, no wide witness, no new proof or weighted-fact protocol activation',
                tuple_schema=['global_function_id','A_u64','B_effective_u64','C_u64'],normalization='B=signextended decoded immediate when classified immediate; branch C=NativeStep48.flags; otherwise captured result; no PC/owner/request ID in pure function tuple',
                total_steps=total_steps,opcode_counts=opcode_total,opcode_census_exact=True,branch_queries=sum(m['branch_queries'] for m in metas),
                global_=glob.json(),families={k:v.json() for k,v in groups.items()},operations={str(k):v.json() for k,v in byop.items()},
                sum_per_batch_unique=sum(s.n for s in locals_),cross_batch_additional_duplicate_occurrences=sum(s.n for s in locals_)-glob.n,
                per_batch=[dict(**m,statistics=s.json(),family_statistics={k:v.json() for k,v in gs.items()}) for m,s,gs in zip(metas,locals_,localgroups)],
                merge=dict(elapsed_seconds=time.monotonic()-begin,run_count=25,input_buffer_bytes=25*65536,whole_execution_hash_map=False,exact=True))
    result['global']=result.pop('global_')
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('total_steps','sum_per_batch_unique','cross_batch_additional_duplicate_occurrences','merge')}))
    print(json.dumps({k:{v:x[v] for v in ('occurrences','unique_tuples','duplicate_occurrences')} for k,x in result['families'].items()}))
if __name__=='__main__':main()
