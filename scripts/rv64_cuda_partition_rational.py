#!/usr/bin/env python3
"""Bound native rational-projection compilation by splitting independent pair cases.

Each case keeps its global output column addresses. No matrix/protocol changes.
The exported original ABI dispatches all shards on the same caller stream.
"""
import argparse,json,re
from pathlib import Path

def partition(source,output,limit):
    text=source.read_text(); cases=list(re.finditer(r'case (\d+)u:\{',text))
    if not cases: raise ValueError('no rational cases')
    entry=text.index('extern "C" __global__ void');start=text.index('switch(blockIdx.y){',entry)+len('switch(blockIdx.y){')
    tail=text.index('\n#include "rv64/custody.cuh"',cases[-1].end())
    end=text.rfind('}',0,tail);end=text.rfind('}',0,end)
    kernel=re.search(r'extern "C" __global__ void (\w+)\(',text).group(1)
    wrapper=text[tail:];symbol=re.search(r' int (\w+)\(',wrapper).group(1)
    prefix=text[:start];suffix=text[end:tail]
    output.mkdir(parents=True,exist_ok=True);names=[];files=[]
    for part,first in enumerate(range(0,len(cases),limit)):
        count=min(limit,len(cases)-first);last=first+count
        body=text[cases[first].start():cases[last].start() if last<len(cases) else end]
        k=f'{kernel}_part_{part}';s=f'{symbol}_part_{part}';names.append(s)
        head=prefix.replace(kernel,k).replace('switch(blockIdx.y){',f'switch(blockIdx.y+{first}u){{')
        host=wrapper.replace(kernel,k)
        host=re.sub(r"\b"+re.escape(symbol)+r"\b",s,host)
        host=re.sub(r'dim3\(\(rows\+127\)/128,\d+u\)',f'dim3((rows+127)/128,{count}u)',host)
        path=output/f'{s}.cu';path.write_text(head+body+suffix+host);files.append(str(path))
    signature='void*ctx,uint32_t lane,const uint32_t*fixed,const uint32_t*main,const uint32_t*parameters,uint32_t*n,uint32_t*d,uint32_t*status,uint32_t log'
    declarations='\n'.join(f'extern "C" int {name}({signature});' for name in names)
    calls=''.join(f'if(int e={name}(ctx,lane,fixed,main,parameters,n,d,status,log))return e;' for name in names)
    path=output/f'{symbol}_dispatch.cpp';path.write_text('#include <stdint.h>\n'+declarations+f'\nextern "C" __attribute__((visibility("default"))) int {symbol}({signature}){{{calls}return 0;}}\n');files.append(str(path))
    return files
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);p.add_argument('--pairs',type=int,default=16);args=p.parse_args();print(json.dumps(partition(args.source,args.output,args.pairs)))
