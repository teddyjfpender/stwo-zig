"""Compare saved, rejected CUDA transport samples with pinned Rust polynomials."""
import json,struct,sys
from pathlib import Path
transport=Path(sys.argv[1]).read_bytes();words=struct.unpack('<'+'I'*(len(transport)//4),transport)
oracle=json.loads(Path(sys.argv[2]).read_text())
assert words[0]==int.from_bytes(b'SWPC','little'), 'unexpected transport schema'
values=words[words[20]:words[20]+words[21]]
cursor=0;results=[]
def flat(v):
    return tuple(x for pair in v for x in pair)
for tree in oracle['trees']:
    if tree['tree']==1 and cursor==0:cursor=oracle['preprocessed_sample_count']*4
    rows=[]
    for column in tree['columns']:
        for offset,expected in enumerate(column['values']):
            actual=tuple(values[cursor:cursor+4]);cursor+=4
            rows.append(dict(ordinal=column['ordinal'],mask_index=offset,log_rows=column['log_rows'],matches=actual==flat(expected),expected=flat(expected),actual=actual))
    results.append(dict(tree=tree['tree'],samples=len(rows),matching=sum(r['matches'] for r in rows),mismatches=[r for r in rows if not r['matches']]))
print(json.dumps({'full_proof_verified':False,'accepted_benchmark':False,'trees':results},indent=2))
