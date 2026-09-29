"""Independent diagnostic-only M31/QM31 replay of actual device constraint inputs."""
import json,struct,sys
from pathlib import Path
P=2147483647
Z=(0,0,0,0)
def add(a,b): return tuple((x+y)%P for x,y in zip(a,b))
def neg(a): return tuple(-x%P for x in a)
def sub(a,b): return add(a,neg(b))
def cmul(a,b):return ((a[0]*b[0]-a[1]*b[1])%P,(a[0]*b[1]+a[1]*b[0])%P)
def mul(a,b):
    ac=cmul(a[:2],b[:2]);bd=cmul(a[2:],b[2:]);beta=cmul(bd,(2,1))
    ad=cmul(a[:2],b[2:]);bc=cmul(a[2:],b[:2])
    return ((ac[0]+beta[0])%P,(ac[1]+beta[1])%P,(ad[0]+bc[0])%P,(ad[1]+bc[1])%P)
def scale(a,b):return tuple(x*b%P for x in a)
def replay(path):
    files=sorted(path.glob('eval-component-*.json'),key=lambda p:int(p.stem.split('-')[-1]))
    components=[json.loads(p.read_text()) for p in files]
    data=(path/'eval-debug.bin').read_bytes();words=struct.unpack('<'+'I'*(len(data)//4),data)
    n=components[0]['total_constraints']; powers=[tuple(words[i:i+4]) for i in range(0,n*4,4)];cursor=n*4;results=[]
    one_extent=n*4+sum(3*(len(c['preprocessed_indices'])+sum(s['end']-s['start'] for s in c['trace_spans'] if s['tree'] in [1,2]))+4*c['ext_parameter_count']+8 for c in components)
    samples=1 if len(words)==one_extent else 8
    for index,c in enumerate(components):
        spans=c['trace_spans']; counts=[len(c['preprocessed_indices'])]+[sum(s['end']-s['start'] for s in spans if s['tree']==t) for t in [1,2]]
        count=sum(counts);packets=[]
        for sample in range(samples):
            planes=[words[cursor+i*count:cursor+(i+1)*count] for i in range(3)];cursor+=3*count
            ec=c['ext_parameter_count'];params=[tuple(words[cursor+i*4:cursor+(i+1)*4]) for i in range(ec)];cursor+=4*ec
            before=tuple(words[cursor:cursor+4]);cursor+=4
            packets.append((planes,params,before))
        afters=[tuple(words[cursor+i*4:cursor+(i+1)*4]) for i in range(samples)];cursor+=samples*4
        N=1<<c['evaluation_log_size'];rows=[0,1,2,3,N//4,N//2,N-2,N-1][:samples]
        for row,(planes,params,before),after in zip(rows,packets,afters):
            expected=before
            for ordinal in range(c['part_count']):
                p=json.loads((path/f'eval-part-{index}-{ordinal}.json').read_text());base={};ext={}
                for inst in p['base_insts']:
                    op=inst['op'];a=inst['a'];b=inst['b'];imm=inst['imm']
                    if op in ('trace_col','preprocessed_col'):
                        if imm not in (-1,0,1):raise ValueError(f'unsupported mask {imm}')
                        tree=0 if op=='preprocessed_col' else inst['interaction'];col=sum(counts[:tree])+a
                        v=planes[imm+1][col]
                    elif op=='constant':v=a
                    elif op=='param':raise ValueError('base params not captured')
                    elif op=='add':v=base[a]+base[b]
                    elif op=='sub':v=base[a]-base[b]
                    elif op=='mul':v=base[a]*base[b]
                    elif op=='neg':v=-base[a]
                    elif op=='inv':v=pow(base[a],P-2,P)
                    else:raise ValueError(op)
                    base[inst['dst']]=v%P
                for inst in p['ext_insts']:
                    op=inst['op'];a=inst['a'];b=inst['b']
                    if op=='secure_col':v=tuple(base[inst[k]] for k in ('a','b','c','d'))
                    elif op=='param':v=params[a]
                    elif op=='constant':v=tuple(inst[k] for k in ('a','b','c','d'))
                    elif op=='add':v=add(ext[a],ext[b])
                    elif op=='sub':v=sub(ext[a],ext[b])
                    elif op=='mul':v=mul(ext[a],ext[b])
                    elif op=='neg':v=neg(ext[a])
                    else:raise ValueError(op)
                    ext[inst['dst']]=v
                delta=Z
                for k,root in enumerate(p['constraint_roots']):delta=add(delta,mul(ext[root],powers[c['random_coefficient_offset']+p['rc_base']+k]))
                expected=add(expected,scale(delta,c['denominator_inverses'][row >> c['trace_log_size']]))
            results.append(dict(index=index,label=c['label'],row=row,matches=expected==after,expected=expected,actual=after,before=before))
    if cursor!=len(words):raise ValueError(f'layout remainder {len(words)-cursor}')
    report={'full_proof_verified':False,'accepted_benchmark':False,'components':results,'matching_components':sum(r['matches'] for r in results),'component_count':len(results)}
    print(json.dumps(report,indent=2))
if __name__=='__main__':replay(Path(sys.argv[1]))
