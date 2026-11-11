#!/usr/bin/env python3
"""Closed-admission BN254 pairing schedule oracle; no guest/ISA/provider changes.

Independent Python integer arithmetic evaluates the complete input validity,
prepared-line recurrence, signed Miller loop and positive residue obligation.
Operation counters describe THIS deliberately conservative schedule, not an AIR
or the optimized Arkworks instruction count. No host supplied validity/result bit
is an input to accept_positive. Infinity never suppresses point validation.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
import hashlib
import json
from math import gcd
from pathlib import Path
import re

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
X = 4965661367192848881
ATE = (0,0,0,1,0,1,0,-1,0,0,-1,0,0,0,1,0,0,-1,0,-1,0,0,0,1,0,-1,0,0,0,0,-1,0,0,1,0,-1,0,0,1,0,0,0,0,0,-1,0,0,-1,0,1,0,-1,0,0,0,-1,0,-1,0,0,0,1,0,1,1)
O2 = (1, 0); Z2 = (0, 0); XI = (9, 1)
O6 = (O2, Z2, Z2); Z6 = (Z2, Z2, Z2)
O12 = (O6, Z6); Z12 = (Z6, Z6)
QX = (21575463638280843010398324269430826099269044274347216827212613867836435027261,10307601595873709700152284273816112264069230130616436755625194854815875713954)
QY = (2821565182194536844548159561693502659359617185244120367078079554186484126554,3505843767911556378687030309984248845540243509899259641013678093033130930403)
G1 = (1, 2)
G2 = ((10857046999023057135944570762232829481370756359578518086990519993285655852781,11559732032986387107991004021392285783925812861821192530917403151452391805634),(8495653923123431417604973247489272438418190587263600148770280649306958101930,4082367875863433681332203403145435568316851327593401208105741076214120093531))
COUNTS = defaultdict(Counter)
PHASE = None
OPS = Counter()
SCHEDULE = []

def note(op, n=1):
    if PHASE is not None:
        COUNTS[PHASE][op] += n

def semantic(op, **kw):
    if PHASE is not None:
        OPS[op] += 1
        SCHEDULE.append({'op': op, **kw})

@contextmanager
def phase(name):
    global PHASE
    old = PHASE; PHASE = name
    try: yield
    finally: PHASE = old

def add(a,b): note('fq_add'); return (a+b)%P
def sub(a,b): note('fq_sub'); return (a-b)%P
def mul(a,b): note('fq_mul'); return a*b%P
def inv(a):
    if not a: raise ValueError('zero inverse')
    value = pow(a,-1,P)
    # Witness generation is host arithmetic. One mandatory product equation
    # proves the inverse; the result is a canonical Fq writer like every op.
    note('fq_inverse_witness'); assert mul(a,value)==1
    return value

def a2(a,b): return (add(a[0],b[0]),add(a[1],b[1]))
def s2(a,b): return (sub(a[0],b[0]),sub(a[1],b[1]))
def n2(a): return s2(Z2,a)
def m2(a,b):
    v0=mul(a[0],b[0]); v1=mul(a[1],b[1])
    return (sub(v0,v1),sub(sub(mul(add(a[0],a[1]),add(b[0],b[1])),v0),v1))
def scale2(a,b): return (mul(a[0],b),mul(a[1],b))
def i2(a):
    d=inv(add(mul(a[0],a[0]),mul(a[1],a[1])))
    return (mul(a[0],d),sub(0,mul(a[1],d)))
def p2(a,e):
    out=O2
    for bit in bin(e)[2:]:
        out=m2(out,out)
        if bit=='1': out=m2(out,a)
    return out

def a6(a,b): return tuple(a2(x,y) for x,y in zip(a,b))
def s6(a,b): return tuple(s2(x,y) for x,y in zip(a,b))
def nr6(a): return (m2(a[2],XI),a[0],a[1])
def m6(a,b):
    v=[m2(a[i],b[i]) for i in range(3)]
    c0=a2(v[0],m2(s2(s2(m2(a2(a[1],a[2]),a2(b[1],b[2])),v[1]),v[2]),XI))
    c1=a2(s2(s2(m2(a2(a[0],a[1]),a2(b[0],b[1])),v[0]),v[1]),m2(v[2],XI))
    c2=a2(s2(s2(m2(a2(a[0],a[2]),a2(b[0],b[2])),v[0]),v[2]),v[1])
    return (c0,c1,c2)
def a12(a,b): return (a6(a[0],b[0]),a6(a[1],b[1]))
def m12(a,b):
    v0=m6(a[0],b[0]); v1=m6(a[1],b[1])
    return (a6(v0,nr6(v1)),s6(s6(m6(a6(a[0],a[1]),a6(b[0],b[1])),v0),v1))
def p12(a,e):
    out=O12
    for bit in bin(e)[2:]:
        out=m12(out,out)
        if bit=='1': out=m12(out,a)
    return out

FROB = {}
def frob12(a,k):
    if k not in FROB:
        # Immutable constants derived in the same extension, outside witness
        # work. This is not an advice-dependent optimization.
        with phase(None):
            e=P**k-1
            FROB[k]=(p2(XI,e//3),p2(XI,2*e//3),p2(XI,e//6))
    c1,c2,c12=FROB[k]
    def conj(v): return v if k%2==0 else (v[0],sub(0,v[1]))
    def f6(v): return (conj(v[0]),m2(conj(v[1]),c1),m2(conj(v[2]),c2))
    return (f6(a[0]),tuple(m2(c,c12) for c in f6(a[1])))

def neg_point(q, extension=True):
    if q is None: return None
    return (q[0],n2(q[1]) if extension else sub(0,q[1]))
def plus(q,t,extension=True):
    if q is None: return t
    if t is None: return q
    A,S,M,I,Z=(a2,s2,m2,i2,Z2) if extension else (add,sub,mul,inv,0)
    C=lambda n:(n,0) if extension else n
    if q[0]==t[0] and A(q[1],t[1])==Z: return None
    if q==t: slope=M(M(C(3),M(q[0],q[0])),I(M(C(2),q[1])))
    else: slope=M(S(t[1],q[1]),I(S(t[0],q[0])))
    x=S(S(M(slope,slope),q[0]),t[0])
    return (x,S(M(slope,S(q[0],x)),q[1]))
def times(q,n,extension=True):
    out=None
    for bit in bin(n)[2:]:
        out=plus(out,out,extension)
        if bit=='1': out=plus(out,q,extension)
    return out

def psi(q):
    if q is None:return None
    return (m2((q[0][0],sub(0,q[0][1])),QX),m2((q[1][0],sub(0,q[1][1])),QY))

with phase(None): B2=scale2(i2(XI),3)

def canonical(v):
    if not 0<=v<P: raise ValueError('noncanonical coordinate')
    note('canonical_input')
    return v

def validate(p,q):
    for x in p: canonical(x)
    for coord in q:
        for x in coord:canonical(x)
    # Infinity is exactly all-zero pair; neither counterpart gates validation.
    p=None if p==(0,0) else p
    q=None if q==(Z2,Z2) else q
    semantic('validate_g1', infinity=p is None)
    if p is not None and mul(p[1],p[1])!=add(mul(mul(p[0],p[0]),p[0]),3): raise ValueError('G1 off curve')
    # BN254 G1 has cofactor1; curve membership+canonicality suffice.
    semantic('validate_g2', infinity=q is None)
    if q is not None:
        if m2(q[1],q[1])!=a2(m2(m2(q[0],q[0]),q[0]),B2): raise ValueError('G2 off curve')
        semantic('subgroup_6x2_vs_psi')
        if times(q,6*X*X)!=psi(q):raise ValueError('G2 subgroup')
    return p,q

def double_line(r):
    x,y,z=r
    a=scale2(m2(x,y),(P+1)//2); b=m2(y,y); c=m2(z,z)
    e=m2(B2,a2(a2(c,c),c)); f=a2(a2(e,e),e)
    g=scale2(a2(b,f),(P+1)//2); h=s2(m2(a2(y,z),a2(y,z)),a2(b,c))
    i=s2(e,b); j=m2(x,x); es=m2(e,e)
    out=(m2(a,s2(b,f)),s2(m2(g,g),a2(a2(es,es),es)),m2(b,h))
    return out,(n2(h),a2(a2(j,j),j),i)
def add_line(r,q):
    x,y,z=r
    theta=s2(y,m2(q[1],z)); lam=s2(x,m2(q[0],z))
    c=m2(theta,theta); d=m2(lam,lam); e=m2(lam,d); f=m2(z,c); g=m2(x,d)
    h=s2(a2(e,f),a2(g,g)); nx=m2(lam,h)
    ny=s2(m2(theta,s2(g,h)),m2(e,y)); nz=m2(z,e)
    j=s2(m2(theta,q[0]),m2(lam,q[1]))
    return (nx,ny,nz),(lam,n2(theta),j)
def prepare(q):
    r=(q[0],q[1],O2); lines=[]
    for digit in reversed(ATE[:-1]):
        semantic('prepare_double')
        r,line=double_line(r); lines.append(line)
        if digit:
            semantic('prepare_add',sign=digit)
            r,line=add_line(r,q if digit==1 else neg_point(q)); lines.append(line)
    q1=psi(q);q2=neg_point(psi(q1))
    for t in (q1,q2):
        semantic('prepare_frobenius_correction')
        r,line=add_line(r,t);lines.append(line)
    assert len(lines)==87
    return lines

def loop_program(group_count,seeded):
    """Immutable typed macro schedule: op, group-or-sign, exact line index.

    This is a prototype scheduling authority, not a proof parser. All branches
    derive from source ATE digits and validated group count, never hint values.
    """
    if not 0<=group_count<=16:raise ValueError('group count')
    program=[];line=0
    def lines():
        nonlocal line
        for group in range(group_count):program.append(('line034',group,line))
        line+=1
    for i in range(len(ATE)-1,0,-1):
        if seeded or i!=len(ATE)-1:program.append(('square',0,0))
        lines()
        if ATE[i-1]:
            if seeded:program.append(('seed_multiply',ATE[i-1],0))
            lines()
    lines();lines();assert line==87
    return tuple(program)

def execute_loop(groups,program,seed=None,inverse=None):
    # No program supplied by an untrusted hint can select less work.
    if tuple(program)!=loop_program(len(groups),seed is not None):
        raise ValueError('non-source loop program')
    value=O12 if seed is None else seed
    for op,index,line in program:
        if op=='square':
            semantic('fp12_square');value=m12(value,value)
        elif op=='seed_multiply':
            semantic('fp12_seed_multiply',sign=index)
            value=m12(value,seed if index==1 else inverse)
        elif op=='line034':
            point,prepared=groups[index]
            c0,c1,c2=prepared[line]
            c0=scale2(c0,point[1]);c1=scale2(c1,point[0])
            semantic('sparse034_line',line=line)
            value=m12(value,((c0,Z2,Z2),(c1,c2,Z2)))
        else:raise AssertionError('impossible source opcode')
    return value

def miller(groups,seed=None,inverse=None):
    return execute_loop(groups,loop_program(len(groups),seed is not None),seed,inverse)

def decode_pair(raw):
    if len(raw)!=192:raise ValueError('pair width')
    f=[int.from_bytes(raw[i:i+32],'big') for i in range(0,192,32)]
    return ((f[0],f[1]),((f[3],f[2]),(f[5],f[4])))
def encode_pair(p,q):
    if p is None:p=(0,0)
    if q is None:q=(Z2,Z2)
    return b''.join(v.to_bytes(32,'big') for v in (p[0],p[1],q[0][1],q[0][0],q[1][1],q[1][0]))

def groups_for(pairs):
    if len(pairs)>16:raise ValueError('fastpath bounded16 pairs; fallback required')
    points=[]
    with phase('input_validity'):
        for raw in pairs:points.append(validate(*decode_pair(raw)))
    with phase('prepared_lines'):
        return [(p,prepare(q)) for p,q in points if p is not None and q is not None]

def universal(pairs):
    groups=groups_for(pairs)
    with phase('miller_unseeded'):value=miller(groups)
    with phase('final_exponent_reference'):
        semantic('full_final_exponent_reference')
        return value!=Z12 and p12(value,(P**12-1)//R)==O12

def hint_for(pairs):
    # HOST oracle only: never included in provider work counters.
    with phase(None):
        groups=groups_for(pairs)
        with phase(None):value=miller(groups)
        kernel=(P**12-1)//R;remaining=kernel//27;lam=P**3-P**2+P+6*X+2
        assert gcd(remaining,lam)==1 and lam%R==0
        scale=p12(value,(-remaining*pow(remaining,-1,27))%kernel)
        if scale[1]!=Z6:raise ValueError('not positive')
        seed=p12(m12(value,scale),(-pow(lam,-1,remaining))%remaining)
        inverse=p12(seed,P**12-2)
        return seed,inverse,scale[0]

def accept_positive(pairs,hint):
    groups=groups_for(pairs)
    seed,inverse,scale=hint
    with phase('hint_inverse'):
        for plane in (*seed,*inverse,scale):
            for coord in plane:
                for x in coord:canonical(x)
        semantic('checked_seed_inverse')
        if m12(seed,inverse)!=O12:return False
    with phase('miller_seeded'):value=miller(groups,seed,inverse)
    with phase('residue_tail'):
        semantic('frobenius_tail_3_2_1')
        power=m12(m12(frob12(seed,3),frob12(inverse,2)),frob12(seed,1))
        value=m12(m12(value,power),(scale,Z6))
        semantic('require_residue_one')
        return value==O12

def reset():COUNTS.clear();OPS.clear();SCHEDULE.clear()
def snapshot():
    return {'semantic_ops':dict(sorted(OPS.items())), 'fq_ops_by_phase':{k:dict(sorted(v.items())) for k,v in COUNTS.items()},'fq_ops_total':dict(sum(COUNTS.values(),Counter()))}

def source_check(repo):
    paths=['opstack/kona/vendor/ark-bn254/src/curves/mod.rs','opstack/kona/src/precompiles/pairing_miller.rs','opstack/kona/src/precompiles/pairing_residue.rs','opstack/kona/src/precompiles/pairing.rs','opstack/kona/src/precompiles/pairing_hint_stream.rs','opstack/kona/vendor/ark-bn254/src/curves/g2.rs','opstack/kona/vendor/ark-bn254/src/fields/fq6.rs','opstack/kona/vendor/ark-bn254/src/fields/fq12.rs']
    source=(repo/paths[0]).read_text()
    digits=re.search(r'ATE_LOOP_COUNT:.*?=\s*&\[(.*?)\];',source,re.S)
    assert tuple(map(int,re.findall(r'-?\d+',digits.group(1))))==ATE
    assert sum(d*(1<<i) for i,d in enumerate(ATE))==6*X+2
    assert (P**3-P**2+P+6*X+2)%R==0
    assert ((P**12-1)//R)%(P**6-1)==0
    assert gcd(P**6-1,R)==1
    for value in (*QX,*QY):assert str(value) in source
    g2=(repo/'opstack/kona/vendor/ark-bn254/src/curves/g2.rs').read_text()
    for coord in G2:
        for value in coord:assert str(value) in g2
    return {p:hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in paths}


def sqrt2(v):
    """Host-only non-subgroup negative fixture construction, never authority."""
    a,b=v
    if b==0:
        r=pow(a,(P+1)//4,P)
        if r*r%P==a:return (r,0)
        r=pow(-a%P,(P+1)//4,P)
        if -r*r%P==a:return (0,r)
        return None
    norm=pow((a*a+b*b)%P,(P+1)//4,P)
    if norm*norm%P!=(a*a+b*b)%P:return None
    for t in (norm,-norm%P):
        square=(a+t)*pow(2,-1,P)%P
        x=pow(square,(P+1)//4,P)
        if x*x%P==square and x:
            out=(x,b*pow(2*x,-1,P)%P)
            if m2(out,out)==v:return out
    return None


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[3]);parser.add_argument('--census',type=Path);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();sources=source_check(args.repo)
    positive=[encode_pair(G1,G2),encode_pair((1,P-2),G2)]
    # Independent integer exponentiation verifies the actual Miller output;
    # the residue hint is then generated and checked via the signed schedule.
    assert universal(positive)
    with phase(None): hint=hint_for(positive)
    reset();assert accept_positive(positive,hint);positive_cost=snapshot()
    schedule_digest=hashlib.sha256(json.dumps(SCHEDULE,separators=(",",":")).encode()).hexdigest()
    # Same point with no cancelling partner must not accept this positive hint.
    assert not accept_positive([positive[0]],hint)
    assert not universal([positive[0]])
    assert accept_positive([], (O12,O12,O6))
    assert accept_positive([encode_pair(None,None)], (O12,O12,O6))
    try:accept_positive([encode_pair((1,1),None)],hint);raise AssertionError('invalid G1 hidden by infinity')
    except ValueError as error:assert str(error)=='G1 off curve'
    try:execute_loop([], (('seed_multiply',1,0),));raise AssertionError('forged schedule accepted')
    except ValueError as error:assert str(error)=='non-source loop program'
    bad_seed=(Z12,hint[1],hint[2]);assert not accept_positive(positive,bad_seed)
    bad_scale=(hint[0],hint[1],a6(hint[2],O6));assert not accept_positive(positive,bad_scale)
    # Invalid counterpart cannot hide behind an infinity G1 input.
    invalid=encode_pair(None,((1,0),(1,0)))
    try:accept_positive([invalid],hint);raise AssertionError('invalid G2 hidden by infinity')
    except ValueError:pass
    noncanonical=bytes(P.to_bytes(32,'big'))+positive[0][32:]
    try:accept_positive([noncanonical],hint);raise AssertionError('canonical alias')
    except ValueError:pass
    with phase(None):
        non_subgroup=None
        for i in range(1,100):
            qx=(i,1); qy=sqrt2(a2(m2(m2(qx,qx),qx),B2))
            if qy is not None and times((qx,qy),6*X*X)!=psi((qx,qy)):
                non_subgroup=(qx,qy);break
        assert non_subgroup is not None
    try:accept_positive([encode_pair(None,non_subgroup)],hint);raise AssertionError('invalid subgroup hidden by infinity')
    except ValueError as error:assert str(error)=='G2 subgroup'
    report={'schema' :'op-complete-pairing-positive-schedule-v1','production_admission':False,'security_qualified':False,'scope':'independent arithmetic/schedule oracle, not AIR/proof/retirement benchmark','source_sha256':sources,'ate':{'digits':len(ATE),'doublings':64,'signed_additions':sum(d!=0 for d in ATE[:-1]),'lines_per_group':87,'seeded_squares':64,'unseeded_squares':63},'positive_two_pair_cost':positive_cost,'positive_two_pair_schedule_sha256':schedule_digest,'checks':['complete positive pairing against generic final exponent','single generator pairing false','seed inverse mutation','scale mutation','G1 infinity does not hide invalid G2','Fq modulus alias rejected','on-curve non-subgroup G2 rejected even with G1 infinity','omitted/reordered loop opcode schedule rejected','empty input and canonical infinities accepted','G2 infinity does not hide invalid G1']}
    if args.census:
        rows=json.loads(args.census.read_text())
        selected=[bytes.fromhex(pair) for pair in rows[0]['pairs']]
        reset();assert universal(selected)==rows[0]['result']
        with phase(None):selected_hint=hint_for(selected)
        reset();assert accept_positive(selected,selected_hint)
        report['actual_four_pair_positive']={'pairs_hex':rows[0]['pairs'],'expected_result':True,'loop_program_sha256':hashlib.sha256(json.dumps(loop_program(4,True),separators=(',',':')).encode()).hexdigest(),'schedule_cost':snapshot()}
        report['retained_census']={'sha256':hashlib.sha256(args.census.read_bytes()).hexdigest(),'calls':len(rows),'pairs':sum(len(r['pairs']) for r in rows),'positive':sum(r['result'] is True for r in rows),'false':sum(r['result'] is False for r in rows),'invalid':sum(r['result'] is None for r in rows),'distinct_g2':len({p[128:] for r in rows for p in r['pairs']})}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('positive_two_pair_schedule',)},indent=2))

if __name__=='__main__':main()
