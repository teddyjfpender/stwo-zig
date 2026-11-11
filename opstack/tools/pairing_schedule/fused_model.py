#!/usr/bin/env python3
"""Source-only fused quadratic schedule/carry cost; no AIR/admission change.

All homogeneous formulas retain Ark's exact line normalization. The Python
carry derivation mirrors curves/spec.zig and must pass pinned dense envelopes.
This is a source model; active cells omit real component padding unless stated.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
import argparse, hashlib, json
from pathlib import Path
import oracle as O
P=O.P; M31=2**31-1

@dataclass
class Poly:
    terms: dict
    def __add__(self,other):
        out=Counter(self.terms)
        for m,c in other.terms.items():out[m]+=c
        return Poly({m:c for m,c in out.items() if c})
    def __neg__(self):return Poly({m:-c for m,c in self.terms.items()})
    def __sub__(self,other):return self+-other
    def __mul__(self,other):
        out=Counter()
        for a,c in self.terms.items():
            for b,d in other.terms.items():
                mono=tuple(sorted(a+b))
                if len(mono)>2:raise ValueError('non-quadratic source expression')
                out[mono]+=c*d
        return Poly({m:c for m,c in out.items() if c})
    def scale(self,n):return Poly({m:c*n for m,c in self.terms.items() if c*n})
    def evaluate(self,values):
        result=0
        for mono,c in self.terms.items():
            term=c
            for name in mono:term*=values[name]
            result+=term
        return result%P

def var(name):return Poly({(name,):1})
def aa(a,b):return (a[0]+b[0],a[1]+b[1])
def ss(a,b):return (a[0]-b[0],a[1]-b[1])
def mm(a,b):return (a[0]*b[0]-a[1]*b[1],a[0]*b[1]+a[1]*b[0])
def sc(a,n):return tuple(x.scale(n) for x in a)

class Fused:
    def __init__(self):self.values={};self.relations=[]
    def bind(self,name,values):
        for i,v in enumerate(values):self.values[f'{name}{i}']=v
        return tuple(var(f'{name}{i}') for i in range(len(values)))
    def write(self,name,expression):
        values=tuple(x.evaluate(self.values) for x in expression)
        output=self.bind(name,values)
        for i,(p,q) in enumerate(zip(expression,output)):
            relation=p-q
            self.relations.append(relation)
            assert relation.evaluate(self.values)==0
            forged=dict(self.values);forged[f'{name}{i}']=(forged[f'{name}{i}']+1)%P
            assert relation.evaluate(forged)!=0
        return output
    def point(self):return tuple(tuple(self.values[f'{n}{i}'] for i in range(2)) for n in ('X','Y','Z'))

def homogeneous_double(point):
    f=Fused();x=f.bind('x',point[0]);y=f.bind('y',point[1]);z=f.bind('z',point[2])
    half=f.bind('half',((P+1)//2,))[0];B=f.bind('B',O.B2)
    k=f.write('k',mm(x,y));a=f.write('a',tuple(t*half for t in k))
    b=f.write('b',mm(y,y));c=f.write('c',mm(z,z));e=f.write('e',sc(mm(B,c),3))
    g=f.write('g',tuple(t*half for t in aa(b,sc(e,3))))
    h=f.write('h',sc(mm(y,z),2));j=f.write('j',mm(x,x))
    f.write('X',mm(a,ss(b,sc(e,3))));f.write('Y',ss(mm(g,g),sc(mm(e,e),3)));f.write('Z',mm(b,h))
    i=f.write('i',ss(e,b))
    line=tuple(tuple(v.evaluate(f.values) for v in p) for p in (sc(h,-1),sc(j,3),i))
    expected,expected_line=O.double_line(point)
    assert f.point()==expected and line==expected_line
    return f

def homogeneous_add(point,q):
    f=Fused();x=f.bind('x',point[0]);y=f.bind('y',point[1]);z=f.bind('z',point[2]);qx=f.bind('qx',q[0]);qy=f.bind('qy',q[1])
    theta=f.write('t',ss(y,mm(qy,z)));lam=f.write('l',ss(x,mm(qx,z)))
    c=f.write('c',mm(theta,theta));d=f.write('d',mm(lam,lam));e=f.write('e',mm(lam,d));v=f.write('f',mm(z,c));g=f.write('g',mm(x,d))
    h=ss(aa(e,v),sc(g,2))
    f.write('X',mm(lam,h));f.write('Y',ss(mm(theta,ss(g,h)),mm(e,y)));f.write('Z',mm(z,e))
    j=f.write('j',ss(mm(theta,qx),mm(lam,qy)))
    line=tuple(tuple(v.evaluate(f.values) for v in p) for p in (lam,sc(theta,-1),j))
    expected,expected_line=O.add_line(point,q)
    assert f.point()==expected and line==expected_line
    return f

def affine_step(a,b):
    """Eight scalar congruences; slope/inverse range-checked witness ports.

    The fixed scalar path starts after its leading1. Zero denominators are
    outside this positive fastpath and force CPU fallback, never free advice.
    """
    doubling=a==b
    denominator=O.scale2(a[1],2) if doubling else O.s2(b[0],a[0])
    inverse=O.i2(denominator)
    numerator=O.scale2(O.m2(a[0],a[0]),3) if doubling else O.s2(b[1],a[1])
    slope=O.m2(numerator,inverse)
    result=O.plus(a,b)
    assert result is not None
    f=Fused();x=f.bind('x',a[0]);y=f.bind('y',a[1]);bx=f.bind('bx',b[0]);by=f.bind('by',b[1])
    iv=f.bind('iv',inverse);sl=f.bind('s',slope);rx=f.bind('rx',result[0]);ry=f.bind('ry',result[1]);one=f.bind('one',O.O2)
    d=sc(y,2) if doubling else ss(bx,x)
    n=sc(mm(x,x),3) if doubling else ss(by,y)
    expressions=(ss(mm(d,iv),one),ss(mm(d,sl),n),ss(ss(mm(sl,sl),aa(x,bx)),rx),ss(ss(mm(sl,ss(x,rx)),y),ry))
    for expression in expressions:
        for relation in expression:
            assert relation.evaluate(f.values)==0
            f.relations.append(relation)
    assert len(f.relations)==8
    for name in ('iv0','iv1','s0','s1','rx0','rx1','ry0','ry1'):
        forged=dict(f.values);forged[name]=(forged[name]+1)%P
        assert any(p.evaluate(forged)!=0 for p in f.relations)
    return f,result

def basis(x,y):
    out=[0]*12;i=x%2+y%2;v=(x//2)%3+(y//2)%3;w=x//6+y//6;v+=w//2
    sign=(-1)**(i//2);out[i%2+2*(v%3)+6*(w%2)]+=sign*(1 if v<3 else 9)
    if v>=3:out[(i+1)%2+2*(v%3)+6*(w%2)]+=(-1)**((i+1)//2)
    return out

def sparse_relations():
    # Scaled sparse034 coefficients are already canonical local SSA writers.
    active=(0,1,6,7,8,9);relations=[]
    for coordinate in range(12):
        terms={}
        for a in range(12):
            for b in active:
                c=basis(a,b)[coordinate]
                if c:terms[(f'a{a}',f'b{b}')]=c
        terms[(f'out{coordinate}',)]=-1
        relations.append(Poly(terms))
    return relations

def masses(relations):
    result=[0,0,0,0]
    for relation in relations:
        values=[0,0,0,0]
        for mono,c in relation.terms.items():
            assert 1<=len(mono)<=2
            index=(0 if len(mono)==2 else 2)+(c<0)
            values[index]+=abs(c)
        result=[max(a,b) for a,b in zip(result,values)]
    return result

def carry_geometry(mass):
    """Exact integer port of asymmetric deriveRelation for mass envelopes."""
    pp,nn,lp,ln=mass;L=32;vmax=2**256-1
    pos=pp*vmax*vmax+lp*vmax;neg=nn*vmax*vmax+ln*vmax
    k=(neg+P-1)//P;kp=k*P;qbytes=(((pos+kp)//P).bit_length()+7)//8
    coefficients=max(63 if pp or nn else 32,qbytes+31,(kp.bit_length()+7)//8)
    p=[0]*160;n=[0]*160
    for j in range(63):
        pairs=min(j,31)-max(0,j-31)+1
        p[j]+=pp*255*255*pairs;n[j]+=nn*255*255*pairs
    for j in range(32):p[j]+=lp*255;n[j]+=ln*255
    for j in range(coefficients):p[j]+=(kp>>(8*j))&255
    for i in range(qbytes):
        for j in range(32):n[i+j]+=255*((P>>(8*j))&255)
    for group in (2,1):
        radix=1<<(8*group);groups=(coefficients+group-1)//group
        positive=negative=hp=hn=partialp=partialn=0
        for j in range(groups):
            gp=gn=0
            for off in range(group):
                i=group*j+off
                if i>=coefficients:continue
                gp+=p[i]<<(8*off);gn+=n[i]<<(8*off)
                partialp+=p[i]<<(8*i);partialn+=n[i]<<(8*i)
            positive=max(positive,gp);negative=max(negative,gn)
            if j+1<groups:
                hp=max(hp,partialp>>(8*group*(j+1)));hn=max(hn,partialn>>(8*group*(j+1)))
        span=hp+hn+1
        if span>=M31:continue
        bits=max(1,(span-1).bit_length());width=1<<bits
        pb=positive+width-1;nb=negative+radix*(width-1)
        if pb>=M31:continue
        step=radix-1
        low=max(hn,max(0,(nb-(M31-1)+step-1)//step))
        high=min(width-1-hp,(M31-1-pb)//step)
        if low>high:continue
        offset=low+(high-low)//2;upper=width-1-offset
        rp=positive+upper+radix*offset;rn=negative+offset+radix*upper
        assert rp<M31 and rn<M31
        return {'q_bytes':qbytes,'groups':groups,'carries':groups-1,'carry_bits':bits,'carry_bytes':(bits+7)//8,'carry_offset':offset,'residual_positive':rp,'residual_negative':rn}
    raise ValueError('no M31 exact carry geometry')

def cost(relations):
    mass=masses(relations);g=carry_geometry(mass)
    deps=max(len({v for m in p.terms for v in m}) for p in relations)
    # One designated canonical result/witness coordinate per equation. Source
    # constants are still counted as input slots; branch controls are separate.
    inputs=deps-1
    main=1+32*inputs+32+g['q_bytes']+g['carries']*g['carry_bytes']+32+15+1
    bytes_=32+g['q_bytes']+g['carries']*g['carry_bytes']+(g['carries'] if g['carry_bits']%8 else 0)+32
    return {'coordinate_congruences':len(relations),'max_input_fq_slots':inputs,'coefficient_mass':mass,'geometry':g,'main':main,'byte_queries':bytes_,'arithmetic_cells_at_40_inter':len(relations)*(main+40),'qualification':'source model only; source SSA/range/binding/branch selectors and actual padding not implemented'}

def sparse_numeric_checks():
    def flatten(value):return [x for plane in value for pair in plane for x in pair]
    def unflatten(values):return tuple(tuple(tuple(values[k*6+j*2+i] for i in range(2)) for j in range(3)) for k in range(2))
    relations=sparse_relations();active=(0,1,6,7,8,9)
    cases=[]
    for a in range(12):
        for b in active:
            x=[0]*12;y=[0]*12;x[a]=1;y[b]=1;cases.append((x,y))
    for seed in range(17):
        x=[(seed*0x123456789abcdef+i*i+1)%P for i in range(12)]
        y=[0]*12
        for i in active:y[i]=(P-1 if seed==0 else (seed+1)*(i+3))
        cases.append((x,y))
    for a,b in cases:
        expected=flatten(O.m12(unflatten(a),unflatten(b)))
        values={**{f'a{i}':v for i,v in enumerate(a)},**{f'b{i}':v for i,v in enumerate(b)},**{f'out{i}':v for i,v in enumerate(expected)}}
        assert all(p.evaluate(values)==0 for p in relations)
        for i in range(12):
            forged=dict(values);forged[f'out{i}']=(expected[i]+1)%P
            assert relations[i].evaluate(forged)!=0
    return len(cases)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--receipt',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--census',type=Path);ap.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[3]);args=ap.parse_args()
    sparse_cases=sparse_numeric_checks()
    source=json.loads(args.receipt.read_text());pairs=[O.decode_pair(bytes.fromhex(p)) for p in source['actual_four_pair_positive']['pairs_hex']]
    ds=[];ads=[];affines=[]
    for _,q in pairs:
        r=(q[0],q[1],O.O2)
        for digit in reversed(O.ATE[:-1]):
            f=homogeneous_double(r);ds.append(f);r=f.point()
            if digit:
                f=homogeneous_add(r,q if digit==1 else O.neg_point(q));ads.append(f);r=f.point()
        for t in (O.psi(q),O.neg_point(O.psi(O.psi(q)))):
            f=homogeneous_add(r,t);ads.append(f);r=f.point()
        r=q
        for bit in bin(6*O.X*O.X)[3:]:
            f,r=affine_step(r,r);affines.append(f)
            if bit=='1':f,r=affine_step(r,q);affines.append(f)
        assert r==O.psi(q)
    double=cost([p for f in ds[:1] for p in f.relations]);addition=cost(ads[0].relations)
    affine=cost([p for f in affines for p in f.relations])
    # Common shape across both scalar double/add kinds; per-step equation count8.
    affine['coordinate_congruences']=8;affine['arithmetic_cells_at_40_inter']=8*(affine['main']+40)
    sparse=cost(sparse_relations())
    assert len(ds)==256 and len(ads)==92 and len(affines)==780
    assert double['coordinate_congruences']==24 and addition['coordinate_congruences']==22
    dense_geometry=carry_geometry((97,56,0,1))
    assert (dense_geometry['q_bytes'],dense_geometry['carry_bits'],dense_geometry['carry_offset'])==(34,21,883205)
    cold_g2=87;calls=84;input_pairs=336
    point_preparation_cells=cold_g2*(64*double['arithmetic_cells_at_40_inter']+23*addition['arithmetic_cells_at_40_inter'])
    subgroup_cells=cold_g2*195*affine['arithmetic_cells_at_40_inter']
    # Existing standalone source-cell references include their own inputfrontier.
    dense_square=9456;dense_mul=14748;old_sparse=14772
    scalar_scale_rows=4;scalar_scale_bound=426
    direct_sparse_cells=sparse['arithmetic_cells_at_40_inter']+scalar_scale_rows*scalar_scale_bound+20*57
    hot_cells=calls*(64*dense_square+(21+5)*dense_mul+4*87*direct_sparse_cells)
    report={'schema':'op-pairing-fused-source-cost-v1','production_admission':False,'security_qualified':False,'actual_request':hashlib.sha256(''.join(source['actual_four_pair_positive']['pairs_hex']).encode()).hexdigest(),'checks':{'all256homogeneous_double_steps':True,'all92homogeneous_add_steps':True,'all780affine_subgroup_steps':True,'all_original_point_outputs_and_line_coefficients_exact':True,'dense_carry_reference_exact':True,'sparse_basis_and_mixed_cases':sparse_cases,'all_canonical_writer_inverse_slope_mutations_reject':True},'homogeneous_double':double,'homogeneous_add':addition,'subgroup_affine_step':affine,'direct_sparse034':sparse,'sparse_cells':{'current32row_with_frontier':old_sparse,'candidate12direct_rows_plus4scaled_coeff_rows_plus20frontier':direct_sparse_cells,'scale_row_bound':scalar_scale_bound,'scope':'conditional source-shape estimate; no provider or AIR admission'},'heavy_active_cost':{'calls':calls,'pairs':input_pairs,'source_validated_g2_cache_entries':cold_g2,'original_homogeneous_preparation_arithmetic_cells':point_preparation_cells,'subgroup_arithmetic_cells':subgroup_cells,'seeded_miller_dense_tail_sparse_cells':hot_cells,'subtotal':point_preparation_cells+subgroup_cells+hot_cells,'excluded':['canonical public-input and hint frontiers','G1/G2 curve checks and psi terminal4coords','branch/infinity/unsupported denominator selectors','point-cache proof closure across worker shards','actual role padding and all fixed cells','remaining CPU retirements','GKR facts/memory','recursion openings/graph and whole wall time']},'separate_BYTE_table':{'main_plus_inter':17,'log':8,'cells_per_proof':4352,'planned_square_opening_columns':805,'planned_multiply_opening_columns':1189,'scope':'additional table cost excluded from original9456/14748active provider figures; full pairing role-opening sum remains unqualified'},'source_pin':source['source_sha256'],'carry_source_sha256':hashlib.sha256((args.repo/'src/frontends/riscv/rv64/air/delegations/curves/spec.zig').read_bytes()).hexdigest()}
    if args.census:
        assert hashlib.sha256(args.census.read_bytes()).hexdigest()==source['retained_census']['sha256']
        corpus=json.loads(args.census.read_text());batches=[]
        roles={'point_double':(double,lambda n,q:64*24*q),'point_add':(addition,lambda n,q:23*22*q),'subgroup':(affine,lambda n,q:195*8*q),'sparse':(sparse,lambda n,q:4*87*12*n)}
        for start in range(0,len(corpus),8):
            rows=corpus[start:start+8];n=len(rows);q=len({p[128:] for row in rows for p in row['pairs']});parts={}
            for name,(shape,count) in roles.items():
                active=count(n,q);log=max(8,(active-1).bit_length())
                parts[name]={'active_rows':active,'log':log,'padded_arithmetic_cells':(shape['main']+40)*(1<<log),'BYTE512_facts':512*(1<<log),'SSA16_facts':16*(1<<log)}
            for name,active,width,minlog in [('dense_square',n*64*12,691+40,8),('dense_multiply',n*26*12,1075+40,8),('line_scaling',n*4*87*4,370+56,15)]:
                log=max(minlog,(active-1).bit_length());parts[name]={'active_rows':active,'log':log,'padded_arithmetic_cells':width*(1<<log)}
            batches.append({'first_call':start,'calls':n,'private_validated_g2_points':q,'roles':parts})
        role_totals={}
        for batch in batches:
            for name,part in batch['roles'].items():
                summary=role_totals.setdefault(name,{'active_rows':0,'padded_arithmetic_cells':0,'log_histogram':Counter()})
                summary['active_rows']+=part['active_rows'];summary['padded_arithmetic_cells']+=part['padded_arithmetic_cells'];summary['log_histogram'][part['log']]+=1
        compact_batches=[{'first_call':b['first_call'],'calls':b['calls'],'private_validated_g2_points':b['private_validated_g2_points'],'padded_arithmetic_cells':sum(p['padded_arithmetic_cells'] for p in b['roles'].values())} for b in batches]
        report['eight_call_private_cache_model']={'batches':compact_batches,'role_totals':role_totals,'total_private_g2_validations':sum(b['private_validated_g2_points'] for b in batches),'padded_arithmetic_cells':sum(p['padded_arithmetic_cells'] for b in batches for p in b['roles'].values()),'largest_source_checkpoint_fact_bytes_52':max((p.get('BYTE512_facts',0)+p.get('SSA16_facts',0))*52 for b in batches for p in b['roles'].values()),'scope':'conditional role padding / inherited range model, NOT a whole-worker memory budget; excludes frontiers/fixed/branches/global closure and recursion'}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
