"""Exact-rational CONDITIONAL model, not a receiver/certificate or protocol change."""
import argparse, hashlib, json, math, pathlib
from fractions import Fraction as F

def bits(x):
    return None if not x else math.log2(x.denominator)-math.log2(x.numerator)

def run(bundle_path, receiver_path):
    bundle=json.loads(bundle_path.read_text())
    receiver=json.JSONDecoder().raw_decode(receiver_path.read_text().lstrip())[0]
    s=receiver['source_shape']; source=receiver['source_lookup_only_conditional_degrees']
    assert receiver['profile']=='experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering'
    assert receiver['accepted'] and receiver['completed_ethereum_block']
    P=s['native_proofs']; cpus=len(bundle['cpus']); I=s['max_local_instances']; V=s['max_gkr_variables']
    C=s['max_columns']; S=s['max_samples_per_column']; N=1<<s['max_trace_log']; d=s['max_air_degree']
    assert (P,cpus,I,V,C,S,N,d)==(30,25,22,26,7371,5,1<<22,5)
    assert min(x['declaration']['geometry']['boundary_log'] for x in bundle['cpus'])==5
    rho=F(1,4); rho_plus=rho*F(34,32); alpha=F(41,64); theta=1-alpha
    assert theta < (1-rho_plus)/2 and rho_plus < alpha*alpha
    mu=F(3**8,2**256)
    product_rows=sum(1<<t['declaration']['logs'][0] for t in bundle['truths'] if t['declaration']['family']!='keccak')
    degree={
      'joint_cleared_lookup_all_scopes':source['rational_identity'],
      'gkr_sumcheck':cpus*I*3*V*(V-1)//2,
      'gkr_instance_mix':cpus*(I+2)*V,
      'gkr_late_eta_binding':cpus*I,
      'secp_product_polynomial':62*product_rows,
      'composition_mix':P*s['max_constraints'],
      # Coarse source-degree correspondence bounds; theorem mapping explicitly conditional.
      'oods_circle_correspondence':P*C*S*32*N,
      'deep_batching':P*C*S,
      # Each binary fold contributes alpha^(2^j), four folds degree15.
      # <=C insertions add <=30C; bound32(C+1). Unique CA bad-set <=degree*domain.
      'fri_unique_curve_correspondence':P*8*32*(C+1)*(4*N),
    }
    round_formula=cpus*(2*V*V+(4*I+16)*V+128)+P*(2*C*S+512+16*V)+4096
    R=1<<22
    assert round_formula<R
    query=P*alpha**256
    algebra=sum(degree.values())*mu
    E=algebra+query
    # Union per native proof plus shared-manifest challenge protocol, rather than
    # silently assuming a single global BCS collision event. One SHA identity term.
    H=3*(P+1)+1
    work=[]
    for w in [0,64,120,121,122,124,128]:
        T=1<<w
        e=(T+R)*E+F(H*(T*T+1),2**256)
        work.append({'log2_adversarial_RO_queries':w,'unclipped_error_bits':bits(e),'unclipped_error':float(e),'unclipped_success_per_query_bits':bits(e/T)})
    maxT=1<<120
    uniform_per_work=(1+R)*E+F(H*(maxT+1),2**256)
    assert uniform_per_work < F(1,1<<128)
    old=(source['tuple_collision']+source['rational_identity']+source['poles'])*mu
    return {'source_revision':'8ce5fb0a7d104baadf812c55fa3985a2406274d2','input_sha256':{'bundle':hashlib.sha256(bundle_path.read_bytes()).hexdigest(),'fresh_receiver':hashlib.sha256(receiver_path.read_bytes()).hexdigest()},'shape':s,'cpu_proofs':cpus,'parameters':{'field_degree':8,'raw_mod_max_point_mass':'6561/2^256','rho':'1/4','rho_plus':'17/64','agreement':'41/64','theta':'23/64','queries':256,'PoW':0,'fold_step':4,'minimum_nonzero_trace_rows':32},'degree_weights':degree,'conditional_term_bits':{k:bits(mu*v) for k,v in degree.items()},'query_union_bits':bits(query),'conditional_algebraic_union_bits':bits(algebra),'old_lookup_pairwise_union_bits':bits(old),'joint_lookup_bits':bits(mu*source['rational_identity']),'round_source_formula_value':round_formula,'round_upper_bound':R,'collision_coefficient_conservative':H,'conditional_BCS_formula':'(T+2^22)*(sum(degree_weights)*6561/2^256 +30*(41/64)^256) +94*(T^2+1)/2^256','work_table':work,'bounded_work_1_through_2pow120_uniform_per_query_bits':bits(uniform_per_work),'native_theorem_correspondence_review_complete':False,'recursion_security_qualified':False,'whole_protocol_128_certified':False,'source_changes':False,'limitations':['coarse OODS/FRI source-degree and multi-scope BCS correspondence require independent proof review','source unit/support/canonicality and characteristic lemmas must hold','R is an analysis bound, not newly enforced receiver authority','existing recursion secure field/profile is separate and not upgraded by native OM31','256-bit hash theorem constants do not prove unrestricted literal128 per-work security']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('bundle',type=pathlib.Path);p.add_argument('receiver',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);a=p.parse_args();a.output.write_text(json.dumps(run(a.bundle,a.receiver),indent=2)+'\n')
