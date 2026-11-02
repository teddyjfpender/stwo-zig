"""Exact-rational CONDITIONAL model, not a receiver/certificate or protocol change."""
import argparse, hashlib, json, math, pathlib
from fractions import Fraction as F

def bits(x):
    return None if not x else math.log2(x.denominator)-math.log2(x.numerator)

def run(bundle_path, receiver_path, reviewed_v2_envelope=False):
    bundle=json.loads(bundle_path.read_text())
    receiver=json.JSONDecoder().raw_decode(receiver_path.read_text().lstrip())[0]
    s=receiver['source_shape']; source=receiver['source_lookup_only_conditional_degrees']
    assert receiver['profile']=='experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering'
    assert receiver['accepted'] and receiver['completed_ethereum_block']
    P=s['native_proofs']; cpus=len(bundle['cpus']); I=s['max_local_instances']; V=s['max_gkr_variables']
    C=s['max_columns']; S=s['max_samples_per_column']; N=1<<s['max_trace_log']; d=s['max_air_degree']
    if not reviewed_v2_envelope:
        assert (P,cpus,I,V,C,S,N,d)==(30,25,22,26,7371,5,1<<22,5)
    else:
        # Monotone subset of the source-reviewed native v2 envelope only.
        # This is NOT permission to admit v3 providers or relax parser caps.
        assert P == len(bundle['cpus']) + len(bundle['truths'])
        assert receiver['cpu_proofs'] == cpus and receiver['truth_proofs'] == len(bundle['truths'])
        assert 0 < P <= 30 and 0 < cpus <= 25
        assert 0 < I <= 22 and 1 <= V <= 26 and 0 < C <= 7371
        assert 0 < S <= 5 and 32 <= N <= 1<<22 and 0 < d <= 5
        assert 0 < s['max_constraints'] <= 6128 and 0 < s['max_tuple_arity'] <= 35
        assert 0 <= source['rational_identity'] <= 3804538944
        assert all(t['declaration']['family'] in ('keccak', 'add', 'double') for t in bundle['truths'])
        assert all(t['declaration']['family'] != 'keccak' or t['declaration']['logs'][1] == 0 for t in bundle['truths'])
        for cpu in bundle['cpus']:
            declaration = cpu['declaration']; g = declaration['geometry']
            assert not g.get('cpu_fused_tail', False) and not g.get('cpu_u8_pairs', False)
            # Optional v3 fields must be absent, not merely uncounted.
            assert set(declaration['bridges']) <= {'keccak', 'add', 'double'}

    assert min(x['declaration']['geometry']['boundary_log'] for x in bundle['cpus'])==5
    assert all(v is None or v>=5 for x in bundle['cpus'] for k,v in x['declaration']['geometry'].items() if k.endswith('_log'))
    assert all(v==0 or v>=5 for x in bundle['truths'] for v in x['declaration']['logs'])
    rho=F(1,4); rho_plus=rho*F(34,32); alpha=F(41,64); theta=1-alpha
    assert theta < (1-rho_plus)/2 and rho_plus < alpha*alpha
    assert 2*alpha-1 > rho_plus
    for log in range(5,23):
        ni=1<<log
        assert F(ni+2,4*ni)<=rho_plus and 5*(F(ni,2)+1)<3*ni
    for c in range(1,16385):
        assert c+8<=32*c # S>=1; N cancels
    mu=F(3**8,2**256)
    product_rows=sum(1<<t['declaration']['logs'][0] for t in bundle['truths'] if t['declaration']['family']!='keccak')
    if reviewed_v2_envelope:
        assert product_rows <= 395264
    degree={
      'joint_cleared_lookup_all_scopes':source['rational_identity'],
      'gkr_sumcheck':cpus*I*3*V*(V-1)//2,
      'gkr_instance_mix':cpus*(I+2)*V,
      'gkr_late_eta_binding':cpus*I,
      'secp_product_polynomial':62*product_rows,
      'composition_mix':P*s['max_constraints'],
      # Coarse source-degree correspondence bounds; theorem mapping explicitly conditional.
      'oods_circle_correspondence':P*C*S*32*N,
      'deep_batching':P*C*S*(4*N),
      # One first-layer polynomial, no per-height insertions in this implementation.
      # Generic degree15 unique CA (whitepaper Remarks12/13), <=8 macro rounds.
      'fri_unique_curve_correspondence':P*8*15*(4*N),
    }
    cap_I,cap_V,cap_A,cap_P=128,30,128,256
    child_round_cap=cap_V*(2*cap_I+3)+cap_V*(cap_V-1)+4*cap_I+1+9*(cap_A+2)+32
    round_formula=cap_P*(child_round_cap+256)+256
    assert child_round_cap==10355 and round_formula==2716672
    R=1<<22
    assert round_formula<R
    query=P*alpha**256
    algebra=sum(degree.values())*mu
    E=algebra+query
    # Union per native proof plus shared-manifest challenge protocol, rather than
    # silently assuming a single global BCS collision event. One SHA identity term.
    scope_count=P+cpus+1
    H=3*scope_count+1
    work=[]
    for w in [0,64,120,121,122,124,128]:
        T=1<<w
        e=(T+R)*E+F(H*(T*T+1),2**256)
        work.append({'log2_adversarial_RO_queries':w,'unclipped_error_bits':bits(e),'unclipped_error':float(e),'unclipped_success_per_query_bits':bits(e/T)})
    maxT=1<<120
    uniform_per_work=(1+R)*E+F(H*(maxT+1),2**256)
    assert uniform_per_work < F(1,1<<128)
    old=(source['tuple_collision']+source['rational_identity']+source['poles'])*mu
    return {'source_revision':'8ce5fb0a7d104baadf812c55fa3985a2406274d2','input_sha256':{'bundle':hashlib.sha256(bundle_path.read_bytes()).hexdigest(),'fresh_receiver':hashlib.sha256(receiver_path.read_bytes()).hexdigest()},'shape':s,'cpu_proofs':cpus,'parameters':{'field_degree':8,'raw_mod_max_point_mass':'6561/2^256','rho':'1/4','rho_plus':'17/64','agreement':'41/64','theta':'23/64','queries':256,'PoW':0,'fold_step':4,'minimum_nonzero_trace_rows':32},'degree_weights':degree,'conditional_term_bits':{k:bits(mu*v) for k,v in degree.items()},'query_union_bits':bits(query),'conditional_algebraic_union_bits':bits(algebra),'old_lookup_pairwise_union_bits':bits(old),'joint_lookup_bits':bits(mu*source['rational_identity']),'all_candidate_caps_child_round_bound':child_round_cap,'all_candidate_caps_proof_cap':cap_P,'round_source_formula_value':round_formula,'round_upper_bound':R,'collision_coefficient_conservative':H,'conditional_BCS_formula':f'(T+2^22)*(sum(degree_weights)*6561/2^256 +{P}*(41/64)^256) +{H}*(T^2+1)/2^256','work_table':work,'bounded_work_1_through_2pow120_uniform_per_query_bits':bits(uniform_per_work),'native_theorem_correspondence_review_complete':False,'recursion_security_qualified':False,'whole_protocol_128_certified':False,'source_changes':False,'limitations':['coarse OODS/FRI source-degree and multi-scope BCS correspondence require independent proof review','source unit/support/canonicality and characteristic lemmas must hold','R is derived from accepted source caps; multi-scope ROM correspondence still requires review','existing recursion secure field/profile is separate and not upgraded by native OM31','256-bit hash theorem constants do not prove unrestricted literal128 per-work security']}


def run_v3(bundle_path,receiver_path,source_path):
    """Explicit pinned V3 roster; never weakens or substitutes v2 assertions."""
    bundle=json.loads(bundle_path.read_text())
    receiver=json.JSONDecoder().raw_decode(receiver_path.read_text().lstrip())[0]
    source_report=json.loads(source_path.read_text())
    s=receiver['source_shape']; source=receiver['source_lookup_only_conditional_degrees']
    assert receiver['accepted'] and receiver['completed_ethereum_block']
    assert receiver['profile']=='experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering'
    assert bundle['field_degree']==8 and bundle['profile']=='RV64-SERVICES-CPU-GKR-TRUTH-CLASSIC-OM31-V3'
    assert s==source_report['shape'] and source==source_report['lookup_only_conditional_degrees']
    P=s['native_proofs']; cpus=len(bundle['cpus']); I=s['max_local_instances']; V=s['max_gkr_variables']
    C=s['max_columns']; S=s['max_samples_per_column']; N=1<<s['max_trace_log']; d=s['max_air_degree']
    assert (P,cpus,len(bundle['truths']),I,V,C,S,N,d)==(18,7,11,36,26,7444,5,1<<22,5)
    steps=sum(c['request']['cpu']['steps'] for c in bundle['cpus'])
    assert steps==26894777 and receiver['cpu_proofs']==7 and receiver['truth_proofs']==11
    assert all(c['declaration']['geometry']['cpu_fused_tail'] and c['declaration']['geometry']['cpu_u8_pairs'] for c in bundle['cpus'])
    for cpu in bundle['cpus']:
        assert not any(cpu['declaration']['geometry'].get(k,False) for k in ('mul_u8_pairs','ls_fused_pairs','alu_fused_tail','ls_dword_fused_pairs','cpu_compact_decode'))
    assert len(source_report['cpu_scopes'])==7
    p=(1<<31)-1
    for scope in source_report['cpu_scopes']:
        assert len(scope['relations'])==10 and scope['relations'][9]['arity']==4
        assert scope['relations'][9]['unit_consumer_mass']>0
        assert scope.get('namespace_count',10)==10
        owner=scope['owner_table'];assert owner['unit_consumer_mass']<p
        if owner['unit_consumer_mass']:assert owner['valid_provider_support']==8448
    for scope in source_report['cpu_scopes']+source_report['truth_scopes']:
        for bound in scope['relations']:
            for k in ['unit_consumer_mass','unit_positive_mass','unit_negative_mass']:
                assert bound.get(k,0)<p
    for bound in source_report['global_signed'].values():
        assert bound['positive']<p and bound['negative']<p
    policies=[];providers=[]
    for entry in bundle['truths']:
        t=entry['declaration'];family=t['family'];log,word=t['logs'];assert t['calls']>0 and log>=5
        if family=='keccak':
            assert word in [0,(27<<16)|(4<<8)|21] # policy word, NOT a log!
            r27=word!=0; rows=27 if r27 else 29
            assert ((t['calls']+1)//2)*rows <= 1<<log
            policies.append({'calls':t['calls'],'row_log':log,'wire_policy_word':word,'policy':'throughput_r27_v1' if r27 else 'triple_v2','rows_per_pair':rows,'clearing_width':4 if r27 else 3,'air_degree':5 if r27 else 4,'chi_table_log':21 if r27 else 13,'xor5_table_log':16 if r27 else 10})
        else:
            assert word==0 and family in ['add','double','sha256','arith256_mod']
            assert t['calls'] < 1<<log
            if family in ['add','double']:assert log>=8
            providers.append({'family':family,'calls':t['calls'],'row_log':log,'profile':'secp_row_v1' if family in ['add','double'] else family,'air_degree':4 if family in ['add','double'] else 3,'random_polynomial_compression_degree':0,'authority':'curves carried-byte RCB equations' if family in ['add','double'] else 'SHA Boolean/round/feed-forward equations' if family=='sha256' else 'arith256 exact carried 16-bit coefficient equations'})
    assert len(policies)==4 and len(providers)==7
    assert sum(x['family']=='add' for x in providers)==3 and sum(x['family']=='double' for x in providers)==2
    assert source['rational_identity']==1482915616 and source['poles']==1482915616
    rho=F(1,4);rho_plus=F(17,64);alpha=F(41,64);theta=1-alpha
    assert theta<(1-rho_plus)/2 and rho_plus<alpha*alpha and 2*alpha-1>rho_plus
    for log in range(5,23):
        ni=1<<log;assert F(ni+2,4*ni)<=rho_plus and 5*(F(ni,2)+1)<3*ni
    for c in range(1,16385):assert c+8<=32*c
    mu=F(3**8,2**256)
    degree={
      'joint_cleared_lookup_all_actual_scopes':source['rational_identity'],
      # Explicit extra allowance: cumulative-only V3 classic fractions do not
      # universally enforce a separate inverse column. Never omit pole error.
      'conservative_all_physical_poles':source['poles'],
      'gkr_cubic_sumchecks':cpus*I*3*V*(V-1)//2,
      'gkr_instance_and_layer_mix':cpus*(I+2)*V,
      'gkr_late_eta_bindings':cpus*I,
      # All actual secp providers are ROW, no legacy random62-degree compression.
      'legacy_secp_product_random_compression':0,
      'composition_mix':P*s['max_constraints'],
      'oods_circle_correspondence':P*C*S*32*N,
      'deep_batching_common_domain_CA':P*C*S*(4*N),
      'fri_degree15_unique_curve':P*8*15*(4*N),
    }
    # Receiver-validated actual maxima give conservative per-CPU counts: <=36
    # layers/oracles, each <=26 variables; not a claim of exact executed rounds.
    actual_child_envelope=V*(2*I+3)+V*(V-1)+4*I+1+10*(128+2)+32
    actual_round_envelope=cpus*actual_child_envelope+P*256+256
    cap_child=30*(2*128+3)+30*29+4*128+1+10*(128+2)+32
    cap_rounds=256*(cap_child+256)+256
    assert cap_rounds==2749952 and actual_round_envelope<=cap_rounds<(1<<22)
    R=1<<22;query=P*alpha**256;algebra=sum(degree.values())*mu;E=query+algebra
    scopes=P+cpus+1;H=3*scopes+1;assert H==79
    work=[]
    for w in [0,64,120,121,122,124,128]:
        T=1<<w;e=(T+R)*E+F(H*(T*T+1),2**256)
        work.append({'log2_total_adversarial_RO_queries':w,'unclipped_error_bits':bits(e),'unclipped_error':float(e),'success_per_query_bits':bits(e/T)})
    uniform=(1+R)*E+F(H*((1<<120)+1),2**256)
    assert uniform<F(1,1<<128)
    return {'mode':'explicit-reviewed-v3-roster-under-stated-assumptions','source_revision':'6423bc59e','accounting_profile':'rv64-source-derived-services-v3-lookup/v1','assumption_set':'rv64-native-v3-om31-beta2-q256-p0-fold4-bounded-20261102-v1','inputs_sha256':{k:hashlib.sha256(v.read_bytes()).hexdigest() for k,v in [('bundle',bundle_path),('fresh_receiver',receiver_path),('source_bounds',source_path)]},'completed_steps':steps,'shape':s,'cpu_proofs':7,'truth_proofs':11,'namespace_counts':[10]*7,'keccak_policies':policies,'new_truth_authorities':providers,'parameters':{'extension_degree':8,'raw_mod_max_point_mass':'6561/2^256','blowup_log':2,'queries':256,'PoW':0,'fold_step':4,'fri_first_word_rate':'1/4','original_extraction_rho_plus':'17/64','agreement':'41/64','theta':'23/64'},'degree_weights':degree,'conditional_term_bits':{k:bits(mu*v) for k,v in degree.items()},'conditional_algebraic_union_bits':bits(algebra),'query_union_bits':bits(query),'gkr_count_envelope':{'max_instances_per_cpu':I,'max_variables':V,'sumcheck_rounds_per_instance_upper_bound':V*(V-1)//2,'cubic_sumcheck_degree_total':degree['gkr_cubic_sumchecks'],'instance_layer_mix_degree_total':degree['gkr_instance_and_layer_mix'],'late_eta_binding_degree_total':degree['gkr_late_eta_bindings']},'actual_roster_transcript_operation_envelope':actual_round_envelope,'all_caps_ten_namespace_transcript_operation_envelope':cap_rounds,'transcript_round_upper_bound':R,'hash_scopes':scopes,'hash_collision_coefficient':H,'conditional_BCS_formula':'(T+2^22)*(sum(degree_weights)*6561/2^256 +18*(41/64)^256) +79*(T^2+1)/2^256','bounded_work_range':'1 <= TOTAL adversarial RO queries T <= 2^120','uniform_success_per_query_bits':bits(uniform),'work_table':work,'bounded_engineering_arithmetic_review_complete':True,'independent_security_audit_complete':False,'whole_protocol_128_certified':False,'security_qualified':False,'recursion_included':False,'limitations':['conditional nonzero rational lookup/source weighting/canonicality and characteristic lemmas','unique decoding FRI/DEEP/OODS implementation correspondence from prior proof outline must apply to degree<=5 V3 roles','source AIR integer semantics and range-inheritance premises remain assumptions, not proved by proof acceptance','adaptive multiscope BCS/ROM correspondence and raw Blake/SHA ideal-hash assumptions','exact hash constants do not imply unrestricted literal128 per-work security near2^128 queries','numerical result only for pinned18-proof V3 roster, not arbitrary256-proof inventory','outer recursion field/profile and composed security excluded']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('bundle',type=pathlib.Path);p.add_argument('receiver',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);p.add_argument('--reviewed-v2-envelope',action='store_true',help='Require a monotone subset of the reviewed native v2 roster; v3 is excluded');p.add_argument('--v3-source-bounds',type=pathlib.Path,help='Explicit pinned V3 roster mode; never weakens v2 assertions');a=p.parse_args();assert not(a.reviewed_v2_envelope and a.v3_source_bounds);result=run_v3(a.bundle,a.receiver,a.v3_source_bounds) if a.v3_source_bounds else run(a.bundle,a.receiver,a.reviewed_v2_envelope);a.output.write_text(json.dumps(result,indent=2)+'\n')
