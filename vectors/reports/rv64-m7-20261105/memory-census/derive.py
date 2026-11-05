#!/usr/bin/env python3
"""Reconcile the frozen M6 negative; no GPU access or performance extrapolation."""
import hashlib,json,pathlib
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[3]
chunk=32<<20; slab=512<<20; capacity=22<<30
requested=14750402976; live=9613865472; mapped_free=13488881664
large_capacity=capacity-slab
live_large=large_capacity-mapped_free
live_small=live-live_large
rounded=((requested+chunk-1)//chunk)*chunk
assert (large_capacity//chunk,live_large//chunk,mapped_free//chunk)==(688,286,402)
assert rounded//chunk==440
assert (rounded-mapped_free)//chunk==38
assert live_large+live_small==live
roles=3516; rows=1<<20
rc={'dense_evaluation_bytes':roles*rows*4,'aux_staging_bytes':(1<<18)*4,'twiddle_bytes':(1<<19)*4,'descriptors_bytes':roles*6*4}
assert sum(rc.values())==requested
census_path=ROOT/'vectors/reports/rv64-m7-20261105/native-layout/source-census/24628607-baseline-census.json'
census=json.loads(census_path.read_text())
cpus=[]
for ordinal,cpu in enumerate(census['cpus']):
 slots=cpu['slots']
 cpus.append({'ordinal':ordinal,'physical_gpu':ordinal%2,'main_bytes':sum(s['main_cols']*(1<<s['log'])*4 for s in slots),'stage1_projection_bytes':sum((s['binding_cols']//2)*(1<<s['log'])*4 for s in slots),'global_evaluation_bytes':sum((s['ram_cols']+s['other_cols'])*(1<<s['log'])*4 for s in slots)})
t=census['truths'][0]
truth={key:sum(p[cols]*(1<<p['log'])*4 for p in t['parts']) for key,cols in [('fixed_payload_bytes','fixed_cols'),('main_payload_bytes','main_cols')]}
truth['inter_payload_bytes']=sum((p['local_cols']+p['global_cols'])*(1<<p['log'])*4 for p in t['parts'])
result={'status':'SOURCE_DERIVED_RECONCILED_M6_NEGATIVE_NOT_D2_FAILURE','arena':{'capacity_bytes':capacity,'small_slab_bytes':slab,'live_large_bytes':live_large,'live_small_bytes':live_small,'available_large_bytes':mapped_free,'available_small_bytes':slab-live_small,'requested_payload_bytes':requested,'requested_rounded_bytes':rounded,'shortfall_large_chunks':38,'shortfall_large_bytes':rounded-mapped_free},'rc_payload_parts':rc,'owner_snapshot':{'retained_bytes':9373928128,'lease_bytes':9138817728,'domains_bytes':9373928128-9138817728,'idle_pcs_bytes':0,'active_pcs_bytes':0,'per_scope_lease_inventory_available':False},'cpu_static_payloads_not_simultaneous_snapshot':cpus,'first_keccak_truth_static_payloads':truth,'census_sha256':hashlib.sha256(census_path.read_bytes()).hexdigest(),'process_limit':{'required_bytes':28000000000,'stack_context_whole_device_delta_bytes':32480886784-29473570816,'whole_device_used_after_stack_before_arena_bytes':33679736832-29473570816,'arena22g_plus_whole_device_used_model_bytes':capacity+33679736832-29473570816,'exact_process_peak_known':False}}
print(json.dumps(result,indent=2))
