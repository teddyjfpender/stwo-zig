#!/usr/bin/env python3
"""Summarize bounded existing-gadget native Blake source-cost evidence.

No proof/timing/security conclusion is inferred from dummy trace-only graphs.
Cell counts cover named roles only; this is not a complete mixed R7 layout.
"""
import argparse
import hashlib
import json
from pathlib import Path

def records(path,prefix):
    return [json.loads(line.split(prefix,1)[1]) for line in path.read_text().splitlines() if prefix in line]
def rows(n):return 1<<max(4,(n-1).bit_length())
def main():
    p=argparse.ArgumentParser();p.add_argument('--primitive-log',type=Path,required=True);p.add_argument('--actual-log',type=Path,required=True);p.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    primitive=records(args.primitive_log,'NATIVE_BLAKE_HASH_SOURCE ')
    actuals=records(args.actual_log,'NATIVE_BLAKE_ACTUAL_CPU_SOURCE ')
    controls=records(args.actual_log,'NATIVE_P2_MATCHED_PCS_SOURCE ')
    assert len(primitive)==6 and len(actuals)==len(controls)==1
    actual=actuals[0];control=controls[0]
    assert actual['config']['fri_config']=={'log_blowup_factor':2,'log_last_layer_degree_bound':0,'n_queries':72,'fold_step':4}
    assert actual['config']['pow_bits']==0 and actual['root_bytes']==32
    assert actual['native_om_mul']==control['native_om_mul'] and actual['dot_calls']==control['dot_calls']
    for item in primitive:
        assert item['raw']['blake_g_gate']==80*item['blocks']
        assert item['raw']['triple_xor']==8*item['blocks']
    total_blocks=actual['raw']['blake_g_gate']//80
    assert actual['raw']['blake_g_gate']==80*total_blocks
    assert actual['raw']['triple_xor']==8*total_blocks
    # XOR12 expands its top2bits, so it is log20, not log24.
    tables=[{'role':'xor8','log':16,'main':2,'om_inter':8}, {'role':'xor12','log':20,'main':16,'om_inter':64}, {'role':'xor4','log':8,'main':1,'om_inter':8}, {'role':'xor7','log':14,'main':1,'om_inter':8}, {'role':'xor9','log':18,'main':1,'om_inter':8}]
    for table in tables:
        table['fixed']=3
        table['cells']=(1<<table['log'])*(table['main']+table['om_inter']+table['fixed'])
    floor=sum(t['cells'] for t in tables)
    def hash_roles(blocks):
        return {'compressions':blocks,'g_gates':80*blocks,'g_log':rows(80*blocks).bit_length()-1,'g_main_inter_fixed_cells':rows(80*blocks)*(52+104+11),'triple_xor_rows':rows(8*blocks),'triple_main_inter_fixed_cells':rows(8*blocks)*(20+48+5),'xor_table_cells':floor,'subtotal':rows(80*blocks)*167+rows(8*blocks)*73+floor}
    q=actual['config']['fri_config']['n_queries'];heights=actual['tree_heights']
    trace_leaf=sum((n+15)//16 for n in actual['columns'])*q
    trace_path=sum(heights)*q
    # Existing folded FRI: 4 packed leaves per coset (4 OM31 each),
    # three internal hashes, then authpath after dropping fold_step bits.
    lifting=max(heights);bound=lifting-2;remaining=bound;bits=lifting;fri=[]
    while remaining:
        step=min(4,remaining);remaining-=step
        packed=2 if bits>=2 and step>1 else 0
        leaves=1<<(step-packed)
        leaf_blocks=leaves*((((1<<packed)*8)+15)//16)
        bits-=step
        fri.append({'step':step,'path_height':bits,'leaf_blocks_per_query':leaf_blocks,'internal_node_blocks_per_query':leaves-1})
    merkle_blocks=trace_leaf+trace_path+q*sum(l['leaf_blocks_per_query']+l['internal_node_blocks_per_query']+l['path_height'] for l in fri)
    assert merkle_blocks<=total_blocks
    caps=[]
    for c in (0,1,3,5):
        eligible=sum(h>c for h in heights+[l['path_height'] for l in fri]) if c else 0
        saved=eligible*(q*c-((1<<c)-1)) if c else 0
        item=hash_roles(total_blocks-saved);item.update({'cap_log':c,'eligible_trees':eligible,'compression_saving':saved,'scope':'static compression/gate counterfactual only; cap selection arithmetic/source authority/padding not qualified'})
        caps.append(item)
    p2_cells=rows(control['p2_permutations'])*(476+192+73)
    sources=['src/frontends/circuit/common/component_list.zig','src/frontends/circuit/common/preprocessed.zig','src/frontends/circuit/native_verifier/blake_chain.zig','src/integrations/riscv_cpu/rv64_recursion/om31_native/mod.zig','src/integrations/riscv_cpu/rv64_recursion/om31_native/proof.zig','src/integrations/riscv_cpu/poseidon2_outer/layout.zig']
    report={'schema':'op-native-blake-vs-p2-actual-source-cost-v1','production_admission':False,'security_qualified':False,'no_new_native_or_outer_proof':True,'scope':'same actual selectedCPU geometry/OM31/q72B4P0fold4, PCS/FS/DEEP/FRI source graphs; omitted AIR/P2GKR/frame and mixed source closure','primitive_source_cases':primitive,'actual_blake':actual,'matched_p2':control,'source_qualifiers':['fresh native P2 bundle physically accepted before/after callback','NEW dummy32-byte Blake values; P2 capture supplies geometry only','audit public/claim framing is not a new production suite','R7 Mul/Dot scopes enabled; Input-origin source/Var usage not finalized','neither dummy verifier graph is asserted valid or admitted'],'hash_work':{'total_blake_compressions':total_blocks,'trace_leaf_blocks':trace_leaf,'trace_path_blocks':trace_path,'fri_layers':fri,'all_merkle_blocks':merkle_blocks,'residual_FS_blocks_including_audit_framing':total_blocks-merkle_blocks},'additional_xor_tables':tables,'additional_xor_table_floor_cells':floor,'blake_hash_roles_cap0':hash_roles(total_blocks),'p2_hash_role_cells':p2_cells,'static_cap_counterfactuals':caps,'excluded':['original AIR/OODS/terminal/GKR public frame work','full R7 input origin/Var/range fanout and typed mixed roster','remaining generic arithmetic/OMmul/Dot and M31-u32 roles','extra lookup fractions/source-degree qualification','native prover speed and whole native+root wall time','actual cap witnesses/selectors and fresh source VK cost'],'opening_columns_added':{'main_plus_om_inter':341,'fixed':31,'roles':7,'scope':'existing classic lookup roster; not a qualified mixed key'},'source_sha256':{s:hashlib.sha256((args.repo/s).read_bytes()).hexdigest() for s in sources},'evidence_sha256':{'primitive_log':hashlib.sha256(args.primitive_log.read_bytes()).hexdigest(),'actual_log':hashlib.sha256(args.actual_log.read_bytes()).hexdigest()}}
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'hash_blocks':total_blocks,'cap0_hash_cells':report['blake_hash_roles_cap0']['subtotal'],'p2_hash_cells':p2_cells,'cap1_hash_cells':caps[1]['subtotal'],'decision':'do not implement a native crypto switch before complete same-security source/physical qualification'},indent=2))
if __name__=='__main__':main()
