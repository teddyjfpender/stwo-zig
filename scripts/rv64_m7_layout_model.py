#!/usr/bin/env python3
"""Source/receipt arithmetic for fewer leaves and D2/D3; no timing forecast.

D: exact arithmetic over accepted M6 declarations and source-generated census.
E: proposed CPU coalescing geometry; private ALU/BINARY/SHIFT events are absent
from bundle publics, so their summed padded capacities are conservative inputs.
The model separates coefficient cells, LDE work volume and simultaneously live
planes. LDE volume is NOT claimed as peak memory (commitment streams columns).
"""
import argparse, copy, hashlib, json
from pathlib import Path

FAMILIES = ['keccak', 'add', 'double', 'sha256', 'arith256_mod', 'bn254_g1_add',
            'bn254_g1_double', 'bn254_fp2_mul', 'bls12_381_fp2_mul',
            'arith384_mont', 'bls12_381_g1_add', 'bls12_381_g1_double']
PROFILES = {'M6_b2_q108': (1, 108), 'D2_b4_q54': (2, 54), 'D3_b8_q36': (3, 36)}
GIB = 1 << 30
FULL_TREE_PLAN_SHA256 = "289c576ebf911520f4569b1a7be58de6967f0d5de5d4191e758b67729d56ad14"

def ceil_log(n, minimum=5):
    return max(minimum, (max(1, n)-1).bit_length())

def gkr_workspace(variables):
    """Exact rv64/gkr.zig Plan.init word layout, including consumed-Eq reuse."""
    if not variables:
        return 0
    if len(variables) > 128 or max(variables) > 28:
        return None
    cursor = 0
    def append(words):
        nonlocal cursor
        cursor = (cursor+63)//64*64 + words
    for words in [2580, 61+33*128, 16*len(variables), 8*len(variables), 64]:
        append(words)
    for v in variables:
        n = 1 << v
        for level in range(v):
            count = n >> (level+1)
            append(8*count); append(8*count)
        groups = max(1, (n//4+127)//128)
        append(16*groups); append(16*groups); append(16)
    height = max(variables)
    for depth in range(height):
        append(depth*44)
        append(32*sum(v >= height-depth for v in variables))
    return cursor*4

# Frozen GPU fixture in implicit-source/receipt.json, independent CPU exact proof.
assert gkr_workspace([11, 6, 6]) == 188288

def components(census):
    proofs = []
    for index, cpu in enumerate(census['cpus']):
        parts = []
        for s in cpu['slots']:
            parts.append(dict(name=s['name'], log=s['log'], fixed=s['fixed_cols'],
                              main=s['main_cols'], classic=s['binding_cols']+s['ram_cols']+s['other_cols'],
                              terms=s['native_terms'], split=1,
                              classic_aux=10 if s['binding_cols'] else 0))
        assert sum(c['main']*(1<<c['log']) for c in parts)==cpu['main_cells']
        assert sum(c['classic']*(1<<c['log']) for c in parts)==cpu['inter_cells']
        proofs.append(dict(kind='cpu', ordinal=index, components=parts))
    for t in census['truths']:
        assert t.get('native_supported', True), 'native mode unsupported for this source class'
        parts = []
        for p in t['parts']:
            parts.append(dict(name=p['kind'], log=p['log'], fixed=p['fixed_cols'], main=p['main_cols'],
                              classic=p['local_cols']+p['global_cols'], terms=p['native_terms'],
                              split=p['composition_split'], classic_aux=1 if p['kind']=='keccak' else 0))
        assert sum(c['main']*(1<<c['log']) for c in parts)==t['main_cells']
        assert sum(c['classic']*(1<<c['log']) for c in parts)==t['inter_cells']
        proofs.append(dict(kind=t['family'], ordinal=len(proofs), calls=t['calls'], components=parts))
    return proofs

def split_count(count, cap=22):
    """Minimum padded volume of the source's at-most-two head/tail chips."""
    choices=[]
    for head in range(5,cap+1):
        remaining=max(0,count-((1<<head)-1))
        tail=None if remaining==0 else ceil_log(remaining+1)
        if tail is None or tail<=cap:
            choices.append(((1<<head)+(0 if tail is None else 1<<tail),-head,head,tail))
    _,_,head,tail=min(choices)
    return head,tail

def cpu_candidates(bundle, baseline, limit, wide_legacy):
    """Coalesce adjacent old segments. Re-capture is required before proving."""
    groups=[]; group=[]; steps=0
    for i,c in enumerate(bundle['cpus']):
        count=c['request']['cpu']['steps']
        if group and steps+count >= 1 << limit:
            groups.append(group);group=[];steps=0
        group.append(i);steps+=count
    if group:groups.append(group)
    cpus=[]
    constants={'core.rom','core.range16','core.range8','core.and_table','core.shift_table','core.jtab'}
    bulk_fields={'desc':'calls','copy':'copy_words','set':'set_words','ucopy':'ucopy_rows',
                 'cdesc':'cmp_calls','cmp':'cmp_words','jdesc':'jump_calls','jscan':'jump_rows'}
    def value(request,name):
        if name in FAMILIES:
            i=FAMILIES.index(name)
            return request.get('calls',[])[i] if i<len(request.get('calls',[])) else request.get(name+'_calls',0)
        return request.get(name,0)
    for group in groups:
        requests=[bundle['cpus'][i]['request'] for i in group]
        source={}
        for i in group:
            for c in baseline[i]['components']:source.setdefault(c['name'],[]).append(c)
        total_steps=sum(r['cpu']['steps'] for r in requests)
        total_ls=sum(r.get('ls_count',0) for r in requests)
        total_dw=sum(r.get('ls_dword',0) for r in requests)
        parts=[]
        for name, entries in source.items():
            if name in ('core.ls_tail','dword.1','core.alu_tail','core.binary_tail','core.shift_tail'):continue
            c=copy.deepcopy(entries[0]); count=None
            if name=='core.cpu':count=total_steps
            elif name in ('core.initial','core.terminal') or name in constants or name=='bulk.jtab':
                c['log']=max(x['log'] for x in entries)
            elif name=='core.multiplication':count=sum(r.get('multiplication_requests',0) for r in requests)
            elif name=='core.division':count=sum(r.get('division_requests',0) for r in requests)
            elif name in ('core.ls','dword.0','core.alu','core.binary','core.shift'):
                tail_name='dword.1' if name=='dword.0' else name+'_tail'
                if name=='core.ls':total=total_ls
                elif name=='dword.0':total=total_dw
                else:
                    total=sum((1<<x['log'])-1 for x in entries+source.get(tail_name,[]))
                    c['capacity_basis']='sum_old_usable_private_rows_upper_bound'
                head_log,tail_log=split_count(total)
                c['log']=head_log;parts.append(c)
                if tail_log is not None:
                    tail=copy.deepcopy(c);tail['name']=tail_name;tail['log']=tail_log;parts.append(tail)
                continue
            elif name.startswith('bridge.'):count=sum(value(r,name.split('.')[1]) for r in requests)
            elif name.startswith('bulk.'):
                count=sum(r.get('bulk',{}).get(bulk_fields[name.split('.')[1]],0) for r in requests)
            elif name.startswith('sponge.'):
                count=sum(r.get('sponge',{}).get('calls' if name.endswith('call') else 'perms',0) for r in requests)
            else:
                # Exact events are not public. Keep sufficient capacity for all
                # original padded rows; this is not a measured new partition.
                c['log']=ceil_log(sum(1<<x['log'] for x in entries))
                c['capacity_basis']='sum_old_padded_rows_upper_bound'
            if count is not None:
                c['log']=ceil_log(count+1)
                c['public_count']=count
            if wide_legacy and name=='core.cpu':
                c['main']=47;c['terms'][0]=15;c['classic']=c['classic']+4
            if wide_legacy and name=='core.and_table':
                c['main']=1;c['terms'][0]=1
            parts.append(c)
        cpus.append(dict(kind='cpu', ordinal=len(cpus), original_ordinals=group,
                         steps=total_steps, components=parts))
    return cpus

def evaluate(proofs, native_gkr):
    out=[]
    for proof in proofs:
        fixed=main=inter=composition=0; columns=0; largest_plane=0; variables=[];max_log=0
        for c in proof['components']:
            rows=1<<c['log'];max_log=max(max_log,c['log'])
            width=16 if native_gkr and any(c['terms']) else (0 if native_gkr else c['classic'])
            fixed+=c['fixed']*rows;main+=c['main']*rows;inter+=width*rows
            columns+=c['fixed']+c['main']+width
            aux=10 if native_gkr and any(c['terms']) else c['classic_aux']
            plane=4*(c['fixed']+c['main']+width+aux)*(1<<(c['log']+c['split']))
            largest_plane=max(largest_plane,plane)
            for terms in c['terms']:
                if terms:variables.append(c['log']+(terms-1).bit_length())
        split=max(c['split'] for c in proof['components'])
        global_composition_log=max(c['log']+c['split'] for c in proof['components'])
        # Composition is split into 8*2^split base columns. Total coefficient
        # volume = 8*2^global_composition_log, independent of split itself.
        composition=8*(1<<global_composition_log)
        workspace=gkr_workspace(variables) if native_gkr else None
        decoded=4*(fixed+main)
        gkr_lower=None if workspace is None else workspace+decoded+4*(1<<(max_log-1))
        out.append(dict(kind=proof['kind'],ordinal=proof['ordinal'],fixed_cells=fixed,
                        main_cells=main,inter_cells=inter,composition_coefficient_cells=composition,
                        total_coefficient_cells=fixed+main+inter+composition,open_leaf_base_columns=columns,
                        rc_largest_expanded_plane_bytes=largest_plane,
                        rc_plane_is_total_peak=False,
                        gkr_instances=len(variables) if native_gkr else None,
                        gkr_max_variables=max(variables) if native_gkr else None,
                        gkr_workspace_bytes=workspace,
                        gkr_transient_lower_bytes_excluding_small_metadata=gkr_lower))
    main_gpu=[sum(p['main_cells']*4 for p in out if p['ordinal']%2==device) for device in range(2)]
    for p in out:
        p['gkr_with_same_gpu_stage_one_main_lower_bytes']=None if p['gkr_transient_lower_bytes_excluding_small_metadata'] is None else p['gkr_transient_lower_bytes_excluding_small_metadata']+main_gpu[p['ordinal']%2]
    totals={k:sum(p[k] for p in out) for k in ['fixed_cells','main_cells','inter_cells','composition_coefficient_cells','total_coefficient_cells','open_leaf_base_columns']}
    totals['native_proofs']=len(out);totals['retained_main_bytes_cyclic_per_gpu']=main_gpu
    totals['max_rc_expanded_plane_bytes']=max(p['rc_largest_expanded_plane_bytes'] for p in out)
    totals['profiles']={}
    for name,(beta,queries) in PROFILES.items():
        totals['profiles'][name]=dict(log_blowup=beta,queries=queries,
            expanded_four_tree_cell_volume=totals['total_coefficient_cells']*(1<<beta),
            trace_leaf_query_words_proxy=totals['open_leaf_base_columns']*queries,
            query_proxy_excludes_FRI_auth_dedup_and_OODS=True)
    return dict(totals=totals,proofs=out)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--inputs',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args(); blocks=[]
    assert hashlib.sha256(Path('src/integrations/riscv_cuda/rv64/gkr.zig').read_bytes()).hexdigest()==FULL_TREE_PLAN_SHA256, 'full-tree Plan changed: refresh model from source before reusing its byte claims' 
    for block in [26235156,24628607]:
        bundle=json.loads((args.inputs/f'{block}-bundle.json').read_text())
        baseline=json.loads((args.inputs/'source-census'/f'{block}-baseline-census.json').read_text())
        merged=json.loads((args.inputs/'source-census'/f'{block}-truth-merged-census.json').read_text())
        base=components(baseline);truth_merged=components(merged)
        variants={'baseline':('D source arithmetic on accepted M6 declarations',base),
                  'one_truth_per_family':('D source geometry; unproved proposed inventory',truth_merged)}
        for limit in [23,24]:
            for legacy in [False,True]:
                cpus=cpu_candidates(bundle,base,limit,legacy)
                truths=copy.deepcopy(truth_merged[len(bundle['cpus']):])
                for i,p in enumerate(truths,len(cpus)):p['ordinal']=i
                name=f'cpu{limit}_'+('wide47' if legacy else 'compact37_extended')+'_truth1'
                variants[name]=('E new CPU authority/class/capture required; private event capacity upper bounds',cpus+truths)
        result={name:dict(label=label,**{mode:evaluate(proofs,mode=='native_gkr') for mode in ['classic','native_gkr']}) for name,(label,proofs) in variants.items()}
        blocks.append(dict(block=block,total_steps=sum(c['request']['cpu']['steps'] for c in bundle['cpus']),variants=result))
    source_paths=['scripts/rv64_m7_layout_model.py','src/integrations/riscv_cpu/word16_global_execution/services/types.zig','src/integrations/riscv_cpu/word16_global_execution/services/native_gkr/native_roster.zig','src/integrations/riscv_cpu/word16_global_execution/services/native_gkr/cpu_component.zig','src/integrations/riscv_cuda/rv64/gkr.zig','src/integrations/riscv_cuda/rv64/abi.zig',
                  'src/integrations/riscv_cpu/word16_global_execution/services/native_gkr/census_main.zig',
                  'src/integrations/riscv_cuda/rv64/resident_composition.zig',
                  'src/frontends/riscv/rv64/air/word16_execution/layout.zig',
                  'src/integrations/riscv_cpu/word16_execution/geometry.zig',
                  'src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/service_scope.zig']
    output=dict(schema='rv64-m7-fewer-leaves-d2-d3-model/v1',author='OpenAI Codex',label='D/E; no proof or performance qualification',
        blocks=blocks,source_sha256={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in source_paths},
        inputs_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in list(args.inputs.glob('*-bundle.json'))+list((args.inputs/'source-census').glob('*-census.json'))+list((args.inputs/'source-census').glob('*-input.json'))},
        notes=['Only the source census was executed; no proposed proof or GPU timing was run.',
               'D2/D3 byte/field/hash domains and FIXED roots/VKs must change; this does not promote either conjectured128 profile.',
               'Poseidon2 changes hashing/FS circuit work; these layout volumes are hash-independent and do not forecast Poseidon circuit cells.',
               'CPU23 current classic geometry requires fused tail with no byte pairs, hence compact37 is unavailable; GKR source scope rejects >22.',
               'CPU24 exceeds geometryMAX_LOG23; register gap bound needs scale64 instead of wide scale128 and fresh MAIN/query/class authority.',
               'RC plane is a lower bound on live stage memory: retained columns, bucket buffers, FFT scratch, immutable caches and allocator charge are additional.',
               'GKR workspace is exact current consumed-Eq Plan; its transient lower bound adds decodedMAIN/FIXED and twiddle, omits small parameters and allocator charge.',
               'MAIN cyclic retention assumes all stage-one native coefficient owners remain on ordinal%2; planner may park/replay owners.',
               'Commitment LDE cell volume is work volume, not a full materialization memory claim.',
               'Query proxy counts base trace-leaf words times q only; no composition leaf, FRI, auth paths/dedup, OODS or GKR circuit-cell estimate.'])
    args.output.write_text(json.dumps(output,indent=2)+'\n')
    for b in blocks:
        for name,v in b['variants'].items():
            a=v['native_gkr']['totals'];print(b['block'],name,'proofs',a['native_proofs'],'main+inter',a['main_cells']+a['inter_cells'],'RCplaneGiB',round(a['max_rc_expanded_plane_bytes']/GIB,3))
if __name__=='__main__':main()
