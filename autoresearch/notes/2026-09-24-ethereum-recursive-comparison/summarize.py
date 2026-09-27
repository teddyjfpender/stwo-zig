"""Extract verified observations and CPU stage occupancy without summing overlap as latency."""
from pathlib import Path
import collections,datetime,json,re
H=Path(__file__).resolve().parent
observations=[]
for path in sorted(H.glob('*.invocation.json')):
    invocation=json.loads(path.read_text())
    if invocation.get('mode')!='prove' or invocation.get('exit_code')!=0:
        continue
    stem=path.name.removesuffix('.invocation.json')
    report=json.loads((H/(stem+'.json')).read_text())
    log=(H/(stem+'.log')).read_text()
    assert report.get('verified') and (report.get('recursive') or report.get('aggregation'))
    footprint=re.search(r'(\d+)\s+peak memory footprint',log)
    row={'run':stem,'report':report,'process_wall_seconds':invocation['process_wall_seconds'],
         'peak_footprint_bytes':int(footprint[1]) if footprint else None,
         'security_normalized':False,'peer_stage_profile':invocation.get('peer_stage_profile',False),
         'swap_before':invocation.get('swap_before'),'swap_after':invocation.get('swap_after')}
    if invocation['side']=='local':
        leaves=re.findall(r'BLAKE3_SEGMENT_LEAF_TIMING proving_ns=(\d+) capture_verification_ns=(\d+)',log)
        row['base_proving_seconds']=sum(int(a) for a,b in leaves)/1e9
        row['base_verification_seconds']=sum(int(b) for a,b in leaves)/1e9
        row['recursive_preparation_seconds']=report['leaf_and_recursion_preparation_ns']/1e9-row['base_proving_seconds']-row['base_verification_seconds']
        row['timed_transaction_seconds']=report['total_ns']/1e9
        row['total_seconds']=invocation['process_wall_seconds']
    else:
        row['timed_transaction_seconds']=report['setup_seconds']+report['prove_seconds']+report['verify_seconds']
        row['total_seconds']=invocation['process_wall_seconds']
        phases={};events=[];work=collections.defaultdict(float)
        for line in log.splitlines():
            m=re.match(r'(\S+Z)\s+(?:\S+\s+)?(?:INFO|DEBUG|TRACE): (>>>|<<<) (.+)',line)
            if not m:continue
            stamp=datetime.datetime.fromisoformat(m[1]).timestamp()
            name=m[3];elapsed=re.search(r'\((\d+)ms\)',name)
            if m[2]=='<<<' and elapsed:phases[name.split(' (')[0]]=int(elapsed[1])/1000
            category=None
            if name.startswith('GEN_PROOF_'):category='base_proof'
            elif name.startswith('GEN_RECURSIVE_PROOF_'):
                category='final_proof' if 'VadcopFinal' in name else 'inner_recursive_proof'
            elif name.startswith(('GENERATING_COMPRESSOR_WITNESS_','GENERATING_RECURSIVE1_WITNESS_','GENERATE_WITNESS_AGGREGATION')):
                category='recursive_witness'
            if category:
                events.append((stamp,category,1 if m[2]=='>>>' else -1))
                if elapsed and m[2]=='<<<':work[category]+=int(elapsed[1])/1000
        counts=collections.Counter();occupied=collections.defaultdict(float);overlap=0.;previous=None
        for stamp,category,change in sorted(events,key=lambda event:event[0]):
            if previous is not None:
                dt=stamp-previous
                for kind,count in counts.items():
                    if count:occupied[kind]+=dt
                if counts['base_proof'] and counts['inner_recursive_proof']:overlap+=dt
            counts[category]+=change
            if counts[category]<0:raise ValueError(f'Unmatched timer in {stem}: {category}')
            previous=stamp
        if any(counts.values()):raise ValueError(f'Unclosed timers in {stem}: {counts}')
        row['native_phase_seconds']=phases
        row['reported_task_seconds_not_wall_latency']=dict(work)
        row['category_elapsed_wall_seconds_including_waits']=dict(occupied)
        row['base_inner_recursion_span_overlap_seconds']=overlap
    observations.append(row)
(H/'summary.json').write_text(json.dumps({'classification':'native_cpu_observations_not_security_normalized','observations':observations},indent=2)+'\n')
for r in observations:
    print(r['run'],f"{r['total_seconds']:.3f}s",f"{r['peak_footprint_bytes']/2**30:.2f}GiB" if r['peak_footprint_bytes'] else '')
