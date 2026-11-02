import json,pathlib,re,statistics
b=pathlib.Path('/tmp/rv64-active-om-air-prefix4-ab-v1');p=b/'summary.json';d=json.loads(p.read_text())
for r in d['runs']:
 i=r['index'];rows=re.findall('OM_DOMAIN_STAGE.*',(b/f'{i}.time.log').read_text());r['cpu_domain_summed_seconds']={k[:-3]:sum(int(re.search(k+r'=(\d+)',x)[1]) for x in rows)/1e9 for k in ['prep_ns','fft_ns','rows_ns']}
 out=b/f'{i}-{0 if r["variant"]=="baseline" else 1}'
 r['native_composition_seconds']=[next(x['seconds'] for x in json.loads(f.read_text())['stages'] if x['id']=='composition_evaluation') for f in sorted(out.glob('physical-*.stages.json'))]
for v in ['baseline','active_air_fused']:
 rr=[r for r in d['runs'] if r['variant']==v]
 d['medians'][v]['cpu_domain_rows_summed_seconds']=statistics.median(r['cpu_domain_summed_seconds']['rows'] for r in rr)
 d['medians'][v]['cpu_domain_fft_summed_seconds']=statistics.median(r['cpu_domain_summed_seconds']['fft'] for r in rr)
 d['medians'][v]['native_composition_summed_seconds']=statistics.median(sum(r['native_composition_seconds']) for r in rr)
p.write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d['medians'],indent=2))
