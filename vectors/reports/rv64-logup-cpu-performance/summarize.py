import json,sys
rows=[json.loads(l) for l in open(sys.argv[1])]
for x in rows:
    r=x['r']; k=r['kernel']
    per = r.get('ns_per_leaf') or r.get('ns_per_fraction') or r.get('ns_per_element')
    extra = {kk:r[kk] for kk in ('kind','impl','n_sums','width') if kk in r}
    print(f"{k:8s} log={r['log']:2d} thr={r.get('threads',1):2d} {extra} med={r['median_ns']/1e6:9.2f}ms min={r['min_ns']/1e6:9.2f}ms per={per:8.2f}ns load={x['load1']} sha={r['sha256'][:12]}")
