from pathlib import Path
import hashlib,json,re,sys
H=Path(__file__).resolve().parent
label=sys.argv[1] if len(sys.argv)>1 else 'balanced'
rows=[]
for size in (1,16,32,64):
 stem=H/f'local-batch-{size}-prove-{label}'
 inv=Path(str(stem)+'.invocation.json')
 if not inv.exists():continue
 meta=json.loads(inv.read_text())
 if meta.get('exit_code')!=0:
  rows.append({'transactions':size,'verified':False,'exit_code':meta.get('exit_code')});continue
 value=json.loads(Path(str(stem)+'.json').read_text())
 assert value['verified'] and value['recursive'] and meta['output_checked']
 assert value['queries']==70 and value['pow_bits']==26
 log=Path(str(stem)+'.log').read_text()
 footprint=int(re.search(r'(\d+)\s+peak memory footprint',log)[1])
 leaf=re.search(r'BLAKE3_SEGMENT_LEAF_TIMING proving_ns=(\d+) capture_verification_ns=(\d+)',log)
 rows.append({'transactions':size,'verified':True,'process_wall_seconds':meta['process_wall_seconds'],'peak_process_footprint_bytes':footprint,'peak_process_footprint_gib':footprint/2**30,'worker_peak_bytes':value['worker_peak_bytes'],'worker_peak_gib':value['worker_peak_bytes']/2**30,'preparation_retained_bytes':value['preparation_retained_bytes'],'parent_proving_seconds':value['parent_proving_ns']/1e9,'leaf_proving_seconds':int(leaf[1])/1e9,'g_partitions':[g for g in value['geometry'] if g['name'].endswith('blake3_g_call')], 'hash_partition_seconds':value.get('hash_partition_ns',0)/1e9,'proof_bytes':value['proof_bytes'],'cycles':value['cycles']})
initial=H/'local-batch-16-prove-compact-consuming.proof'
final=H/'local-batch-16-prove-compact-opening.proof'
equal=initial.read_bytes()==final.read_bytes() if initial.exists() and final.exists() else None
out={'label':label,'security':{'queries':70,'pow_bits':26},'workers':16,'worker_limit_gib':48,'samples_per_case':1,'opening_storage_change_preserves_16_tx_proof_bytes':equal,'results':rows}
(H/('summary.json' if label=='balanced' else f'summary-{label}.json')).write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
