import json,pathlib,subprocess,time,hashlib,statistics
out=pathlib.Path('/tmp/rv64-capture-real-ab-v1')
binary=pathlib.Path('/private/tmp/stwo-rv64-capture-cli/zig-out/bin/rv64-word16-ethereum-gkr')
config='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json'
jobs='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs'
allruns=[]; authority=None
for index,mode in enumerate(['serial','two','serial','two','serial','two']):
 result=out/f'{index}-{mode}.json'; timelog=out/f'{index}-{mode}.time.txt'
 command=['/usr/bin/time','-l',str(binary),'capture',config,jobs,'0',str(out/f'{mode}.resources.json')]
 start=time.perf_counter()
 with result.open('w') as stdout,timelog.open('w') as stderr:
  completed=subprocess.run(command,stdout=stdout,stderr=stderr)
 if completed.returncode: raise RuntimeError(f'capture failed {index} {mode}: {timelog.read_text()}')
 receipt=json.loads(result.read_text())
 semantic={key:receipt[key] for key in ['total_steps','final_pc','cpu','truths','memory_words','captured_values_sha256']}
 if authority is None: authority=semantic
 if semantic!=authority: raise RuntimeError(f'capture semantic mismatch {index} {mode}')
 allruns.append({'ordinal':index,'mode':mode,'process_wall_s':time.perf_counter()-start,'packet_import_s':receipt['packet_import_ns']/1e9,'digest_s':receipt['diagnostic_digest_ns']/1e9,'capture_selection':receipt['capture_selection']})
 print(json.dumps(allruns[-1]),flush=True)
 (out/'progress.json').write_text(json.dumps(allruns,indent=2)+'\n')
summary={'schema':'rv64-capture-real-ab-v1','source_commit':'7b45fbbac','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'configuration':config,'jobs':jobs,'host':'M5 Max shared host; cooperative heavy lock, no claim of quiet host','order':['serial','two','serial','two','serial','two'],'runs':allruns,'total_steps':authority['total_steps'],'cpu_packets':len(authority['cpu']),'truth_instances':len(authority['truths']),'captured_values_sha256':authority['captured_values_sha256'],'semantic_parity':'all6 equal canonical captured values and geometry','proof_artifact_parity':'NOT RUN: no proof/acceptance diagnostic','default':'serial unchanged'}
for mode in ['serial','two']:
 summary[mode+'_median_import_s']=statistics.median(r['packet_import_s'] for r in allruns if r['mode']==mode)
summary['median_import_ratio']=summary['serial_median_import_s']/summary['two_median_import_s']
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2),flush=True)
