"""Actual durable receiver rekey-negative gate; bin files stay hardlinked/read-only."""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def differences(a,b,path=''):
    if type(a)!=type(b): return [path]
    if isinstance(a,dict):
        if a.keys()!=b.keys(): return [path]
        return sum((differences(a[k],b[k],path+'.'+k) for k in a),[])
    if isinstance(a,list):
        if len(a)!=len(b): return [path]
        return sum((differences(x,y,path+f'[{i}]') for i,(x,y) in enumerate(zip(a,b))),[])
    return [] if a==b else [path]
def main():
    ap=argparse.ArgumentParser();ap.add_argument('cli');ap.add_argument('config');ap.add_argument('prefix');ap.add_argument('complete');ap.add_argument('output');x=ap.parse_args()
    out=Path(x.output);out.mkdir(exist_ok=False)
    binary=out/'receiver';shutil.copy2(x.cli,binary)
    report={'binary_sha256':sha(binary),'receiver_source_authority':'old root control CLI, receiver unchanged by truth composition optimization','scope':'actual fresh durable receiver; declaration-only mutation, unchanged physical proofs and cells','whole_protocol_128':False,'cases':[]}
    for kind,original,mode in [('cpu',Path(x.prefix),'verify-prefix-control'),('keccak',Path(x.complete),'verify-control')]:
        original_json=original/'bundle.json';original_sha=sha(original_json);before=json.loads(original_json.read_text());changed=json.loads(original_json.read_text())
        if kind=='cpu':
            g=changed['cpus'][0]['declaration']['geometry'];old=g['alu_log'];g['alu_log']=old+1
            assert old+1<=22 and changed['cpus'][0]['request']['cpu']['steps'] < 1<<g['cpu_log']
            expected_path='.cpus[0].declaration.geometry.alu_log'
        else:
            truth=changed['truths'][0]['declaration'];assert truth['family']=='keccak' and truth['logs'][0]==18
            old=truth['logs'][0];truth['logs'][0]=19
            assert ((truth['calls']+1)//2)*29 <= 1<<19 and truth['logs'][0]<=21
            assert ((truth['calls']+1)//2)*24*1600 < 2147483647
            expected_path='.truths[0].declaration.logs[0]'
        assert differences(before,changed)==[expected_path]
        mutant=out/(kind+'-mutated');mutant.mkdir()
        bins={p.name:sha(p) for p in original.iterdir() if p.name.endswith('.bin')}
        for name in bins: os.link(original/name,mutant/name)
        (mutant/'bundle.json').write_text(json.dumps(changed,indent=2)+'\n')
        results={}
        for label,bundle in [('accepted-control',original),('mutated',mutant)]:
            proc=subprocess.run([str(binary),mode,x.config,str(bundle)],capture_output=True,text=True)
            (out/(kind+'-'+label+'.stdout')).write_text(proc.stdout);(out/(kind+'-'+label+'.stderr')).write_text(proc.stderr)
            if label=='accepted-control':
                assert proc.returncode==0,(kind,proc.stderr)
                result=json.loads(proc.stdout);assert result['accepted'] and result['completed_ethereum_block']==(kind=='keccak')
            else:
                assert proc.returncode!=0,(kind,'accepted mutated geometry')
                match=re.search(r'error: (\w+)',proc.stderr);assert match,(kind,proc.stderr)
                error=match.group(1)
                assert error==('LocalGkrReceiptShape' if kind=='cpu' else 'WideCpuPublicRamMismatch'),(kind,proc.stderr)
                assert error not in ['OutOfMemory','InvalidServicesTruthGeometry','InvalidServicesWireRoster','ServicesWireBudget'],(kind,proc.stderr)
                result={'rejected':True,'error':error,'phase':'after declaration preflight and independently rebuilt keys; exact rejection authority pinned in qualification note'}
            results[label]=result
        assert sha(original_json)==original_sha
        assert {name:sha(mutant/name) for name in bins}==bins
        assert all((mutant/name).stat().st_ino==(original/name).stat().st_ino for name in bins)
        report['cases'].append({'kind':kind,'mutation':expected_path,'old':old,'new':old+1,'original_bundle_sha256':original_sha,'mutated_bundle_sha256':sha(mutant/'bundle.json'),'physical_file_sha256':bins,'hardlinked_physical_files':len(bins),'original_unchanged':True,'results':results})
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'passed':True,'cases':len(report['cases']),'report':str(out/'report.json')}))
if __name__=='__main__':main()
