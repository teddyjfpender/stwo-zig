#!/usr/bin/env python3
"""Bounded official native Kona capture; never run RV64/STARK/GPU work.

Requires source prepared with the pinned host-only patch and an existing native
binary. Drives the two loopback authenticated adapters, preserving progress and
terminating complete process groups at deadline or the decoded-KV byte cap.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import transition_capture as C
from transition_transport_cache import Cache, claim_id
from prepare import validate_tree
from cache_refresh import missing_code_leaves


def hash_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1 << 20), b''):h.update(chunk)
    return h.hexdigest()


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


def validate(source, candidate):
    pin = C.read_json(HERE/'pin.json',1 << 20)
    if C.sha((HERE/'disable_optional_prefetch.patch').read_bytes()) != pin['patch_sha256']:
        raise ValueError('patch hash mismatch')
    revision = subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
    if revision != pin['revision']:
        raise ValueError('upstream revision mismatch')
    validate_tree(source, {'original_files':pin['patched_files']})
    v = C.read_json(candidate/'capture.json',1 << 20)['candidate']
    for name in ('l1-anchor','previous','next'):
        raw=(candidate/(name+'.rlp')).read_bytes()
        header = C.decode_rlp(raw)
        if int.from_bytes(header[8], 'big') != v[name]['number'] or C.keccak(raw) != C.unhex(v[name]['hash'],32):
            raise ValueError('candidate header hash mismatch')
    for name in ('previous','next'):
        raw=(candidate/(name+'-root-preimage.bin')).read_bytes()
        header=C.decode_rlp((candidate/(name+'.rlp')).read_bytes())
        if len(raw)!=128 or raw != bytes(32)+header[3]+header[16]+C.unhex(v[name]['hash'],32) or C.keccak(raw)!=C.unhex(v[name]['output_root'],32):
            raise ValueError('candidate output preimage mismatch')
    if C.decode_rlp((candidate/'next.rlp').read_bytes())[0] != C.unhex(v['previous']['hash'],32):
        raise ValueError('candidate parent hash mismatch')
    if v['previous']['number']+1!=v['next']['number']:
        raise ValueError('candidate numbers not adjacent')
    return pin,v



def resume_kv(previous, output, candidate, pin, host_hash, limit, evict_keccak=()):
    old=C.read_json(previous/'capture-run.json',1 << 20)
    if old['candidate']!=candidate or old['upstream_revision']!=pin['revision'] or old['patch_sha256']!=pin['patch_sha256'] or old['host_sha256']!=host_hash:
        raise ValueError('resume source or claim mismatch')
    output.mkdir(parents=True,exist_ok=False)
    C.write_new(output/'kvformat',b'directory')
    total=count=copied=copied_bytes=0
    evictions=set(evict_keccak);removed=[]
    with C.kv_reader(previous/'kv','directory') as rows:
        for key,value in rows:
            total+=len(value);count+=1
            if len(key)!=32 or key[0] not in (1,2,3,4,5,6) or total>limit or count>1000000 or len(value)>1 << 20:
                raise ValueError('resume KV bounds exceeded')
            if key[0]==2:
                digest=C.keccak(value)
                if digest[1:]!=key[1:]:raise ValueError('resume Keccak mismatch')
                if digest in evictions:
                    removed.append(digest.hex());continue
            if key[0]==4 and hashlib.sha256(value).digest()[1:]!=key[1:]:
                raise ValueError('resume SHA256 mismatch')
            name=key.hex();directory=output/name[:4];directory.mkdir(exist_ok=True)
            with (directory/(name[4:]+'.txt')).open('xb') as f:f.write(value.hex().encode())
            copied+=1;copied_bytes+=len(value)
    if set(removed)!={x.hex()for x in evictions}:raise ValueError('refresh source changed before copy')
    return {'rows':copied,'decoded_bytes':copied_bytes,'source_rows':count,'source_decoded_bytes':total,'evicted_account_leaves':removed}



def kv_usage(path):
    decoded=allocated=count=0
    for directory,_,names in os.walk(path):
        allocated+=Path(directory).stat().st_blocks*512
        for name in names:
            try:info=Path(directory,name).stat()
            except FileNotFoundError:continue
            allocated+=info.st_blocks*512
            if name.endswith('.txt'):
                decoded+=info.st_size//2;count+=1
    return decoded,allocated,count



def supplement_records(kv, paths, limit):
    decoded,allocated,count=kv_usage(kv);added=added_bytes=0;inputs=[]
    if len(paths)>16:raise ValueError('supplement file count cap')
    for path in paths:
        rows=C.read_json(path,16<<20)
        if not isinstance(rows,list)or len(rows)>1000000:raise ValueError('supplement row cap')
        inputs.append({'path':str(path),'sha256':hash_file(path)})
        for key,value in rows:
            digest=C.unhex(key,32);raw=C.unhex(value)
            if len(raw)>1<<20 or C.keccak(raw)!=digest:raise ValueError('supplement preimage hash mismatch')
            name=(bytes([2])+digest[1:]).hex();folder=kv/name[:4];file=folder/(name[4:]+'.txt')
            if file.exists():
                if C.unhex(file.read_text())!=raw:raise ValueError('supplement source conflict')
                continue
            if decoded+len(raw)>limit or count+1>1000000:raise ValueError('supplement KV cap')
            folder.mkdir(exist_ok=True)
            with file.open('xb')as f:f.write(raw.hex().encode())
            decoded+=len(raw);count+=1;added+=1;added_bytes+=len(raw)
    _,allocated,_=kv_usage(kv)
    if allocated>4<<30:raise ValueError('supplement filesystem cap')
    return {'inputs':inputs,'rows_added':added,'decoded_bytes_added':added_bytes}


def run(source,candidate,l1,l2,beacon,output,seconds=180,kv_limit=64 << 20,resume=None,header_window=1,transport_cache=None,stop_on_failure=False,code_provenance=(),refresh_missing_code=False,verified_records=(),pooled_rpc=False,rpc_min_interval=0):
    if not 1<=seconds<=180 or not 1<=kv_limit<=64 << 20 or not 1<=header_window<=32:
        raise ValueError('capture limits invalid')
    for url in (l1,l2,beacon):C.endpoint_label(url)
    pin,v=validate(source,candidate)
    if transport_cache is not None:Cache(transport_cache,claim_id(v))
    binary=source/'rust/target/debug/kona-host'
    if binary.is_symlink() or not binary.is_file():raise ValueError('prepared native executable missing')
    provenance_paths=list(code_provenance)
    if resume is not None and (resume/'l2-adapter/code-provenance.json').is_file():
        provenance_paths.insert(0,resume/'l2-adapter/code-provenance.json')
    if len(provenance_paths)>16:raise ValueError('provenance input count cap')
    for path in provenance_paths:
        C.read_json(path,16<<20)
    refresh=None
    if refresh_missing_code:
        if resume is None:raise ValueError('code refresh requires existing capture')
        import transition_rpc_adapter as A
        advice=A.Adapter('https://example.invalid',code_provenance=provenance_paths,provenance_block=v['previous']['hash'])
        header=C.decode_rlp((candidate/'previous.rlp').read_bytes())
        refresh=missing_code_leaves(resume/'kv',header[3],advice.code_accounts.keys())
    output.mkdir(parents=True,exist_ok=False)
    evict=[bytes.fromhex(x['leaf_hash'])for x in refresh['evictions']]if refresh else ()
    resumed=resume_kv(resume,output/'kv',v,pin,hash_file(binary),kv_limit,evict) if resume else None
    supplements=supplement_records(output/'kv',verified_records,kv_limit) if verified_records else None
    started=time.monotonic()
    deadline=started+seconds
    children=[];logs=[];host=None;reason='failed';peak=0;peak_allocated=0
    # Explicit minimal child environment: no ambient RPC credentials/CLI config.
    child_env={'PATH':'/usr/bin:/bin','RUST_LOG':'warn'}
    try:
        ports=[]
        for label,rpc in (('l1',l1),('l2',l2)):
            port=free_port();ports.append(port)
            log=(output/(label+'-adapter.log')).open('xb');logs.append(log)
            command=[sys.executable,str(HERE.parent/'transition_rpc_adapter.py'),'--rpc',rpc,'--port',str(port),'--seconds',str(seconds),'--header-window',str(header_window),'--output',str(output/(label+'-adapter'))]
            if pooled_rpc:command += ['--pooled-rpc']
            if rpc_min_interval:command += ['--rpc-min-interval-seconds',str(rpc_min_interval)]
            if label=='l1' and transport_cache is not None:
                command += ['--transport-cache',str(transport_cache),'--cache-claim',claim_id(v)]
            if label=='l2' and provenance_paths:
                command += ['--provenance-block',v['previous']['hash']]
                for path in provenance_paths:command += ['--code-provenance',str(path)]
            proc=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=child_env);children.append(proc)
            ready=False
            while time.monotonic()<deadline and proc.poll() is None:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):pass
                    ready=True;break
                except OSError:time.sleep(.05)
            if not ready:raise ValueError('adapter startup failed')
        command=[str(binary),'single','--native','--disable-execution-witness-prefetch',
                 '--l1-head',v['l1-anchor']['hash'],'--agreed-l2-head-hash',v['previous']['hash'],
                 '--agreed-l2-output-root',v['previous']['output_root'],
                 '--claimed-l2-output-root',v['next']['output_root'],
                 '--claimed-l2-block-number',str(v['next']['number']),
                 '--l1-node-address',f'http://127.0.0.1:{ports[0]}',
                 '--l2-node-address',f'http://127.0.0.1:{ports[1]}',
                 '--l1-beacon-address',beacon,'--l2-chain-id','10',
                 '--data-dir',str(output/'kv'),'--data-format','directory']
        log=(output/'host.log').open('xb');logs.append(log)
        host=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=child_env);children.append(host)
        while host.poll() is None:
            total,allocated,count=kv_usage(output/'kv')
            peak=max(peak,total);peak_allocated=max(peak_allocated,allocated)
            if total>kv_limit or allocated>4<<30 or count>1000000:reason='kv_limit';break
            if any(p.stat().st_size>2 << 20 for p in output.glob('*.log')):reason='log_limit';break
            if stop_on_failure and any(b'\"adapter_failure\"' in p.read_bytes() for p in output.glob('*-adapter.log')):
                reason='diagnostic_adapter_failure';break
            if time.monotonic()>=deadline:reason='deadline';break
            if any(p.poll() is not None for p in children[:-1]):reason='adapter_exited';break
            time.sleep(.25)
        else:
            reason='native_accepted' if host.returncode==0 else 'native_rejected'
    finally:
        for proc in reversed(children):
            if proc.poll() is None:
                try:os.killpg(proc.pid,signal.SIGINT)
                except ProcessLookupError:pass
        for proc in reversed(children):
            try:proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL);proc.wait()
        for log in logs:log.close()
        total,allocated,count=kv_usage(output/'kv')
        peak=max(peak,total);peak_allocated=max(peak_allocated,allocated)
        if total>kv_limit or allocated>4<<30 or count>1000000:reason='kv_limit'
        result={'status':reason,'elapsed_seconds':time.monotonic()-started,'seconds_cap':seconds,'decoded_kv_bytes_cap':kv_limit,'peak_observed_decoded_kv_bytes':peak,'filesystem_kv_bytes_cap':4<<30,'peak_observed_allocated_kv_bytes':peak_allocated,'kv_rows':count,
                'upstream_revision':pin['revision'],'patch_sha256':pin['patch_sha256'],'host_sha256':hash_file(binary),
                'candidate':v,'upstream_native_client_accepted':reason=='native_accepted',
                'complete_exported_witness':False,'derivation_accepted':False,'proof_verified':False,'guest_executed':False,
                'host_exit_code':host.returncode if host else None,'resumed_kv':resumed,'header_window':header_window,'transport_cache':str(transport_cache) if transport_cache else None,'stop_on_adapter_failure':stop_on_failure,'code_provenance_inputs':[{'sha256':hash_file(p),'path':str(p)}for p in provenance_paths],'code_provenance_refresh':refresh,'verified_record_supplements':supplements,'pooled_rpc':pooled_rpc,'rpc_min_interval':rpc_min_interval,'upstream_endpoints':{'l1':C.endpoint_label(l1),'l2':C.endpoint_label(l2),'beacon':C.endpoint_label(beacon)}}
        C.write_new(output/'capture-run.json',(json.dumps(result,indent=2)+'\n').encode())
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--l1-rpc',required=True);p.add_argument('--l2-rpc',required=True);p.add_argument('--beacon',required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--seconds',type=int,default=180);p.add_argument('--resume',type=Path);p.add_argument('--header-window',type=int,default=1);p.add_argument('--transport-cache',type=Path);p.add_argument('--stop-on-adapter-failure',action='store_true');p.add_argument('--code-provenance',type=Path,action='append',default=[]);p.add_argument('--refresh-missing-code-provenance',action='store_true');p.add_argument('--verified-records',type=Path,action='append',default=[]);p.add_argument('--pooled-rpc',action='store_true');p.add_argument('--rpc-min-interval-seconds',type=float,default=0)
    a=p.parse_args()
    try:print(json.dumps(run(a.source.resolve(),a.candidate.resolve(),a.l1_rpc,a.l2_rpc,a.beacon,a.output.absolute(),a.seconds,resume=a.resume.resolve() if a.resume else None,header_window=a.header_window,transport_cache=a.transport_cache.resolve() if a.transport_cache else None,stop_on_failure=a.stop_on_adapter_failure,code_provenance=[p.resolve()for p in a.code_provenance],refresh_missing_code=a.refresh_missing_code_provenance,verified_records=[p.resolve()for p in a.verified_records],pooled_rpc=a.pooled_rpc,rpc_min_interval=a.rpc_min_interval_seconds),indent=2))
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print(json.dumps({'status':'capture_host_failed','error_type':type(error).__name__}));raise SystemExit(1)from None
