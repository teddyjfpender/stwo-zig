#!/usr/bin/env python3
"""Reconstruct standard sidecars and canonical OPD records from native Kona KV.

Blob fields/proofs are opaque until the independent pinned c-kzg checker passes.
Oracle blob scaffolding is not packed as ordinary OPD records. Native acceptance
of the resulting OPD remains a separate mandatory gate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

import transition_capture as C

FR=int('73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001',16)
ROOT=10238227357739495823651030575849232062558860180284477541189508159991286009131
SETUP_SHA='d39b9f2d047cc9dca2de58f264b6a09448ccd34db967881a6713eacacf0f26b7'


def roots():
    generator=pow(ROOT,1<<20,FR)
    if pow(generator,4096,FR)!=1 or pow(generator,2048,FR)==1:raise ValueError('root order mismatch')
    values=[1]
    for _ in range(4095):values.append(values[-1]*generator%FR)
    return [values[int(f'{i:012b}'[::-1],2)].to_bytes(32,'big') for i in range(4096)]


class Store:
    def __init__(self,path):self.path=Path(path)
    def read(self,tag,digest,width):
        name=(bytes([tag])+digest[1:]).hex();directory=self.path/name[:4];file=directory/(name[4:]+'.txt')
        if directory.is_symlink()or file.is_symlink()or not file.is_file()or file.stat().st_size>2*width:
            raise ValueError('missing or oversized native KV field')
        value=C.unhex(file.read_text())
        if len(value)!=width:raise ValueError('native KV field width')
        return value
    def commitment_rows(self):
        for directory in sorted(self.path.iterdir()):
            if not re.fullmatch('04[0-9a-f]{2}',directory.name):continue
            if directory.is_symlink()or not directory.is_dir():raise ValueError('unsafe SHA namespace')
            for file in sorted(directory.iterdir()):
                if not re.fullmatch('[0-9a-f]{60}\\.txt',file.name)or file.is_symlink():raise ValueError('invalid commitment key')
                key=bytes.fromhex(directory.name+file.stem)
                value=self.read(4,key,48)
                if hashlib.sha256(value).digest()[1:]!=key[1:]:raise ValueError('commitment SHA key mismatch')
                yield value


def reconstruct(store,commitment,unity):
    fields=[];helpers=set();blob_keys=set()
    for root in unity:
        preimage=commitment+root;digest=C.keccak(preimage)
        if store.read(2,digest,80)!=preimage:raise ValueError('blob helper preimage mismatch')
        value=store.read(5,digest,32)
        if int.from_bytes(value,'big')>=FR:raise ValueError('noncanonical blob scalar')
        fields.append(value);helpers.add(digest);blob_keys.add(bytes([5])+digest[1:])
    preimage=commitment+unity[-1][:24]+(4096).to_bytes(8,'big');digest=C.keccak(preimage)
    if store.read(2,digest,80)!=preimage:raise ValueError('blob proof helper mismatch')
    proof=store.read(5,digest,48);helpers.add(digest);blob_keys.add(bytes([5])+digest[1:])
    return {'kzg_commitment':commitment.hex(),'kzg_proof':proof.hex(),'blob':b''.join(fields).hex()},helpers,blob_keys


def export(kv,output,checker,setup,keep_helpers=False):
    if C.sha(setup.read_bytes())!=SETUP_SHA:raise ValueError('trusted setup SHA mismatch')
    store=Store(kv);commitments=list(store.commitment_rows())
    if len(commitments)>256 or len(set(commitments))!=len(commitments):raise ValueError('commitment count/duplicate')
    sidecars=[];helpers=set();owned_blob=set();unity=roots()
    for commitment in sorted(commitments):
        row,h,b=reconstruct(store,commitment,unity);sidecars.append(row);helpers.update(h);owned_blob.update(b)
    records={};counts={};raw_bytes=0;scanned=0;seen_blob=set()
    with C.kv_reader(kv,'directory')as rows:
        for key,value in rows:
            scanned+=1;raw_bytes+=len(value)
            if len(key)!=32 or len(value)>1<<20 or scanned>1000000 or raw_bytes>64<<20:raise ValueError('native transport KV cap')
            counts[str(key[0])]=counts.get(str(key[0]),0)+1
            if key[0]==2:
                digest=C.keccak(value)
                if digest[1:]!=key[1:]:raise ValueError('Keccak namespace authentication')
                if keep_helpers or digest not in helpers:records[digest]=value
            elif key[0]==4:
                if len(value)!=48 or hashlib.sha256(value).digest()[1:]!=key[1:]:raise ValueError('SHA namespace authentication')
            elif key[0]==5:
                if key not in owned_blob:raise ValueError('unowned blob field key')
                seen_blob.add(key)
            elif key[0]not in(1,3,6):raise ValueError('unknown native preimage namespace')
    if seen_blob!=owned_blob:raise ValueError('incomplete blob field namespace')
    if len(records)>C.MAX_RECORDS:raise ValueError('ordinary OPD record cap')
    output.mkdir(parents=True,exist_ok=False)
    bundle=struct.pack('<I',len(sidecars))+b''.join(C.unhex(r['kzg_commitment'],48)+C.unhex(r['kzg_proof'],48)+C.unhex(r['blob'],C.BLOB_BYTES)for r in sidecars)
    C.write_new(output/'sidecars.bin',bundle)
    result=subprocess.run([str(checker),str(setup),str(output/'sidecars.bin')],capture_output=True,text=True,timeout=120,env={'PATH':'/usr/bin:/bin'})
    if result.returncode!=0:raise ValueError('independent standard sidecar KZG rejection')
    checked=json.loads(result.stdout)
    if checked.get('verified_standard_sidecars')!=len(sidecars)or checked.get('trusted_setup_sha256')!=SETUP_SHA or checked.get('kzg_verified')is not True:
        raise ValueError('KZG checker receipt mismatch')
    C.write_new(output/'records.json',(json.dumps([(k.hex(),v.hex())for k,v in sorted(records.items())])+'\n').encode())
    C.write_new(output/'sidecars.json',(json.dumps(sidecars)+'\n').encode())
    report={'schema':'op-native-kv-export-v1','transport_namespaces':counts,'transport_rows':scanned,'transport_decoded_bytes':raw_bytes,
            'ordinary_records':len(records),'ordinary_payload_bytes':sum(map(len,records.values())),
            'blob_sidecars':len(sidecars),'removed_exact_oracle_blob_helpers':0 if keep_helpers else len(helpers),
            'preimage_hashes_verified':True,'kzg_verified':True,'trusted_setup_sha256':SETUP_SHA,
            'checker_sha256':C.sha(checker.read_bytes()),'sidecar_bundle_sha256':C.sha(bundle),
            'complete_witness':False,'derivation_accepted':False,'proof_verified':False}
    C.write_new(output/'capture.json',(json.dumps(report,indent=2)+'\n').encode())
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--kv',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--checker',type=Path,required=True);p.add_argument('--trusted-setup',type=Path,required=True)
    p.add_argument('--keep-blob-helpers',action='store_true');a=p.parse_args()
    try:print(json.dumps(export(a.kv,a.output,a.checker.resolve(),a.trusted_setup,a.keep_blob_helpers),indent=2))
    except(ValueError,KeyError,TypeError,OSError,subprocess.SubprocessError)as error:
        print(json.dumps({'status':'native_kv_export_failed','error_type':type(error).__name__}));raise SystemExit(1)from None
