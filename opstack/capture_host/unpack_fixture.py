#!/usr/bin/env python3
"""Boundedly unpack and hash-check a retained OPD; native replay is explicit."""
import argparse
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transition_capture as C
from capture_host.verify_export import run_native,expected_statement

MAX=16<<20

def decode(manifest):
    m=C.read_json(manifest,1<<20)
    if m['schema']!='op-retained-anchored-mainnet-fixture-v1' or m['file']!='input.opd.gz':raise ValueError('fixture manifest framing')
    for key in('compressed_bytes','uncompressed_bytes'):
        if type(m[key])is not int or not 0<m[key]<=MAX:raise ValueError('fixture size cap')
    path=manifest.parent/m['file']
    if path.is_symlink()or path.stat().st_size!=m['compressed_bytes']:raise ValueError('fixture compressed length')
    encoded=path.read_bytes()
    if C.sha(encoded)!=m['compressed_sha256']or encoded[:3]!=b'\x1f\x8b\x08'or encoded[3]!=0 or encoded[4:8]!=bytes(4):raise ValueError('fixture compressed hash/header')
    with gzip.GzipFile(fileobj=io.BytesIO(encoded),mode='rb')as stream:raw=stream.read(m['uncompressed_bytes']+1)
    if len(raw)!=m['uncompressed_bytes']or C.sha(raw)!=m['uncompressed_sha256']:raise ValueError('fixture decompressed hash/length')
    return raw,m


def unpack(manifest,output,native_host=None):
    raw,m=decode(manifest);C.write_new(output,raw)
    result={'bytes':len(raw),'sha256':C.sha(raw),'guest_executed':False,'proof_verified':False}
    if native_host is not None:
        statement,seconds=run_native(native_host.resolve(),output,output.parent/(output.stem+'-reads.json'),output.parent,time.monotonic()+180)
        od=expected_statement(statement,m['claim'],m['statement']['block_hash'])
        if statement!=m['statement']or od.hex()!=m['od_public_output']:raise ValueError('fresh native fixture statement differs')
        result.update(native_derivation_accepted=True,native_seconds=seconds,native_host_sha256=C.sha(native_host.read_bytes()),od_public_output=od.hex())
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--native-host',type=Path)
    a=p.parse_args()
    try:print(json.dumps(unpack(a.manifest,a.output,a.native_host),indent=2))
    except(ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError)as error:
        print(json.dumps({'status':'fixture_rejected','error_type':type(error).__name__}));raise SystemExit(1)from None
