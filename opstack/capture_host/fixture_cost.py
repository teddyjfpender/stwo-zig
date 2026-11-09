#!/usr/bin/env python3
"""Source-derived workload/capacity census of a retained fixture; no execution."""
import argparse
import json
from pathlib import Path
import struct
import sys
import zlib
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import transition_capture as C
from capture_host.unpack_fixture import decode


def census(manifest):
    raw,m=decode(manifest);shape=C.inspect_container(raw,m['claim'])
    body=zlib.decompress(raw[C.HEADER:])if raw[:8]==b'STWOPDZ1'else raw[C.HEADER:]
    witness_len,count=struct.unpack_from('<II',raw,168);records=shape['records']
    lengths=[struct.unpack_from('<I',body,24+i*40+36)[0]for i in range(records)]
    nonzero=[]
    for i in range(count):
        blob=body[witness_len+i*C.SIDECAR_BYTES+96:witness_len+(i+1)*C.SIDECAR_BYTES]
        nonzero.append(sum(blob[j:j+32]!=bytes(32)for j in range(0,len(blob),32)))
    return {'schema':'op-fixture-source-capacity-v1','input_sha256':m['uncompressed_sha256'],'input_bytes':len(raw),'body_bytes':len(body),'witness_bytes':witness_len,'records':records,'preimage_payload_bytes':sum(lengths),'preimage_keccak_permutations_if_hashed_once':sum(n//136+1 for n in lengths),'sidecars':count,'blob_scalars':count*4096,'nonzero_blob_scalars':sum(nonzero),'nonzero_per_blob':nonzero,'dense_blob_count':sum(n>2048 for n in nonzero),'sparse_blob_count':sum(n<=2048 for n in nonzero),'evaluation_point_sha256_compression_blocks':count*((len(b'FSBLOBVERIFY_V1_')+16+131072+48+9+63)//64),'batch_pairing_checks':int(count>0),'limits':{'input_bytes':(32<<20)-4,'body_bytes':64<<20,'records':131072,'sidecars':256},'guest_executed':False,'native_executed':False,'proof_verified':False,'proving_benchmark':False,'interpretation':'Counts are fixture/source-derived; hashing each preimage once is a stated model, not measured service-call or guest-instruction counts.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True);a=p.parse_args();print(json.dumps(census(a.manifest),indent=2))
