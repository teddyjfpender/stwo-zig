"""Read-only geometry census of previously verified BLAKE3 CSP artifacts.
Not a verifier: artifact authentication remains the matching product CLI's job.
Wire authorities: blake3_profile_artifact, blake3_execution_manifest, and
proof_artifact_wire.encodeStatementFor in src/frontends/riscv/prover.
"""
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
KINDS=['program','memory','clock_update','poseidon2','merkle','bitwise','range_check_20','range_check_8_11','range_check_8_8_4','range_check_8_8','range_check_m31']
records=[]
for path in sorted((ROOT/'autoresearch/notes/2026-09-23-blake3-word-memory/suite').glob('*.b3proof')):
 raw=path.read_bytes()
 assert raw[:8] in (b'B3EVART1',b'B3PVART1',b'B3RVART1')
 version,manifest_len,proof_len=struct.unpack_from('<IQQ',raw,8)
 assert version==1 and len(raw)==28+manifest_len+proof_len
 manifest=raw[28:28+manifest_len]
 # Extension prefixes vary by profile; locate and validate the nested header.
 offset=manifest.index(b'B3EXADM1')
 assert manifest.count(b'B3EXADM1')==1
 inner=manifest[offset:]
 assert struct.unpack_from('<I',inner,8)[0]==1
 statement_len,plan_len=struct.unpack_from('<QQ',inner,104)
 assert len(inner)==184+statement_len+plan_len
 metadata=inner[184:184+statement_len]
 n=struct.unpack_from('<I',metadata)[0]
 assert n<=256
 pos=4+13*n # enum(u8), then three u32 fields
 initial_pc,final_pc,steps,count=struct.unpack_from('<IIII',metadata,pos)
 pos+=16
 assert count<=512
 tables=[]
 for i in range(count):
  kind,log,rows,width=struct.unpack_from('<IIII',metadata,pos);pos+=16
  assert kind<len(KINDS) and log<=24
  tables.append(dict(kind=KINDS[kind],log_size=log,rows=rows,main_columns=width))
 records.append(dict(case=path.stem,artifact_sha256=hashlib.sha256(raw).hexdigest(),steps=steps,infra=tables))
(HERE/'geometry.json').write_text(json.dumps(records,indent=2)+'\n')
for r in records:
 if r['case'].startswith('cpu-'):
  print(r['case'],', '.join(f"{t['kind']}:{t['log_size']}" for t in r['infra']))
