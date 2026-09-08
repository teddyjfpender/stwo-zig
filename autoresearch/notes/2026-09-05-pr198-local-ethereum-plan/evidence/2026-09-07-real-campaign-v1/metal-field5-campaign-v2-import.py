from pathlib import Path
import hashlib,json,os,shutil,sys
repo=Path.cwd();campaign=repo/'.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907';out=campaign/'metal-field5-block-v1';launch=json.loads((out/'prepared-launch-v2.json').read_text());snapshot=Path(launch['cwd']);sys.path.insert(0,str(snapshot))
from scripts import ethereum_block_proof_store as store
from scripts import ethereum_block_proof_protocol as protocol

def sha(path):
 with path.open('rb') as src:return hashlib.file_digest(src,'sha256').hexdigest()

for entry in launch['controller_sources']:
 if sha(snapshot/entry['path'])!=entry['sha256']:raise SystemExit('Frozen controller changed')
for entry in [launch['prover'],launch['verifier'],*launch['aot_files']]:
 if sha(Path(entry['path']))!=entry['sha256']:raise SystemExit('Launch dependency changed')
staging=out/'.staging';store.require_directory(staging,'import staging',create=True)
imports=[]
for index,produced_name,fresh_name in [(9,'metal-field5-segment9-selected-v2','selected-real-metal-field5-fresh-v1'),(120,'metal-field5-segment120-production-v2','selected-real-metal-terminal-field5-fresh-v1')]:
 produced=campaign/produced_name;fresh=repo/'.git/local-ethereum'/fresh_name
 receipt=json.loads((produced/'receipt.json').read_text());verified=json.loads((fresh/'receipt.json').read_text());plan=json.loads((fresh/'plan.json').read_text());v=verified['verification']['verification']
 if not receipt['verified_and_published'] or not verified['passed'] or not verified['inputs_and_binary_unchanged'] or v['segment_index']!=index or v['segment_count']!=121 or v['worker_count']!=1:raise SystemExit('Imported leaf lacks exact external verification')
 for path,digest in plan['input_sha256'].items():
  if sha(Path(path))!=digest:raise SystemExit('Imported verified input changed')
 proof=Path(receipt['artifact']['path']);metadata=Path(receipt['global_metadata']['path']);leaf=json.loads(metadata.read_text());digest=receipt['artifact']['sha256']
 if sha(proof)!=digest or bytes(leaf['proof_sha256']).hex()!=digest or leaf['proof_bytes']!=proof.stat().st_size or leaf['metadata']['segment_index']!=index:raise SystemExit('Imported proof/metadata mismatch')
 destination=out/(digest+'.bin')
 if destination.exists():
  if sha(destination)!=digest:raise SystemExit('Existing destination proof mismatch')
 else:
  temp=staging/(digest+'.import');shutil.copyfile(proof,temp)
  if sha(temp)!=digest:raise SystemExit('Copied proof changed')
  try:os.link(temp,destination)
  except FileExistsError:
   if sha(destination)!=digest:raise SystemExit('Concurrent destination proof mismatch')
  temp.unlink()
 store.publish_new_or_identical(out/f'leaf-{index:06d}.json',protocol.canonical_bytes(leaf),staging_directory=staging)
 retained=out/'imports'/f'leaf-{index:06d}';retained.mkdir(parents=True,exist_ok=True)
 for source,name in [(produced/'plan.json','producer-plan.json'),(produced/'receipt.json','producer-receipt.json'),(produced/'stderr-and-time.log','producer-stderr-and-time.log'),(fresh/'plan.json','external-verifier-plan.json'),(fresh/'receipt.json','external-verifier-receipt.json'),(fresh/'stdout.json','external-verifier-stdout.json'),(metadata,'original-leaf.json')]:
  target=retained/name
  if target.exists() and target.read_bytes()!=source.read_bytes():raise SystemExit('Import provenance differs')
  if not target.exists():shutil.copyfile(source,target)
 imports.append({'segment_index':index,'artifact_sha256':digest,'artifact_bytes':leaf['proof_bytes'],'origin':str(produced),'producer_request_seconds':receipt['real_seconds'],'external_verifier_request_ns':v['request_ns'],'original_producer_executable':json.loads((produced/'plan.json').read_text())['executable'],'claim_admission':'fixed_program_narrow_v5','canonical_metadata_note':'Canonicalized equivalent LeafV1 is reverified by controller before inclusion; original metadata bytes and verification receipt retained separately.'})
accounting={'version':1,'scope':'Two previously produced and externally verified Metal leaves imported; no full bundle acceptance yet','imports':imports,'original_producer_request_seconds_total':sum(i['producer_request_seconds'] for i in imports),'original_external_verifier_request_ns_total':sum(i['external_verifier_request_ns'] for i in imports),'timing_note':'These original measurements remain part of full campaign accounting; subsequent controller invocation duration is additional and includes lock queues and repeat verification.'}
store.publish_new_or_identical(out/'import-accounting-v1.json',protocol.canonical_bytes(accounting),staging_directory=staging)
print(json.dumps(accounting))
