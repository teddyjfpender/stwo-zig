from pathlib import Path
import re,json,hashlib
root=Path('src/frontends/riscv/recursion');expected=json.loads(Path('/tmp/pr198-outer-transaction-transformed-v1.json').read_text());checks=[]
def tokens(s):
 return [m[0] for m in re.finditer(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/|\s+|.',s) if not m[0].isspace() and not m[0].startswith(('//','/*'))]
def check(name,left,right):
 assert tokens(left)==tokens(right), name
 checks.append({'name':name,'equivalent_tokens':True,'current_sha256':hashlib.sha256(right.encode()).hexdigest()})
def extract(s,start):
 i=s.index(start);j=s.index('{',i)+1;depth=1
 while depth:
  if s[j]=='{':depth+=1
  elif s[j]=='}':depth-=1
  j+=1
 if s[j:j+1]==';':j+=1
 return s[i:j]
for name,s in expected.items():
 if name=='segment_outer_transaction_v2':
  s=s.replace('const CpuBackend = Backend;\n','').replace('const prover_work_pool = prover_engine.work_pool;\n','').replace('const core_outer = Diagnostics;\n','').replace('core_outer.','Diagnostics.').replace('ProverEngineForBackend(CpuBackend)','ProverEngineForBackend(Backend)').replace('@import("binary_verified_publication.zig")','@import("canonical_proof_identity_v1.zig")').replace('binary_verified_publication','canonical_identity')
 if name=='segment_verified_artifact_v2':s=s.replace('@import("segment_outer_cohort_v2.zig")','@import("segment_public_wire_boundary_v2.zig")').replace('@import("air/segment_outer_adapter_manifest_v2.zig")','@import("air/segment_outer_manifest_contract_v2.zig")')
 if name=='segment_outer_transaction_support_v2':s=s.replace('const Engine = struct { const Channel = @import("poseidon2_channel.zig").Channel; };','const Channel = @import("poseidon2_channel.zig").Channel;').replace('*Engine.Channel','*Channel')
 if name=='binary_verified_publication':
  s=s.replace('pub const Error = pair_node.Error || global_closure.Error || error{','pub const Error = pair_node.Error || global_closure.Error || @import("canonical_proof_identity_v1.zig").Error || error{')
  for e in ['EmptyProofEncoding','EmptySha256Digest','InvalidNativeDigest','ProofEncodingTooLarge','ProofEncodingLengthMismatch','ProofIdentityAlreadyFinalized']:s=s.replace('    '+e+',\n','')
  for n in ['CanonicalProofIdentityV1','CanonicalProofIdentityStreamV1']:
   b=extract(s,'pub const '+n+' = struct');s=s.replace(b,'pub const '+n+' = @import("canonical_proof_identity_v1.zig").'+n+';')
  for n in ['requireNativeDigest','requireSha256Digest']:
   b=extract(s,'fn '+n+'(');s=s.replace(b,'const '+n+' = @import("canonical_proof_identity_v1.zig").'+n+';')
 check(name,s,(root/(name+'.zig')).read_text())
old=Path('/tmp/pr198-proof-identity-original-v1.txt').read_text();new=(root/'canonical_proof_identity_v1.zig').read_text()
for name in ['CanonicalProofIdentityV1','CanonicalProofIdentityStreamV1']:
 check('identity:'+name,extract(old,'pub const '+name+' = struct'),extract(new,'pub const '+name+' = struct'))
for name in ['requireNativeDigest','requireSha256Digest']:check('identity:'+name,extract(old,'fn '+name+'('),extract(new,'fn '+name+'('))
old=json.loads(Path('/tmp/pr198-public-wire-originals-v1.json').read_text());plan=old[str(root/'segment_outer_cohort_v2_cohort_plan_v2.zig')];contract=old[str(root/'segment_outer_cohort_v2_contract.zig')];new=(root/'segment_public_wire_boundary_v2.zig').read_text()
check('public-wire:type',extract(plan,'pub const PublicWireBoundaryV2 = struct'),extract(new,'pub const PublicWireBoundaryV2 = struct'))
for name in ['publicWireBoundaryIdentity','requireCanonical','allZero','hashQM31']:check('public-wire:'+name,extract(plan,'pub fn '+name+'('),extract(new,'pub fn '+name+'('))
check('public-wire:hashInt',extract(contract,'pub fn hashInt('),extract(new,'pub fn hashInt('))
for name in ['PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION','PUBLIC_WIRE_BOUNDARY_ID_DOMAIN']:
 check('public-wire:'+name,re.search(r'pub const '+name+r'[^;]+;',contract)[0],re.search(r'pub const '+name+r'[^;]+;',new)[0])
old=json.loads(Path('/tmp/pr198-engine-protocol-originals-v1.json').read_text())[str(root/'engine.zig')];new=(root/'engine_protocol.zig').read_text()
for name in ['Hasher','MerkleChannel','Channel','Proof','ExtendedProof']:
 check('engine-protocol:'+name,re.search(r'pub const '+name+r'[^;]+;',old)[0],re.search(r'pub const '+name+r'[^;]+;',new)[0])
old=json.loads(Path('/tmp/pr198-native-mask-originals-v1.json').read_text());new=Path('src/frontends/riscv/air/guest_precompile/mask_layout.zig').read_text()
for component,name in [('secp256k1','MAIN_MASK_OFFSETS'),('keccakf','STATE_MASK_OFFSETS')]:
 s=old['src/frontends/riscv/air/guest_precompile/'+component+'_component.zig'];check('native-mask:'+component,re.search(r'pub const '+name+r'[^;]+;',s)[0].replace(name,component.upper()+'_'+name),re.search(r'pub const '+component.upper()+'_'+name+r'[^;]+;',new)[0])
Path('/tmp/pr198-outer-transaction-transfer-audit-v1.json').write_text(json.dumps({'passed':True,'checks':checks,'transformations':['explicit dependencies and backend/diagnostic parameters','facade aliases and retained named test wrappers','shared canonical identity returns its exact six possible errors; binary publication retains its full error union','public-wire Error drops a redundant catalog union already included in manifest Error','shared nominal public-wire type and helpers replace previous definitions','protocol-only hash/channel and native OODS mask constants retain exact definitions']},indent=2)+'\n')
print('Source transfer audit:',len(checks),'checks passed.')
