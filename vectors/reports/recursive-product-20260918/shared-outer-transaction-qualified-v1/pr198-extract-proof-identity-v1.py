from pathlib import Path
import json
root=Path('src/frontends/riscv/recursion');p=root/'binary_verified_publication.zig';s=p.read_text();Path('/tmp/pr198-proof-identity-original-v1.txt').write_text(s)
def extract(s,start):
 i=s.index(start);j=s.index('{',i)+1;depth=1
 while depth:
  if s[j]=='{':depth+=1
  elif s[j]=='}':depth-=1
  j+=1
 if s[j:j+1]==';':j+=1
 return s[i:j]
names=['CanonicalProofIdentityV1','CanonicalProofIdentityStreamV1'];blocks={n:extract(s,'pub const '+n+' = struct') for n in names};helpers={n:extract(s,'fn '+n+'(') for n in ['requireNativeDigest','requireSha256Digest']}
errors=['EmptyProofEncoding','EmptySha256Digest','InvalidNativeDigest','ProofEncodingTooLarge','ProofEncodingLengthMismatch','ProofIdentityAlreadyFinalized']
header='//! Canonical proof-byte identities, independent of publication and witness preparation.\nconst std = @import("std");\nconst stwo_core = @import("stwo_core");\nconst M31 = stwo_core.fields.m31.M31;\nconst m31 = stwo_core.fields.m31;\nconst channel = @import("poseidon2_channel.zig");\nconst protocol = @import("protocol.zig");\nconst NativeDigest = channel.Digest;\nconst Sha256Digest = [32]u8;\npub const Error = error{'+','.join(errors)+'};\n\n'
(root/'canonical_proof_identity_v1.zig').write_text(header+'\n\n'.join([*blocks.values(),*['pub '+h for h in helpers.values()]])+'\n')
s=s.replace('pub const Error = pair_node.Error || global_closure.Error || error{','pub const Error = pair_node.Error || global_closure.Error || @import("canonical_proof_identity_v1.zig").Error || error{')
for e in errors:s=s.replace('    '+e+',\n','')
for n,b in blocks.items():s=s.replace(b,'pub const '+n+' = @import("canonical_proof_identity_v1.zig").'+n+';')
for n,b in helpers.items():s=s.replace(b,'const '+n+' = @import("canonical_proof_identity_v1.zig").'+n+';')
p.write_text(s)
p=root/'segment_outer_transaction_v2.zig';s=p.read_text().replace('@import("binary_verified_publication.zig")','@import("canonical_proof_identity_v1.zig")');p.write_text(s)
p=root/'mod.zig';p.write_text(p.read_text()+'pub const canonical_proof_identity_v1 = @import("canonical_proof_identity_v1.zig");\n')
