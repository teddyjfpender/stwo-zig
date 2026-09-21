from pathlib import Path
import re
root=Path('src/frontends/riscv/air');p=root/'opcode_memory.zig';old=p.read_text();Path('/tmp/pr198-opcode-memory-before.zig').write_text(old)
s=old
# Extract complete top-level declarations up to the next declaration/comment block
# using balanced braces, so bodies remain exact.
def decl(text,marker):
 a=text.index(marker);start=text.index('{',a);depth=0
 for b in range(start,len(text)):
  if text[b]=='{':depth+=1
  elif text[b]=='}':
   depth-=1
   if depth==0:
    end=b+1
    if end<len(text) and text[end]==';':end+=1
    return text[a:end]
 raise ValueError(marker)
move=['pub const Generated = struct','pub fn generate(','fn accessFromTrace(','fn rdAccess(','fn rs1Access(','fn rs2Access(','fn memoryAccess(','fn witness(','fn limbs(']
chunks=[]
for marker in move:
 body=decl(old,marker);assert body in s;s=s.replace(body+'\n\n','',1);chunks.append(body)
# Retired constraint entry has no remaining consumer anywhere in the source tree.
body=decl(old,'pub fn constraints(');s=s.replace(body+'\n\n','',1)
body=decl(old,'fn freeColumns(');s=s.replace(body+'\n\n','',1)
for line in ['pub const N_COLUMNS: usize = N_ACCESSES * 4;','pub const Previous = [N_ACCESSES][4][]M31;','const relation_challenges = @import("relation_challenges.zig");']:
 s=s.replace(line+'\n','')
s=s.replace('//! Opcode-side `memory_access` LogUp columns and constraints.','//! Committed opcode memory-access layouts and register-boundary validation.')
p.write_text(s)
p=root/'interaction_legacy_test_oracle.zig';s=p.read_text();s=s.replace('const opcode_memory = @import("opcode_memory.zig");','''const opcode_memory = @import("opcode_memory.zig");
const memory_logup = @import("memory_logup.zig");
const access_clock = @import("../access_clock.zig");
const N_ACCESSES = opcode_memory.N_ACCESSES;
const N_COLUMNS = N_ACCESSES * 4;
const Previous = [N_ACCESSES][4][]M31;
const accessCount = opcode_memory.accessCount;''')
s=s.replace('opcode_memory.N_COLUMNS','N_COLUMNS').replace('opcode_memory.Previous','Previous').replace('opcode_memory.generate(','generateMemory(')
chunks[0]=chunks[0].replace('pub const Generated','const Generated')
chunks[1]=chunks[1].replace('pub fn generate(','fn generateMemory(')
# These tiny layout helpers are intentionally frozen with the test oracle.
chunks+=['const AccessKind = enum { rd, rs1, rs2 };',decl(old,'fn accessKind('),decl(old,'fn accessOrdinal('),decl(old,'fn base(')]
s+='\n// Memory witness generation belongs only to this retired test oracle.\n'+'\n\n'.join(chunks)+'\n';p.write_text(s)
