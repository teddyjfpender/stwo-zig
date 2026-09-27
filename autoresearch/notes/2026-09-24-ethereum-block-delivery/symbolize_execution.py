from pathlib import Path
import bisect,collections,hashlib,json,re,subprocess
h=Path(__file__).resolve().parent
profile=json.loads((h/'execution-pc-counts.json').read_text())
elf=h/'ethereum-block.elf'
assert hashlib.sha256(elf.read_bytes()).hexdigest()==profile['elf_sha256']
text=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-nm','--numeric-sort','--print-size','--defined-only','--demangle',str(elf)],text=True)
(h/'execution-symbols.txt').write_text(text)
by_address={}
for line in text.splitlines():
    match=re.match(r'^([0-9a-f]+) ([0-9a-f]+) [tT] (.+)$',line)
    if not match: continue
    address,size=int(match[1],16),int(match[2],16)
    if size and (address not in by_address or size>by_address[address][0]): by_address[address]=(size,match[3])
addresses=sorted(by_address)
counts=collections.Counter()
for entry in profile['entries']:
    pc=entry['pc'];i=bisect.bisect_right(addresses,pc)-1
    start=addresses[i] if i>=0 else None
    name=by_address[start][1] if start is not None and pc<start+by_address[start][0] else '<unmapped>'
    counts[name]+=entry['instructions']
assert sum(counts.values())==profile['base_instructions']
result=dict(scope='Guest base instruction counts attributed to containing ELF symbols; not inclusive call costs or host precompile/prover timings',cycles=profile['cycles'],base_instructions=profile['base_instructions'],keccak_calls=profile['keccak_calls'],recovery_calls=profile['recovery_calls'],elf_sha256=profile['elf_sha256'],functions=[dict(name=name,instructions=count,percent_total=100*count/profile['cycles']) for name,count in counts.most_common()])
(h/'execution-function-profile.json').write_text(json.dumps(result,indent=2)+'\n')
for row in result['functions'][:30]:print(f"{row['percent_total']:6.2f}% {row['instructions']:12d} {row['name']}")
