from pathlib import Path
import json,hashlib,os,tarfile
H=Path(__file__).resolve().parent;O=H/'optimization';R=H.parents[2]
d=json.loads((O/'results.json').read_text());n=json.loads((O/'native-results.json').read_text())
lines=['# Retained short-message BLAKE3 optimization','','Production change: `Blake3Hasher.hash` handles messages up to one chunk (1024 bytes) without constructing streaming state or a CV stack. It uses the existing canonical compression implementation, with compile-time lane indices. Larger messages and streaming hashing keep the standard implementation. Hash framing, domains, digest bytes, and security parameters are unchanged.','','## Matched commitment + 70 openings + verification','','Same contract as the parent README. Frozen old local, new local, and peer binaries are alternated in one battery-powered session, one CPU worker each. Seven medians after warm-up, in milliseconds.','','| Rows | Bytes/row | Before | After | Peer | Peer / after |','|---:|---:|---:|---:|---:|---:|']
for c in d['cases']:
 v=c['median_ms'];b,a,p=[v[k]['total_ns'] for k in ('before','local','peer')]
 lines.append(f"| {c['rows']:,} | {c['row_words']*8} | {b:.3f} | {a:.3f} | {p:.3f} | {p/a:.2f}× |")
lines+=['','New local commitment/opening and verification medians individually beat the peer in all five fixtures. All nodes and paths match; cross-verification succeeds; mutated roots and paths fail. This establishes superiority on these measured CPU fixtures, not across architectures or full provers.','','## Native framed production commitment','','Same native LDE/commit pipeline and inputs before/after; identical roots, one worker. These timings are not compared to ZisK’s different native protocol. Commit medians in milliseconds:','','| Input rows | Columns | Before commit | After commit |','|---:|---:|---:|---:|']
for c in n['cases']:
 v=c['median_ms'];lines.append(f"| {c['input_rows']:,} | {c['width']} | {v['before']['commit_ns']:.3f} | {v['after']['commit_ns']:.3f} |")
lines+=['','Narrow native commitments improve approximately 3–4%; the wide case is effectively unchanged (about 1% slower commitment, approximately unchanged pipeline total in this run). Native leaf hashing still uses streaming and native parent frames require two compression blocks. Do not transfer the matched-protocol speedup wholesale to native proof estimates.','','## Qualification','','- 65 ReleaseSafe tests passed. Differential check against standard BLAKE3 at every length 0 through 4097, including empty input, full blocks, full chunks and multi-chunk fallback.','- `test-blake3-proof`, `test-blake3-challenge-proof`, `test-blake3-routed-proof`, and `bench-keccakf-blake3-system` passed with the serialized build wrapper. The last uses 70 queries, 26 PoW bits and 16 workers. Its single timing is qualification only, not an end-to-end speedup claim.','- Matched harness checks every tree node, 70 paths, roots, cross-verification and corruption rejection on all five fixtures. Native benchmark checks unchanged roots.','','## Reproduction','','From the repository root:','','```sh','python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/build.py optimization/after.dylib','python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/run_optimization.py','python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/build_native.py','python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/run_native.py','```','','Raw samples, binary identities, power metadata, qualification logs, and frozen source archive accompany this report. Baseline comparison needs the retained baseline binaries. No full CSP suite or recursion timing was rerun for this bounded change.','']
(O/'README.md').write_text('\n'.join(lines))
with tarfile.open(O/'local-source.tar.gz','w:gz') as tar:
 for root,dirs,files in os.walk(R/'src'):
  dirs[:]=[x for x in dirs if x not in ('.zig-cache','zig-out','target','.git','node_modules')]
  for name in files:
   if name.endswith(('.zig','.zon')):
    p=Path(root)/name;tar.add(p,arcname=str(p.relative_to(R)))
 tar.add(R/'scripts/zig_serial_build.py',arcname='scripts/zig_serial_build.py')
(O/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(O.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
p=H/'README.md';s=p.read_text();link='Latest retained optimization: [short-message BLAKE3 results](optimization/README.md). The tables below preserve the original baseline.\n\n'
if link not in s:s=s.replace('\n\n','\n\n'+link,1);p.write_text(s)
(H/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(H.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
