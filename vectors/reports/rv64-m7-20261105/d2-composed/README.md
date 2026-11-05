The final composed driver proves D2 on both development blocks with fresh CPU acceptance. Truth coalescing actually reduces the headline native roster from 17 to 14; its recursive tree drops from 23 to 19 nodes and depth 3 to 2. Ten producer requests across five cold/warm sessions pass, with five fresh CPU receivers. The M6 controls preserve every accepted M6 artifact byte. The same current receiver also accepts both original M6 proofs in separate supplemental CPU processes.

| Measured warm kernel GPU-seconds (sum of per-device interval unions) | M6 | D2, original roster | D2 + coalescing |
|---|---:|---:|---:|
|26235156,11 native leaves|9.521793535|8.157546092|same11-leaf configuration|
|24628607|14.053093047|11.921032845,17 leaves|10.584695335,14 leaves|

The small 11-leaf result isolates D2: 14.33% less kernel work. Headline D2 alone uses 15.17% less; adding coalescing saves another 11.21%, for 24.68% less than M6. These are measured observations from one matched cold/warm pair per configuration, not confidence intervals or latency guarantees. Copies included: small 10.855099352→9.229006624 GPU-s; headline 16.078346509→13.556959323→11.984213030 GPU-s. All request windows have node-level graph tracing, zero graph-envelope records, complete kernel accounting, and artifact equality to the freshly accepted cold reference. Cold kernel work closely agrees; raw rows are preserved.

D2 increases native-side work while reducing recursion. Using the same recorded native-stage boundary plus the Root analyzer's 5ms uncertainty band:

| Warm boundary partition, kernel GPU-s | M6 | D2 | D2 + coalescing |
|---|---:|---:|---:|
|Small pre-boundary remainder|2.774812656|3.157370760|same|
|Small after native|6.746980879|5.000175332|same|
|Headline pre-boundary remainder|3.992033795|4.531548357|4.380567847|
|Headline after native|10.061059252|7.389484488|6.204127488|

The remainder includes capture/setup/native and the boundary band; it is not an isolated LDE measurement. Native commitment LDE geometry doubles from blowup 2 to 4. Native verification overlaps recursion, so reported stage durations must not be added. No same-request early GPU recursion was admitted.

Diagnostic warm request walls are small 11.884→10.534s and headline 17.137→14.749→12.935s. Profiler overhead and host-load qualification prevent latency claims (D2-only load1 rises 6.22→29.38). Headline tail after the last leaf is 2.735760088→2.415726625→1.717496071s. Coalescing eliminates one fold and one fold depth. Root proof size increases 708696→749688B with coalescing; D2 alone has 705144B. Small root 750136→749464B. The 28GB/device target FAILS: sampled whole-device peaks span 31.58–31.64GB, including driver usage; these are 200ms samples, not exact process peaks. The final accepted preset uses automatic arena after explicit 22GiB failures; no memory pass is claimed.

Both comparisons use frozen driver 9cf6589f1b479f4c6b1049cc98860c55bfbb2fa680e4716ffd976748f782a2f6 and image a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45. The exact 13-flag preset is preserved, including compact ingressON, assignment graphON, owner controllerON, phase trimON, rolling beta2ON, role workspaceOFF, automatic arena, empty setup cache. Root source checkpoint 9531c5c16 plus frozen formatting is bound by six source hashes in provenance. Original M6 CPU receiver 0434da78 remains identified in its untouched receipts; D2/coalesced receiver ddcbcf4b is built from the same frozen source and also separately accepts the original M6 pair. No verification-performance comparison is made.

The named D2 profile is blowup 4/query 54/P20/fold 4 with raw Blake transcripts. Defaults remain unchanged; no Poseidon-suite inference or whole-protocol 128-bit certificate follows. Coalescing merges only supported add/double truth families, preserving bounded Keccak shards. Full one-proof-per-family and CPU 23/24 authority remain unqualified.

`combined-d2-package/summary.json` contains exact rows, tree counts, memory and provenance. Each session preserves receipts, plans, GPU accounting, after-native attribution, cold/warm metadata and every artifact fingerprint; cold complete root proofs are included locally. Full native and recursive proof pairs and raw Nsight reports remain at the pod paths in those receipts. Supplemental acceptance preserves the original M6 plan/receipt hashes. Author: OpenAI Codex.
