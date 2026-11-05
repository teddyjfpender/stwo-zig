Full D2 (blowup4,54queries,P20,fold4) proves both development Ethereum blocks and complete recursive roots. Four producer requests and two fresh CPU receivers pass. The matched M6 control uses the same frozen driver/image; all four control proof sets are byte-identical to the accepted M6 baseline. Full native+recursive before/after pairs remain at paths in d2-e2e-comparison.json; local root proof pairs and complete artifact fingerprints are included.

| Diagnostic warm request (host load gate failed) | M6 | D2 |
|---|---:|---:|
| Small request |13.441s|11.474s|
| Headline request |18.842s|14.925s|
| Small native proving |3.108s|3.942s|
| Headline native proving |4.577s|4.670s|
| Small recursion |8.297s|5.611s|
| Headline recursion |11.657s|7.811s|

The raw warm differences are14.6%/20.8%, but host-load qualification FAILED: control load1=6.04→9.81, candidate10.33→23.88, against the protocol threshold8. These are diagnostic observations, not qualified speed improvements. Cold requests26.344→27.333s /35.972→35.048s. Physical GPU peak27.812GB/device, sampled200ms. Native LDE size doubles by source-derived profile geometry; small native proving increases26.8%. Exact GPU-seconds pending. Native verification overlaps recursion; do not add its duration again. Root proof sizes barely change (750136→749464 and708696→705144bytes). Defaults remain M6; no whole-protocol128bit certificate or M7-completion claim.

Driver780056b3bb0fdd8f13264cd6c7928866dc3c1f1f68d1576cee05908093ad232c; image d1d1642a4d599fb6dde042a53cfd6efab95888a35decf1298b86d5a4c4e2cf40; receiver73aed464a20917eb6275321770bee6ddf0889ae2872dbfc1417f896530b1ba8b. 22GiB arena, compact ingressOFF, experimental beta2rollingON, standard truth partition. Source gates: ae3421b98(runtimeD2),2ab7caa85(rollingPCS),e5b19c33e(per-proofRCbeta),d8ded0858(router). Native/recursion use raw Blake; this evidence must not be transferred to Poseidon suites.
