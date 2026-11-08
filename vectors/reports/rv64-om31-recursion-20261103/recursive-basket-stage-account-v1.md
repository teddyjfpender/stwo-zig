# Cold recursive basket stage account

First cold trial of each accepted block. Summed instrumented stages, from three pinned implementation groups under concurrent host load. No quiet median, kernel-only timer, hardware throughput bound or causal speedup is claimed. Setup finalize/columns/authority subdivide setup_total. Plan aggregates four disjoint laps; generate is adapter wall including enqueue and GPU execution. These phases are not a complete recursion wall account. Older producers did not emit separate setup spans; missing observations are null, not zero.

| Block | Nodes | Recursion s | FIXED authority s | PP columns s | Assignment plan s | Assignment generate s | Assignment launches |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 24626900 | 39 | 225.589 | unrecorded | unrecorded | 55.182 | 9.184 | 2312519 |
| 24628590 | 111 | 645.961 | unrecorded | unrecorded | 155.698 | 27.434 | 6556237 |
| 24628595 | 131 | 850.771 | 228.410 | 85.563 | 212.877 | 34.470 | 7415161 |
| 24628607 | 33 | 183.136 | unrecorded | unrecorded | 43.726 | 7.341 | 1931428 |
| 24628608 | 39 | 219.998 | unrecorded | unrecorded | 53.653 | 9.259 | 2209308 |
| 24628611 | 133 | 848.467 | 229.064 | 85.353 | 212.683 | 35.606 | 7708330 |
| 24647140 | 29 | 161.846 | unrecorded | unrecorded | 38.488 | 7.704 | 1776026 |
| 24697070 | 61 | 335.774 | unrecorded | unrecorded | 81.269 | 14.825 | 3353558 |
| 24697073 | 55 | 309.608 | unrecorded | unrecorded | 75.576 | 12.604 | 3042585 |
| 25229951 | 115 | 661.236 | 178.305 | 66.426 | 163.562 | 27.490 | 6376954 |
| 25229955 | 97 | 583.459 | 159.627 | 58.955 | 144.963 | 24.029 | 5272928 |
| 25229957 | 33 | 189.171 | unrecorded | unrecorded | 45.769 | 8.650 | 2002388 |
| 26235156 | 21 | 118.311 | unrecorded | unrecorded | 28.679 | 5.489 | 1290518 |
| 26235159 | 149 | 928.513 | 251.398 | 93.399 | 228.739 | 42.324 | 8310993 |
| 26235168 | 97 | 593.318 | 161.411 | 60.611 | 147.679 | 24.672 | 5343621 |

All observations use the historical CPU FIXED setup; the separate device FIXED candidate does not retroactively alter these timings. Assignment generation already has zero full-assignment upload. Its launch count exposes the remaining one-kernel-per-DAG-level scheduling cost; it does not prove how much a persistent implementation will save.

On block26235168 the first node has 17,980,712 ready tasks over 109,504 levels (164.2 tasks/level on average), and 109,504 launches including seed generation. Average width alone does not establish how many consecutive levels fit in one CTA; broad levels must remain explicit dependency barriers. A bounded persistent narrow-level planner needs a distribution, exact assignment parity and physical qualification.

Across these cold cases, original-DAG assignment generation issued **64,902,554 launches**. For the largest block, CPU FIXED authority construction, PP columns and assignment planning account for 251.398s, 93.399s and 228.739s respectively, versus 42.324s in the assignment-generation adapter. These source observations prioritize setup/planning alongside kernel launch reductions; they are not a projection of attainable savings.
