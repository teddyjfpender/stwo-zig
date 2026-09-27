# Native preparation scratch separation: rejected memory experiment

Split the native row assembler's temporary inventory/lowering/fusion allocations
from its returned final-row arena. Builder continued writing final rows directly,
without a new final copy. Full native ReleaseSafe qualification passed 3/3 tests
(42 s / 2 GiB), including the owned handoff and independent proof verification.

The measurement falsified the expected benefit: retained preparation allocation
stayed 461,491,951 bytes. Preparation peak increased from 1,242,103,479 to
1,263,565,696 bytes (+21,462,217). Worker peak remained 1,567,077,617 bytes;
key and 116,382-byte artifact remained unchanged. No speed result was measured.

The candidate was reverted byte-for-byte to the qualified native row assembler.
The earlier padded-row copy removal remains implemented. This experiment did not
improve the requested result and is not retained as architectural cleanup.

Next measure final logical row bytes, ArrayList capacities and arena capacity
separately, then pre-size final output buffers or stream into their final layout.
The current result is consistent with final-buffer growth/arena granularity
outweighing scratch separation; it does not yet attribute that allocation precisely.
Candidate and terminal qualification log are retained for reproducibility.
