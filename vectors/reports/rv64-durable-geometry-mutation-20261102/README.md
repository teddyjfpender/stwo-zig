# Actual durable receiver rejects admissible geometry mutation

This receipt runs the existing native control CLI in fresh processes against accepted durable files, then changes exactly one declaration field while preserving every physical proof, stage-one file and public cell file byte-for-byte. Bin files are hardlinked into private temporary directories; `bundle.json` is written separately so the original is never modified. Original and mutant file hashes and the exact executable SHA are recorded. No new verifier or mock constructor participates.

| Accepted workload | Single admissible mutation | Exact fresh rejection |
|---|---|---|
| One-CPU prefix, no truths | ALU log 19 → 20; CPU remains log 22 with 4,194,303 steps | `LocalGkrReceiptShape` |
| Complete 25-CPU, 5-truth block | First Keccak truth log 18 → 19, same 18,078 calls and first ID | `WideCpuPublicRamMismatch` |

Both unchanged controls freshly accept. The complete control is independently required to report a completed Ethereum block; the prefix is required to report prefix acceptance only. The CPU mutant reaches the child wire topology check, which compares saved layer-mask counts with the independently reconstructed instance dimension. This happens after ordinary declaration/request validation and setup construction. It is not an invalid-log rejection.

The K mutant is also admissible: services wire policy permits log ≤21; 262,131 active paired rows fit 524,288 rows, and 347,097,600 CHI events are below characteristic 2,147,483,647. Independent setup reconstruction changes the K fixed scope in the joined manifest. The newly derived shared RAM challenges change the verifier's public INIT/TEARDOWN claim recomputation, which rejects the unchanged CPU claim before accepting any reinterpretation of the old proofs. The test does not weaken the source policy to admit this case.

The source-authority snapshot identifies the exact validation/check sequence and is hashed in the receipt. It is not presented as the compiled executable's build commit: the gate pins and actually executes the existing supplied binary. This closes these two concrete geometry-rekey negative cases, not an exhaustive theorem over every possible producer declaration. Security qualification and whole-protocol 128-bit certification remain false.

Reproduce with `lockf -k /private/tmp/stwo-rv64-perf-heavy.lock python3 reproduce.py CLI CONFIG ACCEPTED_PREFIX ACCEPTED_COMPLETE NEW_TEMP_OUTPUT`. The script refuses an existing output directory, checks the expected exact errors, and verifies all original/linked bin hashes after rejection. No proof files or receiver executable are duplicated into this repository receipt.
