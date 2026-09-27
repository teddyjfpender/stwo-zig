# Canonical CPU Keccak host sampling

A six-sample canonical Keccak-128 run used the frozen streaming-LDE-arena CPU candidate with 16 workers, 70 queries / 26 PoW bits. macOS sample attached for 12 seconds at 1 ms intervals. The proof verified in process and matched the preceding suite proof hash. Timing values from this instrumented run are diagnostic, not benchmark results.

The sample shows 1,170 inclusive stack hits in the two dominant prepareMain → writeColumnsAt branches, within a 1,407-hit witness-execution subtree. These are sampled stack counts, not exact wall-time proportions. The small-chunk writer scatters one entire logical row across all destination columns and has both memory-copy and scatter costs. This justifies testing a bounded column-major transpose in the shared writer before redesigning frame emission.

Aggregate thread samples also show substantial generic BLAKE3 compression/update, G composition, G interaction, and transform work. They include worker concurrency and waits; their totals cannot be interpreted as an end-to-end breakdown. The raw profile is retained in sample.txt, with exact process report and command metadata.
