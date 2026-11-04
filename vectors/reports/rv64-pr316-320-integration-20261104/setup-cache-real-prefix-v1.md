# PR320 integrated real-prefix cache qualification

Source `d1c408c8a`, real block 24,628,607 prefix 1, unchanged pinned guest/input,
`conjectured128_b2_q108_p20_fold4`, native ARM CPU CLI, 8 workers.

| Producer cache | Wall (s) | Post-capture setup (s) | Prove (s) | Fresh cache-OFF receiver (s) |
|---|---:|---:|---:|---:|
| off | 41.286 | 2.122 | 36.927 | 3.210 |
| cold | 40.682 | 1.653 | 37.485 | 3.207 |
| warm | 39.835 | 0.193 | 38.035 | 3.230 |

All three sets match byte-for-byte across the same 10 native binary/bundle
artifacts. Every fresh receiver independently accepted with the cache disabled
and CUDA access disabled. Warm loading recorded 7 disk hits and no misses.
A physical receiver invocation with the cache enabled rejected immediately with
`PersistedSetupCacheForbiddenForReceiver`.

These are single observations, not medians or a GPU speedup measurement. The
prefix does not establish full-block completion or recursion. Resident GPU
sessions retain their independently derived bounded setup cache and bypass disk
artifacts. Persisted artifacts remain operator-trusted producer acceleration;
their hashes do not establish malicious-producer authority.

The process-group RSS watchdog was 24 GiB; all cases stayed below it. The JSON
receipt contains exact source/binary/input/request/resource/artifact hashes,
cache counters, resource peaks and raw local evidence paths.
