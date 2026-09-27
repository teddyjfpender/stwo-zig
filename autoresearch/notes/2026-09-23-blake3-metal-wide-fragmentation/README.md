# Metal fragmented wide quotient source planning

Observed: canonical BLAKE3 Metal/SMP parent reached FRI under its 36 GiB worker
cap (27,708,198,754-byte peak) but failed quotient batch-index planning. The
checked-allocator qualification had passed earlier. This run is not qualified.

The planner selected a single flat GPU buffer when there were more than 64 source
runs, even when total words exceeded the u32 descriptor address space. Localizing
u64 source views then necessarily failed for out-of-range offsets. The segmented
path already rebases each bounded source run. It is now mandatory above 2^32
words, regardless of the fragmentation heuristic. A device-free regression covers
the exact address boundary and both sides of the 64-run heuristic.

Implemented; pending focused test and full Metal/SMP rerun:
- /tmp/blake3-metal-fragmented-wide-quotient.log
- /tmp/blake3-ethereum-metal-parent-smp-compact-v2.log

This is a compatibility fix, not expanded Ethereum block proving. No speedup claim.


## Qualified canonical Metal retry

The SMP compact-parent retry passed: 8/8 tests, q70/26, CPU independent
verification, parent artifact 907,988 bytes, prepared storage 5,953,718,776 bytes,
worker peak 27,708,198,754 bytes, 191 parent Metal dispatches and two CPU fallbacks.
The leaf also verified on CPU (162 dispatches, three fallbacks). Parent witness
and worker storage were released before verification. This qualifies the wide
fragmented source planner repair in the actual recursion path. The five-minute
ReleaseSafe test runtime is not a production latency benchmark.
Log: canonical-metal-parent-pass.log.
