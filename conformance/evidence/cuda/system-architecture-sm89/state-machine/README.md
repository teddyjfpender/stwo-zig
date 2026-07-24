# Native CUDA State-Machine Evidence

This directory retains the clean SM89 integration evidence for the resident
Native state-machine route at implementation commit
`3f7e58aa3a21adb0aba6cec0069fe90d4bc89ac6`.

The workload is `log_n_rows=14`, `initial_x=9`, and `initial_y=3`. Direct and
CUDA-graph execution produced the same 40,082-byte canonical proof:

```text
488fadeeb4e5d76b6fc0a9c10ab258bab6673de8e912ae5de927561650920b37
```

Both modes passed:

- exact Native CPU/CUDA proof-byte parity;
- independent Zig verification;
- verification by the pinned Rust Stwo oracle;
- authenticated strict-AOT execution;
- zero CPU fallback attempts or completions;
- one terminal device-to-host proof transfer;
- stable repeated-proof topology and bytes;
- bounded persistent allocation with request allocations released.

After excluding the first graph-capture request, graph execution had medians
of 1.456 ms resident proof time, 2.041 ms verified-request time, and 1.429 ms
device time. Direct execution had medians of 1.619 ms, 2.222 ms, and 1.592 ms,
respectively.

This is route correctness and integration evidence. It is not a class-equal
portfolio promotion or a locked-host A/A verdict.
