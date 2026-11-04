# rv64-cuda-counters

LD_PRELOAD CUDA driver-API counter shim (stream measure, plan M4.0 item 9). Counts and times the host calls the
10x plan gates on — `cu{Stream,Ctx,Event}Synchronize`, `cuLaunchKernel(Ex)`, `cuMemAllocFromPoolAsync`,
`cuMemPoolTrimTo`, `cuLibraryLoadData`, pageable vs pinned `cuMemcpy*`, pinned host allocations — per request,
per thread and in 10 ms bins. No CUPTI needed.

`libstwo-rv64-native.so` links cudart statically; static cudart resolves every driver entry point through
`cuGetProcAddress`, which it gets with `dlsym`. The shim interposes `dlsym`, wraps `cuGetProcAddress(_v2)` and
swaps in timing wrappers for the counted symbols. Arguments and results pass through untouched, so proofs
cannot change (verified: proofs byte-identical to the M3 baseline with the shim loaded).

Caveat: `dlsym(RTLD_NEXT, …)` called *through* the shim resolves relative to the shim; nothing in the driver
or cudart does that today.

```sh
gcc -O2 -shared -fPIC -I/usr/local/cuda/include -o librv64_cuda_counters.so rv64_cuda_counters.c -ldl -lpthread
nvcc -arch=sm_120 -cudart static -o selftest selftest.cu
RV64_CUDA_COUNTERS_OUT=. LD_PRELOAD=$PWD/librv64_cuda_counters.so ./selftest   # -> cuda-counters-<pid>.json
```

Pod build: `/workspace/m3/build/m4-measure/shim/librv64_cuda_counters.so`; the harness uses it with `--counters`.
