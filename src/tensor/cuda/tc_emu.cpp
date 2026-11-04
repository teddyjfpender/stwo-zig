// CPU emulation build of the tensor CUDA backend: the unmodified host layer
// and kernels of tc_host.cu, compiled as C++ without nvcc (tc_prelude.cuh
// turns launches into block loops and thread phases into tid loops).
#include "tc_host.cu"
