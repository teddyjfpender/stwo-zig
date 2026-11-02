// Numerical host oracle only: no CUDA API is declared or emulated here.
// Real device compilation includes the toolkit header instead of this file.
#pragma once
#define __host__
#define __device__
#define __forceinline__ inline

#define __constant__
inline int __ffs(int x) { return __builtin_ffs(x); }
