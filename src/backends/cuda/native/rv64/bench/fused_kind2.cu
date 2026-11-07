// Route B kernels for component 2 (split TU so the bench builds in parallel).
#include <algorithm>
#include <cstdio>
#define GB_KIND_TU 2
#include "fused_gkr.cuh"
