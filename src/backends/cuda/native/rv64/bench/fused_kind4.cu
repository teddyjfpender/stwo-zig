// Route B kernels for component 4 (split TU so the bench builds in parallel).
#include <algorithm>
#include <cstdio>
#define GB_KIND_TU 4
#include "fused_gkr.cuh"
