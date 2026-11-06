// Proxy for a compact recursion witness evaluated on the host in program
// order (no task DAG): N QM31 ops over a variable table, each reading two
// earlier variables at pseudo-random distances and writing one new variable.
// 50% multiplies (Karatsuba-free schoolbook over CM31[i]/(i^2+1), u^2 = 2+i),
// 50% adds. Single thread. Reports ns/op and the compact table size.
// Build: cc -O2 -march=native qm31_straightline_probe.c -o probe
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define P 2147483647u
typedef struct { uint32_t a, b, c, d; } qm31;  // (a + b i) + (c + d i) u
static inline uint32_t add(uint32_t x, uint32_t y) { uint32_t s = x + y; return s >= P ? s - P : s; }
static inline uint32_t sub(uint32_t x, uint32_t y) { return x >= y ? x - y : x + P - y; }
static inline uint32_t mul(uint32_t x, uint32_t y) {
  uint64_t t = (uint64_t)x * y; uint32_t r = (uint32_t)(t & P) + (uint32_t)(t >> 31); return r >= P ? r - P : r; }
static inline void cmul(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t* re, uint32_t* im) {
  *re = sub(mul(a, c), mul(b, d)); *im = add(mul(a, d), mul(b, c)); }
static inline qm31 qadd(qm31 x, qm31 y) { return (qm31){add(x.a,y.a), add(x.b,y.b), add(x.c,y.c), add(x.d,y.d)}; }
static inline qm31 qmul(qm31 x, qm31 y) {
  uint32_t r0, i0, r1, i1, r2, i2, r3, i3;
  cmul(x.a, x.b, y.a, y.b, &r0, &i0);            // x0 y0
  cmul(x.c, x.d, y.c, y.d, &r1, &i1);            // x1 y1
  cmul(x.a, x.b, y.c, y.d, &r2, &i2);            // x0 y1
  cmul(x.c, x.d, y.a, y.b, &r3, &i3);            // x1 y0
  // u^2 = 2 + i: x1 y1 (2 + i) = (2 r1 - i1) + (r1 + 2 i1) i
  uint32_t er = sub(add(r1, r1), i1), ei = add(r1, add(i1, i1));
  return (qm31){add(r0, er), add(i0, ei), add(r2, r3), add(i2, i3)};
}
int main(int argc, char** argv) {
  const uint32_t n = argc > 1 ? (uint32_t)atoi(argv[1]) : 2000000u;
  const uint32_t seeds = 4096;
  qm31* v = malloc(sizeof(qm31) * (size_t)(n + seeds));
  uint32_t* op = malloc(sizeof(uint32_t) * 3 * (size_t)n);
  uint64_t x = 0x9e3779b97f4a7c15ull;
  for (uint32_t i = 0; i < seeds; ++i) v[i] = (qm31){i % P, (i * 7) % P, (i * 13) % P, (i * 31) % P};
  for (uint32_t i = 0; i < n; ++i) {  // program: kind, lhs, rhs (earlier vars)
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    const uint32_t at = seeds + i;
    op[3 * i] = (uint32_t)(x & 1);
    op[3 * i + 1] = at - 1 - (uint32_t)((x >> 8) % (at < 65536 ? at : 65536));
    op[3 * i + 2] = at - 1 - (uint32_t)((x >> 32) % at);
  }
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  for (uint32_t i = 0; i < n; ++i) {
    const qm31 l = v[op[3 * i + 1]], r = v[op[3 * i + 2]];
    v[seeds + i] = op[3 * i] ? qmul(l, r) : qadd(l, r);
  }
  clock_gettime(CLOCK_MONOTONIC, &t1);
  const double s = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
  uint32_t check = 0; for (uint32_t i = 0; i < n + seeds; i += 997) check ^= v[i].a ^ v[i].d;
  printf("QM31_STRAIGHTLINE {\"ops\":%u,\"seconds\":%.6f,\"ns_per_op\":%.2f,\"table_bytes\":%zu,\"check\":%u}\n",
         n, s, 1e9 * s / n, sizeof(qm31) * (size_t)(n + seeds), check);
  return 0;
}
