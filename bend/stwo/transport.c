/* Private adapter for Bend 2.0.5 generated runtime; not a stable C ABI.
 * stdin/stdout: little-endian u32. No arithmetic is implemented here.
 * Request: magic BND1, version=1, op, log_size, factor, values[2^log],
 *          then preorder plan[2^log-1] for FFT/IFFT only.
 * Response: magic BNO1, version=1, count, canonical values[count].
 * Exactly one request per process. Timings exclude input/output conversion.
 */
#ifndef REQUIRE_GPU
#define REQUIRE_GPU 0
#endif
static uint64_t bend_started;
static uint32_t bend_output_count;
static void bend_die(const char *msg) { fprintf(stderr, "bend transport: %s\n", msg); exit(2); }
static uint32_t bend_word(void) {
  unsigned char b[4];
  if (fread(b, 1, 4, stdin) != 4) bend_die("truncated request");
  return (uint32_t)b[0] | (uint32_t)b[1]<<8 | (uint32_t)b[2]<<16 | (uint32_t)b[3]<<24;
}
static uint32_t bend_field(void) {
  uint32_t x = bend_word();
  if (x >= 2147483647u) bend_die("noncanonical M31");
  return x;
}
static void bend_put(uint32_t x) {
  unsigned char b[4] = {x, x>>8, x>>16, x>>24};
  if (fwrite(b, 1, 4, stdout) != 4) bend_die("output write failed");
}
static Term bend_plan(Env e, uint32_t depth) {
  uint32_t w = bend_field();
  if (depth == 1) return term_pak(CID_CIRCLE_FFT_TIP, w);
  Term l = bend_plan(e, depth - 1);
  Term r = bend_plan(e, depth - 1);
  Loc p = heap_alloc(e, cls_fit(3));
  e.mem[p] = w; e.mem[p+1] = l; e.mem[p+2] = r;
  return term_ctr(CID_CIRCLE_FFT_FORK, p);
}
Term read_run(Env e, Term *f, IoWork *w) {
  (void)f; (void)w;
  if (REQUIRE_GPU && !io_gpu) bend_die("GPU execution required; no CPU fallback");
  if (bend_word() != 0x31444e42 || bend_word() != 1) bend_die("bad version/magic");
  uint32_t op = bend_word(), depth = bend_word(), factor = bend_field();
  if (op > 4 || depth < 1 || depth > 24) bend_die("unsupported operation/size");
  if (op == 4 && depth < 3) bend_die("FRI requires at least two QM31 values");
  uint32_t n = 1u << depth;
  Loc v = heap_alloc(e, buf_wcls(depth));
  for (uint32_t i=0; i<n; i++) *blk_ptr(e.mem, v, i) = bend_field();
  Term plan = op < 2 ? bend_plan(e, depth) : term_pak(CID_CIRCLE_FFT_TIP, 0);
  uint32_t inv_depth = op == 4 ? depth - 3 : 0;
  Loc inv = heap_alloc(e, buf_wcls(inv_depth));
  for (uint32_t i=0; i<(1u << inv_depth); i++)
    *blk_ptr(e.mem, inv, i) = op == 4 ? bend_field() : 0;
  Loc alpha = heap_alloc(e, buf_wcls(2));
  for (uint32_t i=0; i<4; i++) *blk_ptr(e.mem, alpha, i) = op == 4 ? bend_field() : 0;
  if (fgetc(stdin) != EOF) bend_die("trailing input");
  Loc req = heap_alloc(e, cls_fit(7));
  e.mem[req] = op; e.mem[req+1] = 2*depth; e.mem[req+2] = factor;
  e.mem[req+3] = plan; e.mem[req+4] = term_buf(depth, v);
  e.mem[req+5] = term_buf(inv_depth, inv); e.mem[req+6] = term_buf(2, alpha);
  bend_output_count = (op == 2 || op == 4) ? n/2 : n;
  bend_started = io_tick();
  return term_ctr(CID_REQUEST, req);
}
Term write_run(Env e, Term *f, IoWork *w) {
  (void)w;
  uint64_t elapsed = io_tick() - bend_started;
  Term a = f[0];
  uint32_t n = 1u << blk_cls(a);
  if (term_tag(a) != TAG_BUF || n != bend_output_count) bend_die("bad output shape");
  bend_put(0x314f4e42); bend_put(1); bend_put(n);
  for (uint32_t i=0; i<n; i++) {
    uint32_t x = *blk_ptr(e.mem, term_loc(a), i);
    if (x >= 2147483647u) bend_die("noncanonical result");
    bend_put(x);
  }
  if (fflush(stdout)) bend_die("output flush failed");
  fprintf(stderr, "{\"compute_ns\":%llu,\"lane\":\"%s\"}\n", (unsigned long long)elapsed, io_gpu ? "bend-gpu" : "bend-cpu");
  blk_free(e, a);
  return term_pak(CID_UNIT, 0);
}
static void __attribute__((constructor)) bend_transport_use(void) {
  io_eff(CID_READ, read_run, 0);
  io_eff(CID_WRITE, write_run, 0);
}
