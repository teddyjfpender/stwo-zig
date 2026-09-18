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
static int bend_persistent;
static uint32_t bend_output_count;
static void bend_die(const char *msg) { fprintf(stderr, "bend transport: %s\n", msg); exit(2); }
/* read(2) may return a partial pipe block; fread of a full block could deadlock
 * a persistent caller waiting for the current response before sending more. */
static unsigned char bend_input[65536];
static size_t bend_input_pos, bend_input_len;
static int bend_byte(void) {
  if (bend_input_pos == bend_input_len) {
    ssize_t n;
    do { n = read(fileno(stdin), bend_input, sizeof(bend_input)); } while (n < 0 && errno == EINTR);
    if (n < 0) bend_die("input read failed");
    if (n == 0) return EOF;
    bend_input_len = (size_t)n; bend_input_pos = 0;
  }
  return bend_input[bend_input_pos++];
}
static uint32_t bend_word(void) {
  /* Most words are wholly inside the buffered block. Keep one bounds check,
   * preserving the byte slow path for short reads and boundary crossings. */
  if (bend_input_len - bend_input_pos >= 4) {
    const unsigned char *b = bend_input + bend_input_pos;
    bend_input_pos += 4;
    return (uint32_t)b[0] | (uint32_t)b[1]<<8 | (uint32_t)b[2]<<16 | (uint32_t)b[3]<<24;
  }
  unsigned char b[4];
  for (unsigned i=0; i<4; i++) {
    int c = bend_byte();
    if (c == EOF) bend_die("truncated request");
    b[i] = (unsigned char)c;
  }
  return (uint32_t)b[0] | (uint32_t)b[1]<<8 | (uint32_t)b[2]<<16 | (uint32_t)b[3]<<24;
}
static uint32_t bend_field(void) {
  uint32_t x = bend_word();
  if (x >= 2147483647u) bend_die("noncanonical M31");
  return x;
}
static unsigned char bend_output[65536];
static size_t bend_output_len;
static void bend_flush(void) {
  if (fwrite(bend_output, 1, bend_output_len, stdout) != bend_output_len) bend_die("output write failed");
  bend_output_len = 0;
}
static void bend_put(uint32_t x) {
  if (bend_output_len == sizeof(bend_output)) bend_flush();
  unsigned char *b = bend_output + bend_output_len;
  b[0] = x; b[1] = x>>8; b[2] = x>>16; b[3] = x>>24;
  bend_output_len += 4;
}
/* Session-local canonical twiddle template. No field arithmetic lives here. */
static uint32_t *bend_plan_cache;
static uint32_t bend_plan_count, bend_plan_pos;
static uint32_t bend_plan_field(void) {
  if (bend_plan_pos >= bend_plan_count) bend_die("plan template exhausted");
  return bend_plan_cache[bend_plan_pos++];
}
/* Rearrange preorder twiddle words only; field arithmetic stays in Bend. */
static void bend_plan_words(Env e, Loc p, uint32_t depth, uint32_t index) {
  *blk_ptr(e.mem, p, index) = bend_plan_field();
  if (depth > 1) {
    bend_plan_words(e, p, depth-1, 2*index);
    bend_plan_words(e, p, depth-1, 2*index+1);
  }
}
static Term bend_plan(Env e, uint32_t depth) {
  if (depth <= 8) {
    Loc words = heap_alloc(e, buf_wcls(depth));
    *blk_ptr(e.mem, words, 0) = 0;
    bend_plan_words(e, words, depth, 1);
    Loc p = heap_alloc(e, cls_fit(2));
    e.mem[p] = depth; e.mem[p+1] = term_buf(depth, words);
    return term_ctr(CID_CIRCLE_FFT_BLOCK, p);
  }
  uint32_t w = bend_plan_field();
  Term l = bend_plan(e, depth - 1), r = bend_plan(e, depth - 1);
  Loc p = heap_alloc(e, cls_fit(3));
  e.mem[p] = w; e.mem[p+1] = l; e.mem[p+2] = r;
  return term_ctr(CID_CIRCLE_FFT_FORK, p);
}
static Term bend_empty_plan(Env e) {
  Loc words = heap_alloc(e, buf_wcls(0)); *blk_ptr(e.mem, words, 0) = 0;
  Loc p = heap_alloc(e, cls_fit(2)); e.mem[p] = 0; e.mem[p+1] = term_buf(0, words);
  return term_ctr(CID_CIRCLE_FFT_BLOCK, p);
}
Term read_run(Env e, Term *f, IoWork *w) {
  (void)f; (void)w;
  if (REQUIRE_GPU && !io_gpu) bend_die("GPU execution required; no CPU fallback");
  if (bend_persistent) {
    int first = bend_byte();
    if (first == EOF) exit(0);
    bend_input_pos--;
  }
  uint32_t magic = bend_word();
  if ((bend_persistent ? (magic != 0x32444e42u && magic != 0x33444e42u) : magic != 0x31444e42u) || bend_word() != 1) bend_die("bad version/magic");
  uint32_t op = bend_word(), depth = bend_word(), factor = bend_field();
  int reuse_plan = (op & 0x80000000u) != 0;
  op &= 0x7fffffffu;
  if (reuse_plan && (magic != 0x33444e42u || !(op < 2 || op == 5))) bend_die("invalid plan reuse");
  if (op > 5 || depth < 1 || depth > 24) bend_die("unsupported operation/size");
  if (op == 4 && depth < 3) bend_die("FRI requires at least two QM31 values");
  uint32_t n = 1u << depth;
  Loc v = heap_alloc(e, buf_wcls(depth));
  for (uint32_t i=0; i<n; i++) *blk_ptr(e.mem, v, i) = bend_field();
  int has_plan = op < 2 || op == 5;
  if (has_plan) {
    if (reuse_plan) {
      if (!bend_plan_cache || bend_plan_count != n-1) bend_die("missing plan template");
    } else {
      uint32_t *next = realloc(bend_plan_cache, (size_t)(n-1) * sizeof(uint32_t));
      if (!next) bend_die("plan template allocation failed");
      bend_plan_cache = next; bend_plan_count = n-1;
      for (uint32_t i=0; i<n-1; i++) bend_plan_cache[i] = bend_field();
    }
    bend_plan_pos = 0;
  }
  Term plan = has_plan ? bend_plan(e, depth) : bend_empty_plan(e);
  uint32_t inv_depth = op == 4 ? depth - 3 : 0;
  Loc inv = heap_alloc(e, buf_wcls(inv_depth));
  for (uint32_t i=0; i<(1u << inv_depth); i++)
    *blk_ptr(e.mem, inv, i) = op == 4 ? bend_field() : 0;
  Loc alpha = heap_alloc(e, buf_wcls(2));
  for (uint32_t i=0; i<4; i++) *blk_ptr(e.mem, alpha, i) = op == 4 ? bend_field() : 0;
  if (!bend_persistent && bend_byte() != EOF) bend_die("trailing input");
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
  bend_flush();
  if (fflush(stdout)) bend_die("output flush failed");
  fprintf(stderr, "{\"compute_ns\":%llu,\"lane\":\"%s\"}\n", (unsigned long long)elapsed, io_gpu ? "bend-gpu" : "bend-cpu");
  blk_free(e, a);
  return term_pak(CID_UNIT, 0);
}
Term iterations_run(Env e, Term *f, IoWork *w) {
  (void)e; (void)f; (void)w;
  const char *mode = getenv("STWO_BEND_PERSISTENT");
  bend_persistent = mode && strcmp(mode, "1") == 0;
  return bend_persistent ? 65536 : 1;
}
static void __attribute__((constructor)) bend_transport_use(void) {
  io_eff(CID_ITERATIONS, iterations_run, 0);
  io_eff(CID_READ, read_run, 0);
  io_eff(CID_WRITE, write_run, 0);
}
