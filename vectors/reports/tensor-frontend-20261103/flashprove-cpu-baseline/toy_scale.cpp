// Whole toy run (blocks/toy/product.h: prove knowledge of a,b,c in F^(2^L) with a[i]*b[i]=c[i]) at
// a chosen size, prover vs verifier, median of reps. Mirrors blocks/toy/toy_main.h, but with the
// size as an argument and a timing wrapper around EngineCpu to split the prover's time by engine call.
//   toy_scale L work_bits reps
// Sizes follow the pattern of the repo's own toy runs: toy_size(set, L, L+3, L-1, {1,1,L+2,L}, {0,0,L+2,L+2}).
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>

#include "engine/engine_cpu.h"
#include "toy/toy_main.h"

using namespace blk;
using clk = std::chrono::steady_clock;

static std::map<std::string, double> g_t;
struct Timer {
  const char *k;
  clk::time_point t0;
  Timer(const char *k) : k(k), t0(clk::now()) {}
  ~Timer() { g_t[k] += std::chrono::duration<double>(clk::now() - t0).count(); }
};

class EngineTimed : public EngineCpu {
public:
  CommitId commit(const std::vector<OraclePart> &parts, const OracleTreeShape &shape, Coins &coins, Digest &root) override {
    Timer t("commit(encode+merkle)");
    return EngineCpu::commit(parts, shape, coins, root);
  }
  void open(CommitId c, const PositionList &at, Opening &out) override {
    Timer t("open");
    EngineCpu::open(c, at, out);
  }
  FoldId fold_begin(const std::vector<FoldPart> &parts, unsigned k, const Form &c) override {
    Timer t("fold_begin");
    return EngineCpu::fold_begin(parts, k, c);
  }
  void fold_round(FoldId f, E q[3]) override {
    Timer t("fold_round");
    EngineCpu::fold_round(f, q);
  }
  void fold_bind(FoldId f, const E &g) override {
    Timer t("fold_bind");
    EngineCpu::fold_bind(f, g);
  }
  TableId fold_end(FoldId f, Table &tail, TableId *cf) override {
    Timer t("fold_end");
    return EngineCpu::fold_end(f, tail, cf);
  }
  E evaluate(TableId id, const Tensor &v) override {
    Timer t("evaluate");
    return EngineCpu::evaluate(id, v);
  }
  E evaluate(TableId id, const Form &v) override {
    Timer t("evaluate");
    return EngineCpu::evaluate(id, v);
  }
  u64 search_nonce(const ChainPrefix &p, unsigned bits) override {
    Timer t("search_nonce(PoW)");
    return EngineCpu::search_nonce(p, bits);
  }
};

int main(int argc, char **argv) {
  coins_own_test();
  const unsigned L = argc > 1 ? (unsigned)std::atoi(argv[1]) : 12;
  const unsigned work = argc > 2 ? (unsigned)std::atoi(argv[2]) : 0;
  const int reps = argc > 3 ? std::atoi(argv[3]) : 3;
  Setting set = setting_goldilocks();
  set.hash_block_bytes = HASH_BLOCK_BYTES;
  set.set_work(ErrorKind::QUERY, Scope::REQUEST, work);
  // argv[4] == "deep": a longer chain of proximity-test stages (k=4 folds), so that the last stage's
  // message (sent in full) is short; otherwise the repo's own toy pattern.
  const bool deep = argc > 4 && std::string(argv[4]) == "deep";
  std::vector<StageChoice> further = {StageChoice{1, 1, L + 2, L}, StageChoice{0, 0, L + 2, L + 2}};
  if (deep) further = {StageChoice{4, 3, L, L - 4}, StageChoice{4, 3, L - 3, L - 6}, StageChoice{0, 0, L - 5, L - 5}};
  const ToyRun run = toy_size(set, L, L + 3, L - 1, further);
  if (run.plan->refused()) {
    std::printf("refused: %s\n", run.plan->why_not().c_str());
    return 2;
  }
  std::printf("L=%u work_bits=%u\n", L, work);
  for (size_t i = 0; i < run.shape.codes.base.size(); i++) {
    const Code &c = run.shape.codes.base[i];
    std::printf("base code %zu: log_n=%u ell=%zu r(tail = hidden positions)=%zu rate=%.5f\n", i, c.log_n, c.ell, c.r, c.rate());
  }
  for (size_t i = 0; i < run.shape.codes.mask.size(); i++) {
    const Code &c = run.shape.codes.mask[i];
    std::printf("mask code %zu: log_n=%u ell=%zu r=%zu rate=%.5f\n", i, c.log_n, c.ell, c.r, c.rate());
  }
  for (size_t i = 0; i < run.stages.size(); i++)
    std::printf("stage %zu: base code %u mask code %u k=%u h=%u\n", i, run.stages[i].code, run.stages[i].mask_code, run.stages[i].k, run.stages[i].h);

  std::vector<double> tp, tv;
  size_t bytes = 0;
  bool all_ok = true;
  std::map<std::string, double> last_split;
  for (int rep = 0; rep < reps; rep++) {
    ToyCoins made_up((u64)(1000 + rep));
    Table abc(1, 3, run.shape.codes.base[0].ell);
    made_up.fill(abc.a.data(), 2 * abc.len);
    for (size_t i = 0; i < abc.len; i++) abc.set(2, i, abc.at(0, i) * abc.at(1, i));
    const Digest inputs = CoinInputs().add("the public file", run.shape.text).add("the witness", abc.a.data(), abc.a.size()).finish();
    const std::unique_ptr<StreamCoins> own = run_coins_without_a_seed<StreamCoins>(inputs);
    Coins &coins = *own;
    EngineTimed engine;
    Writer proof;
    g_t.clear();
    const auto t0 = clk::now();
    toy_prove(run, abc, engine, coins, proof);
    const auto t1 = clk::now();
    const char *why = nullptr;
    const bool ok = toy_verify_file(run.shape.text, proof.data(), proof.size(), &why);
    const auto t2 = clk::now();
    all_ok = all_ok && ok;
    bytes = proof.size();
    tp.push_back(std::chrono::duration<double>(t1 - t0).count());
    tv.push_back(std::chrono::duration<double>(t2 - t1).count());
    last_split = g_t;
    std::printf("rep %d: prover %.4f s verifier %.4f s bytes %zu verdict %s\n", rep, tp.back(), tv.back(), proof.size(), ok ? "ACCEPT" : why);
  }
  std::sort(tp.begin(), tp.end());
  std::sort(tv.begin(), tv.end());
  std::printf("engine-call split of last rep (s):");
  for (auto &kv : last_split) std::printf(" [%s %.4f]", kv.first.c_str(), kv.second);
  std::printf("\n");
  std::printf("RESULT L=%u n=%llu work=%u prover_median_s=%.4f verifier_median_s=%.4f proof_bytes=%zu ok=%d reps=%d\n", L,
              (unsigned long long)(1ull << L), work, tp[tp.size() / 2], tv[tv.size() / 2], bytes, all_ok ? 1 : 0, reps);
  return all_ok ? 0 : 1;
}
