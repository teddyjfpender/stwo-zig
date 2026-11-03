// Debug file wrapper over the same pipeline as the in-process native service.
#include "context_owner.cuh"
#include "fixture_words.cuh"
#include "rv64/pcs_pipeline.cuh"
namespace rv64_pcs_pipeline {
inline Input parse(FixtureWords &file) {
  Input input;
  auto take = [&](size_t n) {
    if (n > file.data.size() - file.position)
      throw std::runtime_error("fixture bounds");
    Words v{file.data.data() + file.position, n};
    file.position += n;
    return v;
  };
  input.sections[0] = take(24);
  const auto h = input.sections[0];
  if (h[4] > 28 || h[8] > 65536 || h[9] > 65536 || h[10] > 1024 || h[11] > 96 ||
      h[12] > 4 || h[14] > 28)
    throw std::runtime_error("fixture bounds");
  const size_t sizes[] = {9,
                          h[21] ? 16u : 0u,
                          size_t(h[8]) * 4,
                          size_t(h[9]) * 4,
                          size_t(h[10]) * 8,
                          size_t(h[11]) * 8,
                          size_t(h[12]) * 6,
                          size_t(h[10]) * 4,
                          size_t(h[10]) * 2,
                          h[13],
                          h[8]};
  for (size_t i = 0; i < 11; ++i)
    input.sections[i + 1] = take(sizes[i]);
  const auto warehouse = take(h[15]);
  for (uint32_t c = 0; c < h[8]; ++c) {
    const auto src = input.sections[3];
    const uint64_t offset =
        uint64_t(src[4 * c]) | (uint64_t(src[4 * c + 1]) << 32);
    const uint32_t log = src[4 * c + 3];
    if (log > 28 || offset > warehouse.size() ||
        (uint64_t(1) << log) > warehouse.size() - offset)
      throw std::runtime_error("source bounds");
    input.coefficients.push_back(
        {{warehouse.data() + offset, size_t(1) << log}, 0, 0, 0});
  }
  input.sections[12] = take(h[19]);
  input.sections[13] = take(size_t(h[14]) * 8);
  input.sections[14] = take(h[20]);
  input.domain = take(size_t(2) << h[4]);
  input.sections[15] = take(size_t(h[12]) * 8);
  (void)take(17);
  if (file.position != file.data.size())
    throw std::runtime_error("fixture trailing words");
  return input;
}

} // namespace rv64_pcs_pipeline
#include <fstream>
struct FileOwner : Owner {
  explicit FileOwner(int device) : Owner(device) {}
  void uploadBorrowed(StwoRv64Plane p, const uint32_t *data, size_t words) {
    if (words)
      CHECK(stwo_exec_context_memcpy_h2d_async(ctx, p.words, data, words * 4));
  }
  uint32_t validateCoefficient(rv64_pcs_pipeline::Coefficient source,const uint32_t *) const {
    if(source.kind)throw std::runtime_error("device coefficients require a native session");
    if(source.size()&&!source.data())throw std::runtime_error("missing host coefficients");
    return 0;
  }
  void uploadCoefficient(StwoRv64Plane destination,
                         rv64_pcs_pipeline::Coefficient source,
                         const uint32_t *) {
    if (source.kind)
      throw std::runtime_error("device coefficients require a native session");
    uploadBorrowed(destination, source.data(), source.size());
  }
  StwoRv64Plane domain(uint32_t, rv64_pcs_pipeline::Words data,
                       rv64_pcs_pipeline::Words) {
    auto p = plane(data.size(), 1);
    uploadBorrowed(p, data.data(), data.size());
    return p;
  }
};
int main(int argc, char **argv) {
  try {
    if (argc != 3)
      throw std::runtime_error("expected PCS fixture and readback paths");
    FixtureWords file(argv[1]);
    auto input = rv64_pcs_pipeline::parse(file);
    FileOwner owner(0);
    const auto result = rv64_pcs_pipeline::run(owner, input);
    owner.close();
    std::ofstream out(argv[2], std::ios::binary);
    out.write(reinterpret_cast<const char *>(result.words.data()),
              result.words.size() * 4);
    if (!out)
      throw std::runtime_error("PCS capture write");
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "FAIL %s\n", e.what());
    return 1;
  }
}
