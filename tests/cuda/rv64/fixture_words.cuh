#ifndef STWO_RV64_FIXTURE_WORDS_CUH
#define STWO_RV64_FIXTURE_WORDS_CUH
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
// Cold little-endian native-oracle files only. Never a proof wire decoder.
struct FixtureWords {
  std::vector<uint32_t> data;
  size_t position = 0;
  explicit FixtureWords(const std::string &path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
      throw std::runtime_error("fixture missing");
    const auto end = f.tellg();
    if (end < 0 || uint64_t(end) % 4)
      throw std::runtime_error("fixture alignment");
    std::vector<unsigned char> bytes(size_t(end), 0);
    f.seekg(0);
    f.read(reinterpret_cast<char *>(bytes.data()), bytes.size());
    if (!f)
      throw std::runtime_error("fixture truncated");
    data.resize(bytes.size() / 4);
    for (size_t i = 0; i < data.size(); ++i)
      data[i] = uint32_t(bytes[i * 4]) | (uint32_t(bytes[i * 4 + 1]) << 8) |
                (uint32_t(bytes[i * 4 + 2]) << 16) |
                (uint32_t(bytes[i * 4 + 3]) << 24);
  }
  std::vector<uint32_t> take(size_t count) {
    if (count > data.size() - position)
      throw std::runtime_error("fixture bounds");
    std::vector<uint32_t> out(data.begin() + position,
                              data.begin() + position + count);
    position += count;
    return out;
  }
};
inline void fixture_equal(const char *label,
                          const std::vector<uint32_t> &actual,
                          const std::vector<uint32_t> &expected) {
  if (actual == expected)
    return;
  for (size_t i = 0; i < std::min(actual.size(), expected.size()); ++i)
    if (actual[i] != expected[i]) {
      std::fprintf(stderr, "%s index=%zu got=%u expected=%u\n", label, i,
                   actual[i], expected[i]);
      break;
    }
  throw std::runtime_error(label);
}
#endif
