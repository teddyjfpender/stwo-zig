#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace rv64_fixture {
struct Fixture {
  std::vector<uint32_t> data;
  size_t cursor = 0;
  explicit Fixture(const std::string &file) {
    std::ifstream f(file, std::ios::binary | std::ios::ate);
    if (!f)
      throw std::runtime_error("missing fixture: " + file);
    const auto bytes = f.tellg();
    if (bytes < 32 || uint64_t(bytes) % 4 || bytes > uint64_t(1) << 31)
      throw std::runtime_error("bad fixture size");
    data.resize(size_t(bytes) / 4);
    f.seekg(0);
    f.read(reinterpret_cast<char *>(data.data()), bytes);
  }
  std::vector<uint32_t> take(size_t n) {
    if (n > data.size() - cursor)
      throw std::runtime_error("truncated fixture");
    std::vector<uint32_t> out(data.begin() + cursor, data.begin() + cursor + n);
    cursor += n;
    return out;
  }
};
static void equal(const std::vector<uint32_t> &got,
                  const std::vector<uint32_t> &expected, const char *label,
                  uint32_t id) {
  if (got == expected)
    return;
  for (size_t i = 0; i < std::min(got.size(), expected.size()); ++i)
    if (got[i] != expected[i]) {
      std::fprintf(stderr, "batch=%u %s word=%zu got=%u expected=%u\n", id,
                   label, i, got[i], expected[i]);
      break;
    }
  throw std::runtime_error(std::string("mixed batch mismatch: ") + label);
}

} // namespace rv64_fixture
