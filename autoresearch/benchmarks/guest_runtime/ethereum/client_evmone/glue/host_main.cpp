// Native (host) driver for debugging the client glue (our code).
// Usage: client-evmone-host <canonical-input.ssz> [expected-output.bin]
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

extern "C" void stwo_validate(const uint8_t* ssz, size_t len, uint8_t out_root[32], uint64_t* chain_id,
                              uint16_t* schema_id);

extern "C" [[noreturn]] void stwo_guest_abort(const char* why) noexcept {
    std::fprintf(stderr, "guest abort: %s\n", why);
    std::exit(2);
}

static std::vector<uint8_t> slurp(const char* path) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { std::perror(path); std::exit(1); }
    std::vector<uint8_t> v;
    uint8_t buf[1 << 16];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) v.insert(v.end(), buf, buf + n);
    std::fclose(f);
    return v;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s input.ssz [expected.bin]\n", argv[0]); return 1; }
    std::vector<uint8_t> in = slurp(argv[1]);
    // Keep the input 8-byte aligned at +4 like the guest window (u32 prefix).
    std::vector<uint64_t> win((in.size() + 4 + 7) / 8 + 1);
    uint8_t* base = reinterpret_cast<uint8_t*>(win.data());
    std::memcpy(base + 4, in.data(), in.size());
    uint8_t root[32];
    uint64_t chain = 0;
    uint16_t schema = 0;
    stwo_validate(base + 4, in.size(), root, &chain, &schema);
    uint8_t out[43];
    std::memcpy(out, root, 32);
    out[32] = 1;
    for (int i = 0; i < 8; ++i) out[33 + i] = uint8_t(chain >> (8 * i));
    out[41] = uint8_t(schema);
    out[42] = uint8_t(schema >> 8);
    for (uint8_t b : out) std::printf("%02x", b);
    std::printf("\n");
    if (argc > 2) {
        std::vector<uint8_t> exp = slurp(argv[2]);
        const bool ok = exp.size() == 43 && std::memcmp(exp.data(), out, 43) == 0;
        std::printf("%s\n", ok ? "MATCH" : "MISMATCH");
        return ok ? 0 : 3;
    }
    return 0;
}
