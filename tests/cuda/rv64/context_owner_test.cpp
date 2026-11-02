// Fake async transfers deliberately defer reading host sources until join.
// Exercise ingress lifetime on normal completion and exception teardown.
#include "context_owner.cuh"
#include <cassert>
#include <cstring>
static uint32_t live = 0, joins = 0;
struct Pending {
    void* dst;
    const void* src;
    size_t bytes;
};
static std::vector<Pending> pending;
extern "C" int stwo_exec_context_create_options(const StwoCudaContextOptions*, void** out) {
    *out = reinterpret_cast<void*>(1);
    return 0;
}
extern "C" int stwo_exec_context_alloc_u32(void*, size_t count, uint32_t** out) {
    *out = new uint32_t[count]{};
    ++live;
    return 0;
}
extern "C" int stwo_exec_context_memcpy_h2d_async(void*, void* dst, const void* src,
                                                  size_t bytes) {
    pending.push_back({dst, src, bytes});
    return 0;
}
extern "C" int stwo_exec_context_sync(void*) {
    for (auto p : pending) std::memcpy(p.dst, p.src, p.bytes);
    pending.clear();
    ++joins;
    return 0;
}
extern "C" int stwo_exec_context_free_u32(void*, uint32_t* p) {
    assert(pending.empty());
    delete[] p;
    --live;
    return 0;
}
extern "C" int stwo_exec_context_destroy(void*) {
    assert(!live);
    return 0;
}
int main() {
    {
        Owner o(0);
        const auto p = o.plane(4, 1);
        o.upload(p, std::vector<uint32_t>{1, 2, 3, 4});  // temporary dies here
        CHECK(stwo_exec_context_sync(o.ctx));
        assert(p.words[0] == 1 && p.words[3] == 4);
        o.close();
    }
    const auto before = joins;
    try {
        Owner o(0);
        const auto p = o.plane(4, 1);
        o.upload(p, std::vector<uint32_t>{5, 6, 7, 8});
        throw std::runtime_error("injected after enqueue");
    } catch (const std::runtime_error&) {
    }
    assert(joins == before + 1 && live == 0 && pending.empty());
}
