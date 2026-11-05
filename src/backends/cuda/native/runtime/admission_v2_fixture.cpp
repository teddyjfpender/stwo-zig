// Runtime-only allocator/ownership controls. No arithmetic kernel or proof.
// Run only under the shared GPU harness lock, with STWO_RV64_DEVICE_ARENA=22G.
#include "admission_v2.h"
#include "context_options.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>

static unsigned checks = 0;
static void check(bool ok, const char *label) {
    ++checks;
    if (!ok) { fprintf(stderr, "FAIL %s check=%u\n", label, checks); exit(1); }
}
template<class F> static F load(void *library, const char *name) {
    auto result = reinterpret_cast<F>(dlsym(library, name));
    check(result != nullptr, name); return result;
}
static void bounded(const StwoCudaOwnerSnapshotV2 &s) {
    check(s.version == 2 && s.entered <= 1 && s.ended <= 1, "snapshot ABI/state");
    check(s.global_live_large <= s.capacity - s.small_slab && s.reserved_unused_large <= s.capacity - s.small_slab - s.global_live_large, "global large reservation bound");
    check(s.global_live_small <= s.small_slab && s.reserved_unused_small <= s.small_slab - s.global_live_small, "global small reservation bound");
    check(s.stable_live_large <= s.global_live_large && s.stable_live_small <= s.global_live_small, "stable baseline bound");
    check(s.owner_new_live_large <= s.owner_live_large && s.owner_new_live_small <= s.owner_live_small, "creator ownership bound");
}
int main(int argc, char **argv) {
    check(argc == 2, "selected runtime library argument");
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    check(library != nullptr, "dlopen selected runtime");
    auto create = load<int(*)(const StwoCudaContextOptions *, void **)>(library, "stwo_exec_context_create_options");
    auto destroy = load<int(*)(void *)>(library, "stwo_exec_context_destroy");
    auto identity = load<int(*)(void *, uint64_t *)>(library, "stwo_exec_context_identity");
    auto alloc = load<int(*)(void *, size_t, uint32_t **)>(library, "stwo_exec_context_alloc_u32");
    auto release = load<int(*)(void *, uint32_t *)>(library, "stwo_exec_context_free_u32");
    auto sync = load<int(*)(void *)>(library, "stwo_exec_context_sync");
    auto v1 = load<int(*)(void *, uint64_t)>(library, "stwo_exec_context_admission_configure_v1");
    auto configure = load<decltype(&stwo_exec_context_admission_configure_v2)>(library, "stwo_exec_context_admission_configure_v2");
    auto reserve = load<decltype(&stwo_exec_context_admission_reserve_v2)>(library, "stwo_exec_context_admission_reserve_v2");
    auto enter = load<decltype(&stwo_exec_context_admission_enter_v2)>(library, "stwo_exec_context_admission_enter_v2");
    auto end = load<decltype(&stwo_exec_context_admission_end_v2)>(library, "stwo_exec_context_admission_end_v2");
    auto finish = load<decltype(&stwo_exec_context_admission_finish_v2)>(library, "stwo_exec_context_admission_finish_v2");
    auto cancel = load<decltype(&stwo_exec_context_admission_cancel_v2)>(library, "stwo_exec_context_admission_cancel_v2");
    auto snapshot = load<decltype(&stwo_exec_context_admission_snapshot_v2)>(library, "stwo_exec_context_admission_snapshot_v2");
    constexpr uint64_t chunk = 32ull << 20, cap = 22ull << 30;
    for (uint32_t device = 0; device < 2; ++device) {
        void *a = nullptr, *b = nullptr;
        StwoCudaContextOptions options{1, device, 2, 0};
        check(create(&options, &a) == 0, "create owner A");
        check(create(&options, &b) == 0, "create owner B");
        uint64_t aid = 0, bid = 0;
        check(identity(a, &aid) == 0 && identity(b, &bid) == 0 && aid && bid && aid != bid, "distinct creator identities");
        check(configure(a, cap) == 0 && configure(b, cap) == 0, "configure V2 contexts");
        check(v1(a, cap) != 0, "reject V1/V2 mixing");
        StwoCudaOwnerSnapshotV2 s{};
        uint32_t *old = nullptr, *old_small = nullptr, *anew = nullptr, *asmall = nullptr, *bnew = nullptr, *bsmall = nullptr, *invalid = nullptr;
        check(alloc(a, 1, &invalid) != 0, "reject allocation outside window");
        int host_status = -1;
        std::thread host([&] { host_status = reserve(a, aid, 1, chunk, 512, &s); }); host.join();
        check(host_status == 0, "reserve from non-owner host thread"); bounded(s);
        check(alloc(a, 1, &invalid) != 0, "reject allocation before entry");
        check(enter(b, 1, "wrong-owner") != 0, "reject foreign window entry");
        check(enter(a, 1, "fixture/baseline") == 0, "enter baseline window");
        check(alloc(a, chunk / 4, &old) == 0 && alloc(a, 1, &old_small) == 0, "create old stable allocations");
        check(sync(a) == 0 && end(a, 1, &s) == 0, "join and end baseline"); bounded(s);
        check(s.stable_live_large == 0 && s.owner_new_live_large == chunk, "ended new bytes remain transient");
        check(cancel(a, aid, 1, &s) != 0, "reject cancel after owner entry");
        check(finish(a, aid, 1, &s) == 0, "finish baseline to stable"); bounded(s);
        check(s.stable_live_large == chunk && s.stable_live_small == 512 && s.ticket == 0, "baseline survives finish");
        check(reserve(a, aid, 2, 2 * chunk, 512, &s) == 0, "reserve A overlap window");
        check(reserve(b, bid, 2, chunk, 0, &s) != 0, "reject duplicate physical ticket");
        check(reserve(b, bid, 99, cap, 0, &s) != 0, "reject aggregate capacity overflow");
        check(reserve(b, bid, 3, 2 * chunk, 512, &s) == 0, "reserve B overlap window"); bounded(s);
        check(s.active_reservations == 2, "two simultaneous reservations");
        check(enter(a, 2, "fixture/A") == 0 && enter(b, 3, "fixture/B") == 0, "two entered owner windows");
        check(alloc(a, 2 * chunk / 4, &anew) == 0 && alloc(a, 1, &asmall) == 0, "A consumes own budget");
        check(release(a, old) == 0 && release(a, old_small) == 0, "free old stable creator allocations");
        check(alloc(a, 1, &invalid) != 0 && alloc(a, chunk / 4, &invalid) != 0, "old free never expands own new budget");
        check(alloc(b, chunk / 4, &bnew) == 0 && alloc(b, 1, &bsmall) == 0, "B consumes independent budget");
        check(snapshot(b, aid, &s) != 0, "reject foreign context identity");
        check(snapshot(a, aid, &s) == 0, "snapshot active peer allocations"); bounded(s);
        check(s.global_live_large == 3 * chunk && s.stable_live_large == 0 && s.owner_new_live_large == 2 * chunk, "active ticket attribution excludes peers");
        check(sync(b) == 0 && end(b, 3, &s) == 0, "end B only"); bounded(s);
        check(alloc(b, 1, &invalid) != 0, "reject allocation after end");
        check(end(b, 3, &s) != 0 && cancel(b, bid, 3, &s) != 0, "reject repeated end and entered cancel");
        std::thread finish_host([&] { host_status = finish(b, bid, 3, &s); }); finish_host.join();
        check(host_status == 0, "finish from non-owner host thread"); bounded(s);
        check(s.active_reservations == 1 && s.stable_live_large == chunk, "finish exposes only own retained bytes");
        check(sync(a) == 0 && end(a, 2, &s) == 0 && finish(a, aid, 2, &s) == 0, "finish A independent window"); bounded(s);
        check(s.stable_live_large == 3 * chunk && s.active_reservations == 0, "all joined retention stable");
        check(finish(a, aid, 2, &s) != 0, "reject stale finish");
        check(release(a, anew) == 0 && release(a, asmall) == 0 && release(b, bnew) == 0 && release(b, bsmall) == 0, "release actual creators");
        check(sync(a) == 0 && sync(b) == 0 && snapshot(a, aid, &s) == 0, "join physical retirement"); bounded(s);
        check(s.global_live_large == 0 && s.global_live_small == 0 && s.stable_live_large == 0, "balanced actual retirement");
        check(reserve(a, aid, 4, chunk, 0, &s) == 0 && cancel(a, aid, 4, &s) == 0, "cancel never-entered reservation");
        check(cancel(a, aid, 4, &s) != 0, "reject stale cancel");
        check(destroy(a) == 0 && snapshot(a, aid, &s) != 0, "retired raw handle rejected without dereference");
        check(destroy(b) == 0, "destroy owner B");
    }
    printf("ADMISSION_V2_FIXTURE checks=%u devices=2 PASS\n", checks);
    dlclose(library);
}
