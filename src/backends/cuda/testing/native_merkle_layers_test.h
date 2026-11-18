// Included by the canonical CUDA commitment smoke after its arena and
// independent CPU hash oracle. No production caller or additional launcher.
bool test_merkle_layer_schedules(DeviceArena &arena) {
    for (uint32_t log : {1u, 2u, 3u, 7u, 10u, 11u, 12u, 13u, 14u, 20u, 21u, 22u}) {
        const uint32_t leaves = 1u << log;
        const size_t count = 2ull * leaves - 1;
        std::vector<Hash> expected(count), actual(count);
        for (uint32_t i = 0; i < leaves; ++i)
            for (uint32_t w = 0; w < 8; ++w)
                expected[i].words[w] = (i + 1) * 0x9e3779b9u ^ w * 0x85ebca6bu;
        auto *device = reinterpret_cast<Hash *>(arena.allocate(count * 8));
        if (!device || !arena.upload(device, expected.data(), leaves * sizeof(Hash))) return false;
        stwo_blake2s_m8_merkle_fused_override(0);
        if (!check(stwo_blake2s_merkle_layers_on(device, leaves, count, arena.stream), "oracle tree") ||
            !arena.read(expected.data(), device, count * sizeof(Hash)) ||
            !check(stwo_exec_context_sync(arena.context), "oracle tree wait")) return false;
        if (log <= 14) {
            size_t offset = 0;
            for (uint32_t n = leaves; n > 1; offset += n, n >>= 1)
                for (uint32_t i = 0; i < n / 2; ++i)
                    if (!expect_hash(expected[offset + n + i],
                                     blake2s_reference::hash_children(expected[offset + 2 * i], expected[offset + 2 * i + 1]),
                                     "CPU tree", uint32_t(offset + n + i))) return false;
        }
        for (int mode : {1, -2}) {
            stwo_blake2s_m8_merkle_fused_override(mode);
            if (!arena.upload(device, expected.data(), leaves * sizeof(Hash)) ||
                !check(stwo_blake2s_merkle_layers_on(device, leaves, count, arena.stream), "fused tree") ||
                !arena.read(actual.data(), device, count * sizeof(Hash)) ||
                !check(stwo_exec_context_sync(arena.context), "fused tree wait")) return false;
            for (size_t i = 0; i < count; ++i)
                if (!expect_hash(actual[i], expected[i], "full tree", uint32_t(i))) return false;
        }
        if (stwo_blake2s_merkle_layers_on(device, leaves, count - 1, arena.stream) == 0 ||
            stwo_blake2s_merkle_layers_on(device, 3, count, arena.stream) == 0 ||
            stwo_blake2s_merkle_layers_on(nullptr, leaves, count, arena.stream) == 0) return false;
        stwo_blake2s_m8_merkle_fused_override(2);
        if (stwo_blake2s_merkle_layers_on(device, leaves, count, arena.stream) == 0) return false;
    }
    stwo_blake2s_m8_merkle_fused_override(-2);
    return true;
}
