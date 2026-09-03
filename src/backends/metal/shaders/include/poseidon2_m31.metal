#ifndef STWO_ZIG_POSEIDON2_M31_METAL
#define STWO_ZIG_POSEIDON2_M31_METAL

#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/m31.metal"
#endif

// Exact Stark-V Poseidon2-M31 parameters shared with
// frontends/riscv/air/memory_commitment/poseidon2_constants.zig.  These are
// protocol constants, not runtime/AOT tuning parameters.
constant uint stwo_zig_poseidon2_external_rounds[8][16] = {
    { 1988864850u, 1893772157u, 1025928330u, 1839472709u,
      1611656994u, 1104858731u, 1694088660u, 1564660990u,
      1991332205u, 1875486487u, 1890340790u, 1658614u,
      582370530u, 528029397u, 1196956642u, 655401251u },
    { 1652877415u, 26032894u, 1576640243u, 1277052539u,
      1450142396u, 697623591u, 1401580866u, 1568404175u,
      2145004971u, 265835716u, 1183985610u, 1031234465u,
      436012490u, 172735299u, 352802897u, 1032863094u },
    { 757665783u, 1082171296u, 1507509996u, 309929890u,
      1807683232u, 43258895u, 611592566u, 1854193793u,
      575164234u, 894217817u, 72613857u, 1061659596u,
      8921166u, 1617355017u, 998001536u, 1800758877u },
    { 1002748055u, 1935405944u, 1351462722u, 411368491u,
      1913975372u, 1956167178u, 442558016u, 855898408u,
      699687798u, 1553382248u, 1708169125u, 490049183u,
      1251643415u, 1193594742u, 880473871u, 511174042u },
    { 1460209171u, 530850056u, 398192464u, 536338716u,
      75179210u, 1309934197u, 1335920373u, 127611036u,
      291093831u, 1832379621u, 123571662u, 303176864u,
      2137685056u, 1759609530u, 1418928155u, 71608334u },
    { 6616262u, 1684515814u, 1721194338u, 720801691u,
      878392254u, 460379263u, 87930647u, 940673483u,
      1136203256u, 551499412u, 256220454u, 2007034235u,
      796124985u, 410436345u, 1705042586u, 1286336446u },
    { 1522340456u, 1295296352u, 309794713u, 1772145068u,
      956898901u, 2137070800u, 988829146u, 2059451359u,
      1846491684u, 1105442551u, 1236497773u, 1452000568u,
      549485016u, 385992492u, 1987107948u, 1514377269u },
    { 2090065934u, 1444920141u, 293113979u, 41120774u,
      855319793u, 1663284746u, 1789994008u, 1120509162u,
      358222743u, 1406256810u, 735183687u, 664485235u,
      1331641456u, 38121324u, 595810771u, 1234594393u },
};

constant uint stwo_zig_poseidon2_internal_rounds[14] = {
    2139014335u, 69309039u, 1368974953u, 886780232u,
    1130937085u, 1718115455u, 2027103386u, 1612216449u,
    1994053242u, 110146615u, 514413329u, 1088763546u,
    955319292u, 488794657u,
};

constant uint stwo_zig_poseidon2_internal_diagonal[16] = {
    129501892u, 1809435443u, 1223573407u, 1331944729u,
    415581875u, 1526242955u, 1341275624u, 1333308150u,
    1404946132u, 1549369918u, 709303410u, 1284988537u,
    1490838740u, 115945821u, 754131590u, 800486749u,
};

inline uint stwo_zig_poseidon2_sbox(uint value) {
    uint squared = m31_mul(value, value);
    return m31_mul(m31_mul(squared, squared), value);
}

inline void stwo_zig_poseidon2_m4(thread uint *state) {
    uint t0 = m31_add(state[0], state[1]);
    uint t1 = m31_add(state[2], state[3]);
    uint t2 = m31_add(m31_add(state[1], state[1]), t1);
    uint t3 = m31_add(m31_add(state[3], state[3]), t0);
    uint t4 = m31_add(m31_add(t1, t1), m31_add(m31_add(t1, t1), t3));
    uint t5 = m31_add(m31_add(t0, t0), m31_add(m31_add(t0, t0), t2));
    state[0] = m31_add(t3, t5);
    state[1] = t5;
    state[2] = m31_add(t2, t4);
    state[3] = t4;
}

inline void stwo_zig_poseidon2_external_matrix(thread uint *state) {
    for (uint block = 0u; block < 4u; ++block)
        stwo_zig_poseidon2_m4(state + 4u * block);
    for (uint lane = 0u; lane < 4u; ++lane) {
        uint sum = m31_add(
            m31_add(state[lane], state[lane + 4u]),
            m31_add(state[lane + 8u], state[lane + 12u])
        );
        for (uint block = 0u; block < 4u; ++block) {
            uint index = 4u * block + lane;
            state[index] = m31_add(state[index], sum);
        }
    }
}

inline void stwo_zig_poseidon2_full_round(thread uint *state, uint round) {
    for (uint lane = 0u; lane < 16u; ++lane) {
        state[lane] = stwo_zig_poseidon2_sbox(m31_add(
            state[lane], stwo_zig_poseidon2_external_rounds[round][lane]
        ));
    }
    stwo_zig_poseidon2_external_matrix(state);
}

inline void stwo_zig_poseidon2_internal_matrix(thread uint *state) {
    uint sum = 0u;
    for (uint lane = 0u; lane < 16u; ++lane) sum = m31_add(sum, state[lane]);
    for (uint lane = 0u; lane < 16u; ++lane) {
        state[lane] = m31_add(
            m31_mul(state[lane], stwo_zig_poseidon2_internal_diagonal[lane]),
            sum
        );
    }
}

inline void stwo_zig_poseidon2_permute(thread uint *state) {
    stwo_zig_poseidon2_external_matrix(state);
    for (uint round = 0u; round < 4u; ++round)
        stwo_zig_poseidon2_full_round(state, round);
    for (uint round = 0u; round < 14u; ++round) {
        state[0] = stwo_zig_poseidon2_sbox(m31_add(
            state[0], stwo_zig_poseidon2_internal_rounds[round]
        ));
        stwo_zig_poseidon2_internal_matrix(state);
    }
    for (uint round = 4u; round < 8u; ++round)
        stwo_zig_poseidon2_full_round(state, round);
}

inline void stwo_zig_poseidon2_leaf_init(thread uint *state) {
    for (uint lane = 0u; lane < 16u; ++lane) state[lane] = 0u;
    state[15] = 1u;
}

inline void stwo_zig_poseidon2_leaf_absorb(
    thread uint *state, thread uint &filled, uint word
) {
    state[filled] = m31_add(state[filled], word);
    filled += 1u;
    if (filled == 8u) {
        stwo_zig_poseidon2_permute(state);
        filled = 0u;
    }
}

inline void stwo_zig_poseidon2_leaf_finish(thread uint *state, thread uint &filled) {
    stwo_zig_poseidon2_leaf_absorb(state, filled, 1u);
    if (filled != 0u) {
        stwo_zig_poseidon2_permute(state);
        filled = 0u;
    }
}

inline void stwo_zig_poseidon2_parent(
    thread const uint *children, thread uint *digest
) {
    uint state[16];
    for (uint lane = 0u; lane < 16u; ++lane) state[lane] = children[lane];
    stwo_zig_poseidon2_permute(state);
    for (uint lane = 0u; lane < 8u; ++lane) digest[lane] = state[lane];
}

#endif
