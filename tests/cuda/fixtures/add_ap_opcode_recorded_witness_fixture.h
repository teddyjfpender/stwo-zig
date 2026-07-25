#ifndef STWO_ZIG_CUDA_ADD_AP_RECORDED_WITNESS_FIXTURE_H
#define STWO_ZIG_CUDA_ADD_AP_RECORDED_WITNESS_FIXTURE_H

#include <cstdint>

namespace stwo::cuda::test::add_ap {

inline constexpr std::uint64_t kCacheKey = 0x735903777afd70d2ull;
inline constexpr std::uint64_t kSemanticHash = 0xd94540f2fd219001ull;
inline constexpr std::uint32_t kAbiSchema = 2;
inline constexpr std::uint32_t kArgumentCount = 8;
inline constexpr std::uint32_t kRowCount = 4;
inline constexpr std::uint32_t kInputCount = 4;
inline constexpr std::uint32_t kOutputCount = 17;
inline constexpr std::uint32_t kLookupCount = 55;
inline constexpr std::uint32_t kSubCount = 11;
inline constexpr std::uint32_t kAddressTableSize = 256;
inline constexpr std::uint32_t kBigLimbCount = 28;
inline constexpr std::uint32_t kSmallLimbCount = 8;
inline constexpr std::uint32_t kBigValueCount = 2;
inline constexpr std::uint32_t kSmallValueCount = 2;
inline constexpr const char *kKernelName =
    "stwo_jit_witness_d94540f2fd219001";
inline constexpr const char *kProgramIdentity =
    "1c87a53a6c6ded98045fb88728f9cbd14f79ad8471cff7a16416139a64737da5";

struct AddressEntry {
    std::uint32_t address;
    std::uint32_t encoded_id;
};

inline constexpr AddressEntry kAddressEntries[] = {
    {1u, 1073741825u},
    {2u, 1073741824u},
    {16u, 1u},
    {32u, 0u},
    {100u, 0u},
    {101u, 1u},
    {102u, 1073741824u},
    {103u, 1073741825u},
};

inline constexpr std::uint32_t kInputs[16] = {
    100u, 101u, 102u, 103u, 32768u, 32768u, 32768u, 32768u,
    5u, 7u, 11u, 13u, 17u, 19u, 23u, 29u
};

inline constexpr std::uint32_t kBigLimbs[56] = {
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    1u, 2u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 511u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 256u, 256u
};

inline constexpr std::uint32_t kSmallLimbs[16] = {
    0u, 0u, 0u, 0u, 0u, 0u, 32u, 64u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
};

inline constexpr std::uint32_t kExpectedOutputs[68] = {
    100u, 101u, 102u, 103u, 32768u, 32768u, 32768u, 32768u,
    5u, 7u, 11u, 13u, 1u, 2u, 16u, 32u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    32768u, 32768u, 32768u, 32768u, 1073741825u, 1073741824u, 1u, 0u,
    1u, 1u, 0u, 0u, 1u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 2046u, 2047u, 0u, 0u,
    17u, 19u, 23u, 29u
};

inline constexpr std::uint32_t kExpectedLookupWordMajor[220] = {
    1719106205u, 1719106205u, 1719106205u, 1719106205u, 100u, 101u, 102u, 103u,
    32767u, 32767u, 32767u, 32767u, 32767u, 32767u, 32767u, 32767u,
    1u, 2u, 16u, 32u, 152u, 152u, 152u, 152u,
    16u, 16u, 16u, 16u, 0u, 0u, 0u, 0u,
    1444891767u, 1444891767u, 1444891767u, 1444891767u, 1u, 2u, 16u, 32u,
    1073741825u, 1073741824u, 1u, 0u, 1662111297u, 1662111297u, 1662111297u, 1662111297u,
    1073741825u, 1073741824u, 1u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    508u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    511u, 0u, 0u, 0u, 511u, 0u, 0u, 0u,
    135u, 136u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
    256u, 256u, 0u, 0u, 1109051422u, 1109051422u, 1109051422u, 1109051422u,
    786447u, 15u, 16u, 16u, 991608089u, 991608089u, 991608089u, 991608089u,
    2046u, 2047u, 0u, 0u, 428564188u, 428564188u, 428564188u, 428564188u,
    100u, 101u, 102u, 103u, 32768u, 32768u, 32768u, 32768u,
    5u, 7u, 11u, 13u, 428564188u, 428564188u, 428564188u, 428564188u,
    101u, 102u, 103u, 104u, 1610645502u, 32767u, 32768u, 32768u,
    5u, 7u, 11u, 13u, 1u, 1u, 1u, 1u,
    17u, 19u, 23u, 29u
};

inline constexpr std::uint32_t kExpectedSubWordMajor[44] = {
    100u, 101u, 102u, 103u, 32767u, 32767u, 32767u, 32767u,
    32767u, 32767u, 32767u, 32767u, 1u, 2u, 16u, 32u,
    152u, 152u, 152u, 152u, 16u, 16u, 16u, 16u,
    0u, 0u, 0u, 0u, 1u, 2u, 16u, 32u,
    1073741825u, 1073741824u, 1u, 0u, 786447u, 15u, 16u, 16u,
    2046u, 2047u, 0u, 0u
};

}  // namespace stwo::cuda::test::add_ap

#endif
