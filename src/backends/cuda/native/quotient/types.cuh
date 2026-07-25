#pragma once

#include "../oods/field.cuh"

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::quotient {

using M31 = oods::M31;
using CM31 = oods::CM31;
using QM31 = oods::QM31;
using CirclePoint = oods::CirclePoint;
using SecureCirclePoint = oods::SecureCirclePoint;

struct PreparedTermDescriptor {
    std::uint32_t sample_index;
    std::uint32_t exponent;
    std::uint32_t periodic;
    std::uint32_t period_x;
    std::uint32_t period_y;
};

struct BatchTermDescriptor {
    std::uint32_t source_index;
    std::uint32_t term_index;
    std::uint32_t source_log_size;
};

struct CompactSourceDescriptor {
    std::uint64_t offset_words;
    std::uint32_t stride_words;
    std::uint32_t log_size;
};

static_assert(sizeof(PreparedTermDescriptor) == 5 * sizeof(std::uint32_t));
static_assert(sizeof(BatchTermDescriptor) == 3 * sizeof(std::uint32_t));
static_assert(sizeof(CompactSourceDescriptor) == 2 * sizeof(std::uint64_t));
static_assert(alignof(PreparedTermDescriptor) == alignof(std::uint32_t));
static_assert(alignof(BatchTermDescriptor) == alignof(std::uint32_t));
static_assert(alignof(CompactSourceDescriptor) == alignof(std::uint64_t));
static_assert(offsetof(PreparedTermDescriptor, sample_index) == 0);
static_assert(
    offsetof(PreparedTermDescriptor, period_y) == 4 * sizeof(std::uint32_t));
static_assert(offsetof(BatchTermDescriptor, source_index) == 0);
static_assert(
    offsetof(BatchTermDescriptor, source_log_size) ==
    2 * sizeof(std::uint32_t));
static_assert(offsetof(CompactSourceDescriptor, offset_words) == 0);
static_assert(
    offsetof(CompactSourceDescriptor, stride_words) == sizeof(std::uint64_t));
static_assert(
    offsetof(CompactSourceDescriptor, log_size) ==
    sizeof(std::uint64_t) + sizeof(std::uint32_t));

}  // namespace stwo::cuda::quotient
