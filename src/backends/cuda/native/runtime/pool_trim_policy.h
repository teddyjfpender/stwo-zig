#pragma once
// Shared control flow: validation/capture/joins must succeed before trimming.
// No error reset and no allocation ownership transfer occur here.
namespace stwo::cuda::runtime {
template <class Validate, class Capturing, class Join, class Trim>
int trim_pool(Validate validate, Capturing capturing, Join join, Trim trim,
              int capture_error) {
  const int validated = validate();
  if (validated) return validated;
  if (capturing()) return capture_error;
  const int joined = join();
  if (joined) return joined;
  return trim();
}
} // namespace stwo::cuda::runtime
