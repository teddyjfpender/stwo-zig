// Stable backend exports: cudart may be statically linked and hidden from
// dlsym. Calls execute on the session's CUDA owner thread. No API below waits.
#include "events.h"
#include <cuda_runtime_api.h>
#include <stdint.h>
extern "C" int stwo_rv64_event_create(void **out, uint32_t flags) {
  if (!out || flags != 0) return int(cudaErrorInvalidValue);
  return int(cudaEventCreateWithFlags(reinterpret_cast<cudaEvent_t *>(out), flags));
}
extern "C" int stwo_rv64_event_record(void *event, void *stream) {
  if (!event || !stream) return int(cudaErrorInvalidValue);
  return int(cudaEventRecord(reinterpret_cast<cudaEvent_t>(event),
                            reinterpret_cast<cudaStream_t>(stream)));
}
extern "C" int stwo_rv64_event_elapsed(float *out, void *begin, void *end) {
  if (!out || !begin || !end) return int(cudaErrorInvalidValue);
  return int(cudaEventElapsedTime(out, reinterpret_cast<cudaEvent_t>(begin),
                                 reinterpret_cast<cudaEvent_t>(end)));
}
extern "C" int stwo_rv64_event_destroy(void *event) {
  if (!event) return int(cudaErrorInvalidValue);
  return int(cudaEventDestroy(reinterpret_cast<cudaEvent_t>(event)));
}
