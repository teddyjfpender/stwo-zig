#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int stwo_rv64_event_create(void **out, uint32_t flags);
int stwo_rv64_event_record(void *event, void *stream);
int stwo_rv64_event_elapsed(float *out, void *begin, void *end);
int stwo_rv64_event_destroy(void *event);
#ifdef __cplusplus
}
#endif
