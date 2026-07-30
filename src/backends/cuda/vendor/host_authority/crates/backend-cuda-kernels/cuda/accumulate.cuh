#ifndef ACCUMULATE_H
#define ACCUMULATE_H

#include "fields.cuh"

extern "C"
void accumulate(int size, m31 **left_columns, m31 **right_columns);

extern "C"
void lift_accumulate_secure_columns(
    int size,
    uint32_t log_ratio,
    m31 **previous_columns,
    m31 **current_columns
);

#endif // ACCUMULATE_H
