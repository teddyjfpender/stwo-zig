//! Query-domain geometry from the verifier-owned four-tree capture.
pub const COMMITMENT_TREE_COUNT: usize = 4;
pub fn queryLogSizeFromCapture(
    capture: anytype,
) !u32 {
    if (capture.column_log_sizes.len !=
        COMMITMENT_TREE_COUNT or
        capture.trace_paths.len != COMMITMENT_TREE_COUNT)
    {
        return error.FreshWrapperCaptureMismatch;
    }
    const composition_index = COMMITMENT_TREE_COUNT - 1;
    const logs = capture.column_log_sizes[composition_index];
    if (logs.len == 0) return error.FreshWrapperCaptureMismatch;
    var query_log_size: u32 = 0;
    for (logs) |log_size| {
        if (log_size == 0 or log_size >= 31)
            return error.FreshWrapperCaptureMismatch;
        query_log_size = @max(query_log_size, log_size);
    }
    if (capture.trace_paths[composition_index].path_depth != query_log_size)
        return error.FreshWrapperCaptureMismatch;
    return query_log_size;
}
