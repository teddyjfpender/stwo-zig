const ignored = "recordCompletedDelta(.{ .site = .string_only })";

fn complete(recorder: anytype, alpha: anytype, beta: anytype) !void {
    // try recorder.recordCompletedDelta(.{ .site = .comment_only });
    try recorder.recordCompletedDelta(.{
        .site = .alpha_fft,
        .delta = alpha,
    });
    try recorder.recordCompletedDelta(.{
        .site = .beta_fri,
        .delta = beta,
    });
}
