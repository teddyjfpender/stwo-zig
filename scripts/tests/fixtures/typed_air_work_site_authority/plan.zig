const ignored = "expectProducer(.comment_only)";
const ignored_multiline =
    \\expectProducer(.multiline_only)
;

fn plan(recorder: anytype) !void {
    // try recorder.expectProducer(.comment_only);
    try recorder.expectProducer(.alpha_fft);
    try recorder.expectProducer(
        .beta_fri,
    );
}
