//! Device semantic plane: shared local draws followed by each instance's
//! binding metadata and carry rows. Binding values are instance-specific.
const JP = @import("../joined_parameters.zig");
pub const local_words: usize = 8 * JP.local_count;
pub const metadata_words: usize = 260 * 8;
pub fn instanceOffset(row_logs: []const u32, instance: usize) !usize {
    if (instance >= row_logs.len) return error.NativeSemanticInstance;
    var at: usize = local_words;
    for (row_logs[0..instance]) |log| at += metadata_words + 16 * @as(usize, log);
    return at;
}
pub fn words(row_logs: []const u32) usize {
    var n: usize = local_words;
    for (row_logs) |log| n += metadata_words + 16 * @as(usize, log);
    return n;
}
