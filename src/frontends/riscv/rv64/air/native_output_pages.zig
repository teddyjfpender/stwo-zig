//! Establish writable pages before parallel, bit-reversed scatter stores.
//! Several workers can otherwise fault the same fresh page concurrently even
//! when their cache lines are disjoint. This touches ONE word per OS page; it
//! does not initialize the matrix. The caller must subsequently write every
//! value before reading or publishing any output.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

pub fn prepare(output: []M31) void {
    // Operational opt-out supports same-binary A/B measurements and hosts
    // whose page/NUMA policy needs independent performance qualification.
    if (std.process.hasEnvVarConstant("STWO_RV64_DISABLE_INTERACTION_PAGE_PREPARATION")) return;
    const page_size = std.heap.pageSize();
    const page_words = page_size / @sizeOf(M31);
    if (output.len < page_words) return;
    const first: *volatile M31 = &output[0];
    first.* = M31.zero();
    var offset = (page_size - @intFromPtr(output.ptr) % page_size) / @sizeOf(M31);
    while (offset < output.len) : (offset += page_words) {
        const first_in_page: *volatile M31 = &output[offset];
        first_in_page.* = M31.zero();
    }
}

test "page preparation stays inside a partial-page slice and leaves other words untouched" {
    const a = std.testing.allocator;
    const page_words = std.heap.pageSize() / @sizeOf(M31);
    const backing = try a.alloc(M31, 3 * page_words + 17);
    defer a.free(backing);
    @memset(backing, M31.one());
    // The sub-slice need not start at the allocation or page boundary.
    const output = backing[3 .. backing.len - 5];
    prepare(output);
    for (backing, 0..) |word, i| {
        const touched = i >= 3 and i < backing.len - 5 and
            (i == 3 or @intFromPtr(&backing[i]) % std.heap.pageSize() == 0);
        try std.testing.expect(word.eql(if (touched) M31.zero() else M31.one()));
    }
    prepare(backing[0..0]);
    const short = backing[4..8];
    @memset(short, M31.one());
    prepare(short);
    for (short) |word| try std.testing.expect(word.eql(M31.one()));
}
