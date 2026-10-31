//! Standalone std-only gate: default build must not force libc or wasm symbols.
const std = @import("std");
const builtin = @import("builtin");
const ownership = @import("ownership.zig");
test "RAM arena identity recognizes available stateless allocators without reading undefined context" {
    try std.testing.expect(ownership.same(std.heap.page_allocator, std.heap.page_allocator));
    if (comptime !builtin.single_threaded) try std.testing.expect(ownership.same(std.heap.smp_allocator, std.heap.smp_allocator));
    if (comptime builtin.link_libc) {
        try std.testing.expect(ownership.same(std.heap.c_allocator, std.heap.c_allocator));
        try std.testing.expect(ownership.same(std.heap.raw_c_allocator, std.heap.raw_c_allocator));
    }
    if (comptime builtin.cpu.arch.isWasm() and builtin.single_threaded) try std.testing.expect(ownership.same(std.heap.wasm_allocator, std.heap.wasm_allocator));
}
test "RAM arena identity distinguishes stateful allocator instances with identical vtables" {
    var first = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer first.deinit();
    var second = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer second.deinit();
    try std.testing.expect(ownership.same(first.allocator(), first.allocator()));
    try std.testing.expect(!ownership.same(first.allocator(), second.allocator()));
    try std.testing.expect(!ownership.same(first.allocator(), std.heap.page_allocator));
}
