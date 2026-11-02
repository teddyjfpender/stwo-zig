//! Allocator identity at concrete arena handoff boundaries. Stateless std
//! allocators deliberately carry an UNDEFINED ptr, which must never be read.
const std = @import("std");
const builtin = @import("builtin");
pub fn same(a: std.mem.Allocator, b: std.mem.Allocator) bool {
    if (a.vtable != b.vtable) return false;
    // Compare concrete standard implementations, rather than page_allocator's
    // potentially stateful root.os.heap override.
    if (comptime !builtin.single_threaded) if (a.vtable == &std.heap.SmpAllocator.vtable) return true;
    if (comptime !builtin.cpu.arch.isWasm() and builtin.os.tag != .plan9) if (a.vtable == &std.heap.PageAllocator.vtable) return true;
    if (comptime builtin.link_libc) if (a.vtable == std.heap.c_allocator.vtable or a.vtable == std.heap.raw_c_allocator.vtable) return true;
    if (comptime builtin.cpu.arch.isWasm() and builtin.single_threaded) if (a.vtable == std.heap.wasm_allocator.vtable) return true;
    if (comptime builtin.os.tag == .plan9) if (a.vtable == &std.heap.SbrkAllocator(std.os.plan9.sbrk).vtable) return true;
    return a.ptr == b.ptr;
}
