//! Immutable independently reconstructed memory-tree default recipes. Built
//! once per process, not rehashed along every emitted empty/sharing row.
//! This is fixed public protocol data, never a proof-provided digest oracle.
const std = @import("std");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
var memory: Tree.TreeHasher = undefined;
var initialized = std.once(initialize);
fn initialize() void {
    memory = Tree.TreeHasher.init(.memory);
}
/// Zig0.15 std BLAKE3 cannot evaluate its short-buffer truncation at comptime.
/// Thread-safe immutable reuse preserves the original runtime hash framing.
pub fn get() *const Tree.TreeHasher {
    initialized.call();
    return &memory;
}
