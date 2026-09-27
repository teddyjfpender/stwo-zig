//! Shared fixed-depth sparse byte-tree traversal. Inputs must be admitted first.
const std = @import("std");
/// Canonical byte-tree topology and default-subtree semantics. A recursive
/// caller supplies an independently admitted address iterator and a hasher
/// that records authenticated provider requests, retaining zero-byte leaves.
pub fn root(iterator: anytype, depth: u32, start: u32, width: u32, hasher: anytype) @TypeOf(hasher.emptyRoot(0)) {
    return observed(iterator, depth, start, width, hasher, {});
}

/// Optional node observer receives computed children without another traversal.
pub fn observed(iterator: anytype, depth: u32, start: u32, width: u32, hasher: anytype, observer: anytype) @TypeOf(hasher.emptyRoot(0)) {
    const leaf = iterator.current orelse
        return hasher.emptyRoot(depth);
    std.debug.assert(leaf.index >= start);
    const end = @as(u64, start) + width;
    if (leaf.index >= end) return hasher.emptyRoot(depth);
    if (depth == 30) {
        std.debug.assert(width == 1 and leaf.index == start);
        return hasher.leaf(iterator.consume().value);
    }
    const half = width / 2;
    const left = observed(iterator, depth + 1, start, half, hasher, observer);
    const right = observed(iterator, depth + 1, start + half, half, hasher, observer);
    if (comptime @TypeOf(observer) != void) observer.node(depth, start, width, left, right);
    return hasher.pair(left, right);
}
