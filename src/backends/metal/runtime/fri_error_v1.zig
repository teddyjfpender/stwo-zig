//! Preserve the established runtime error surface without weakening admission.
const std = @import("std");
const runtime = @import("../runtime.zig");
pub fn translate(err: anyerror) (runtime.MetalError || std.mem.Allocator.Error) {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => runtime.MetalError.InvalidColumns,
    };
}
