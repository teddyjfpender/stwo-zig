//! Small cross-target gate for scalar field and exported AIR arithmetic.
//! In particular, run ReleaseSafe and ReleaseFast on the actual x86 CPU.
test {
    _ = @import("air/extract/runtime_program.zig");
}
