//! Guest ABI view of the product hooks. The pipeline reads the guest contract
//! only through this file; the hooks module is injected by the product build
//! (`rv64_pipeline_hooks`) and validated once at comptime.
const std = @import("std");
const hooks = @import("hooks.zig");
const H = @import("rv64_pipeline_hooks");

comptime {
    hooks.assertHooks(H);
}

pub const Symbols = H.Symbols;
pub const OUTPUT_BYTES: usize = H.OUTPUT_BYTES;
/// Largest admitted input window, including the 4-byte length prefix.
pub const INPUT_CAPACITY_MAX: usize = H.MAX_INPUT_BYTES + 4;
pub const admitsProfile = H.admitsProfile;
pub const haltFlag = H.haltFlag;

/// Map ELF and input into the immutable initial image through the product
/// loader. Errors are the product's own; no partial image escapes.
pub fn load(a: std.mem.Allocator, symbols: Symbols, elf: []const u8, input: []const u8) !@import("stwo_riscv_rv64").execution.elf.LoadedImage {
    return H.loadImage(a, symbols, elf, input);
}
