//! Strict command contract for the focused RISC-V CPU product.
//!
//! The parser itself is the shared, spec-driven one; this file is the binding
//! that fixes the CPU product's vocabulary and re-exports the resulting surface.

const std = @import("std");
const shared = @import("riscv_product").cli;

pub const spec = shared.Spec{
    .executable = "stwo-zig-riscv-cpu",
    .backend = "cpu",
    .backend_note = "Backend: CPU scalar/SIMD only; no runtime fallback.",
};

const impl = shared.Cli(spec);

pub const Command = impl.Command;
pub const Protocol = impl.Protocol;
pub const Run = impl.Run;
pub const Prove = impl.Prove;
pub const Bench = impl.Bench;
pub const Verify = impl.Verify;
pub const Parsed = impl.Parsed;
pub const parse = impl.parse;
pub const writeUsage = impl.writeUsage;

test "only ELF and CPU are accepted" {
    const parsed = (try parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "cpu", "--output", "proof.json",
    })).prove;
    try std.testing.expectEqualStrings("guest.elf", parsed.run.elf_path);
    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "metal-hybrid", "--output", "proof.json",
    }));
    try std.testing.expectError(error.UnknownArgument, parse(&.{
        "prove", "--air", "wide_fibonacci", "--backend", "cpu", "--output", "proof.json",
    }));
}

test "focused RISC-V verification requires the source ELF" {
    try std.testing.expectError(error.MissingElf, parse(&.{
        "verify", "--artifact", "proof.json",
    }));
    const request = (try parse(&.{
        "verify", "--artifact", "proof.json", "--elf", "guest.elf",
    })).verify;
    try std.testing.expectEqualStrings("guest.elf", request.elf_path);
}

test "help does not advertise unrelated products" {
    var storage: [4096]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try writeUsage(&output, null);
    inline for (.{ "metal", "cuda", "cairo", "wide_fibonacci", "native" }) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, output.buffered(), forbidden) == null);
    }
}
