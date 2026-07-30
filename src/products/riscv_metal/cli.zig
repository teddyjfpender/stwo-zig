//! Strict command contract for the focused RISC-V Metal product.
//!
//! The parser itself is the shared, spec-driven one in
//! `src/products/riscv_shared/cli.zig`; this file is the binding that fixes the
//! Metal product's vocabulary and re-exports the resulting surface. Because the
//! parser is shared, this CLI accepts exactly the command and flag shape the CPU
//! CLI accepts — that is what makes a CPU run and a Metal run comparable — while
//! `spec.backend` makes `metal` the only token `--backend` will accept here.

const std = @import("std");
const shared = @import("riscv_shared_cli");

pub const spec = shared.Spec{
    .executable = "stwo-zig-riscv-metal",
    .backend = "metal",
    .backend_note = "Backend: fail-closed Apple Metal only; no runtime fallback.",
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

test "only ELF and Metal are accepted" {
    const parsed = (try parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "metal", "--output", "proof.json",
    })).prove;
    try std.testing.expectEqualStrings("guest.elf", parsed.run.elf_path);
    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "cpu", "--output", "proof.json",
    }));
    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "metal-hybrid", "--output", "proof.json",
    }));
    try std.testing.expectError(error.UnknownArgument, parse(&.{
        "prove", "--air", "wide_fibonacci", "--backend", "metal", "--output", "proof.json",
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

test "the benchmark contract matches the CPU lane it is compared against" {
    const request = (try parse(&.{
        "bench",
        "--elf",
        "guest.elf",
        "--backend",
        "metal",
        "--protocol",
        "secure",
        "--warmups",
        "1",
        "--samples",
        "3",
        "--proof-out",
        "proof.json",
    })).bench;
    try std.testing.expectEqual(@as(usize, 1), request.warmups);
    try std.testing.expectEqual(@as(usize, 3), request.samples);
    try std.testing.expectEqual(Protocol.secure, request.run.protocol);
    try std.testing.expect(!request.run.experimental);
}

test "help does not advertise unrelated products" {
    var storage: [4096]u8 = undefined;
    inline for (.{ null, Command.prove, Command.bench, Command.verify, Command.applications }) |command| {
        var output = std.Io.Writer.fixed(&storage);
        try writeUsage(&output, command);
        const text = output.buffered();
        try std.testing.expect(std.mem.indexOf(u8, text, "stwo-zig-riscv-metal") != null);
        inline for (.{ "cpu", "cuda", "cairo", "wide_fibonacci", "native" }) |forbidden| {
            try std.testing.expect(std.mem.indexOf(u8, text, forbidden) == null);
        }
    }
}
