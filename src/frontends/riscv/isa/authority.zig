//! Immutable authorities for the RV32IM frontend.
//!
//! Sail owns ISA decode and retirement semantics. Spike is an independent
//! executable cross-check. The architecture-test pin fixes the test corpus.
//! Stark-V remains only a legacy proof-layout compatibility reference.

const std = @import("std");

pub const sail_repository = "https://github.com/riscv/sail-riscv";
pub const sail_revision = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f";
pub const sail_tag = "2026-07-20-8c7f2da";
pub const sail_compiler_version = "0.20.2";

pub const spike_repository = "https://github.com/riscv-software-src/riscv-isa-sim";
pub const spike_revision = "520a5f185083ac3c97b751501dfac02a6c1f5970";

pub const arch_test_repository = "https://github.com/riscv-non-isa/riscv-arch-test";
pub const arch_test_revision = "426e1598ebc3688eaf9aba7b4a1b8a81dae9807f";

pub const legacy_stark_v_repository = "https://github.com/ClementWalter/stark-v";
pub const legacy_stark_v_revision = "d478f783055aa0d73a93768a433a3c6c31c91d1c";

fn isLowerHexRevision(value: []const u8) bool {
    if (value.len != 40) return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

test "formal ISA authorities are exact immutable revisions" {
    try std.testing.expect(isLowerHexRevision(sail_revision));
    try std.testing.expect(isLowerHexRevision(spike_revision));
    try std.testing.expect(isLowerHexRevision(arch_test_revision));
    try std.testing.expect(isLowerHexRevision(legacy_stark_v_revision));
    try std.testing.expectEqualStrings("0.20.2", sail_compiler_version);
}
