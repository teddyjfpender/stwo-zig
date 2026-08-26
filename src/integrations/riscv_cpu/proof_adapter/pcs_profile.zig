//! One staged RISC-V PCS policy shared by proving and artifact verification.

const std = @import("std");
const stwo = @import("stwo");

pub const Protocol = enum { secure, functional, smoke };

/// `.secure` is the frontend's shared constant, not a restatement of it. The
/// cross-language benchmark contract mirrors that same reviewed authority.
pub fn select(protocol: Protocol) stwo.core.pcs.PcsConfig {
    return switch (protocol) {
        .secure => stwo.frontends.riscv.prover_mod.SECURE_PCS_CONFIG,
        .functional => .{
            .pow_bits = 10,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
            },
        },
        .smoke => .{
            .pow_bits = 0,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
            },
        },
    };
}

test "adapter PCS profiles satisfy their advertised artifact policies" {
    const cases = [_]struct {
        protocol: Protocol,
        pow_bits: u32,
        n_queries: usize,
    }{
        .{ .protocol = .secure, .pow_bits = 26, .n_queries = 70 },
        .{ .protocol = .functional, .pow_bits = 10, .n_queries = 3 },
        .{ .protocol = .smoke, .pow_bits = 0, .n_queries = 3 },
    };
    for (cases) |case| {
        const config = select(case.protocol);
        try std.testing.expectEqual(case.pow_bits, config.pow_bits);
        try std.testing.expectEqual(case.n_queries, config.fri_config.n_queries);
    }
    try std.testing.expectEqual(
        stwo.frontends.riscv.prover_mod.SECURE_PCS_CONFIG,
        select(.secure),
    );
}
