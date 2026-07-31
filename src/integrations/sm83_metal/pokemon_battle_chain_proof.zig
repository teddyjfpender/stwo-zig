//! Metal proof for the complete pinned proof-fast Pokemon benchmark battle.

const std = @import("std");
const core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_sm83_frontend");
const environment = @import("machine_environment.zig");

const battle_chain = frontend.pokemon_battle_chain;
const verifier = frontend.machine_environment_verifier;
const ProverEngine = environment.ProverEngine;
const VerifierEngine = verifier.ProverEngineForBackend(CpuBackend);

const SecurityProfile = enum { secure, smoke };

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const security = parseOptions(arguments) catch {
        std.debug.print(
            "usage: sm83-pokemon-metal-battle-chain /path/to/PE-AGI/v1 [--smoke]\n",
            .{},
        );
        return error.InvalidArguments;
    };
    const receipt = try battle_chain.proveAndVerify(
        ProverEngine,
        VerifierEngine,
        allocator,
        try proofConfig(security),
        arguments[1],
        .benchmark,
    );
    battle_chain.printReceipt("Metal", receipt);
}

fn parseOptions(arguments: []const []const u8) !SecurityProfile {
    if (arguments.len < 2 or arguments.len > 3 or arguments[1].len == 0 or
        std.mem.startsWith(u8, arguments[1], "--"))
    {
        return error.InvalidArguments;
    }
    if (arguments.len == 2) return .secure;
    if (std.mem.eql(u8, arguments[2], "--smoke")) return .smoke;
    return error.InvalidArguments;
}

fn proofConfig(profile: SecurityProfile) !core.pcs.PcsConfig {
    const config: core.pcs.PcsConfig = switch (profile) {
        .secure => .{
            .pow_bits = 26,
            .fri_config = try core.fri.FriConfig.init(0, 1, 70),
        },
        .smoke => .{
            .pow_bits = 0,
            .fri_config = try core.fri.FriConfig.init(0, 1, 3),
        },
    };
    const expected: u32 = if (profile == .secure) 96 else 3;
    if (config.securityBits() != expected)
        return error.InvalidPokemonBattleSecurity;
    return config;
}

test "Metal Pokemon battle chain is secure unless smoke is explicit" {
    try std.testing.expectEqual(
        SecurityProfile.secure,
        try parseOptions(&.{ "chain", "/corpus" }),
    );
    try std.testing.expectEqual(
        SecurityProfile.smoke,
        try parseOptions(&.{ "chain", "/corpus", "--smoke" }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        parseOptions(&.{ "chain", "/corpus", "--benchmark" }),
    );
}
