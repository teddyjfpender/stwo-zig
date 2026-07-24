//! Production Native CUDA CLI dispatch.

const std = @import("std");
const cli = @import("cli.zig");
const proof_route = @import("proof_route.zig");
const plonk_route = @import("plonk_route.zig");
const poseidon_route = @import("poseidon_route.zig");
const blake_route = @import("blake_route.zig");
const wide_route = @import("wide_route.zig");
const xor_route = @import("xor_route.zig");
const state_machine_route = @import("state_machine_route.zig");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);

    const parsed = cli.parse(process_args[1..]) catch |err| {
        try cli.writeUsage(std.fs.File.stderr().deprecatedWriter());
        return err;
    };
    switch (parsed) {
        .help => try cli.writeUsage(std.fs.File.stdout().deprecatedWriter()),
        .prove => |request| switch (request.air) {
            .wide_fibonacci => try proof_route.prove(
                wide_route,
                allocator,
                request,
            ),
            .xor => try proof_route.prove(
                xor_route,
                allocator,
                request,
            ),
            .plonk => try proof_route.prove(
                plonk_route,
                allocator,
                request,
            ),
            .blake => try proof_route.prove(
                blake_route,
                allocator,
                request,
            ),
            .poseidon => try proof_route.prove(
                poseidon_route,
                allocator,
                request,
            ),
            .state_machine => try proof_route.prove(
                state_machine_route,
                allocator,
                request,
            ),
        },
    }
}

test {
    _ = wide_route;
    _ = xor_route;
    _ = plonk_route;
    _ = blake_route;
    _ = poseidon_route;
    _ = state_machine_route;
}
