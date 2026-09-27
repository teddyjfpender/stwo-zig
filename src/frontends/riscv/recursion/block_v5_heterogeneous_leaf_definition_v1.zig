//! Genuine independently selected leaf stacks. No proof-carried family selector.
const std = @import("std");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
pub fn ForSubtype(comptime subtype: Coverage.Subtype) type {
    if (subtype == .native_fused_v2) @compileError("NativeV3 fusion has no genuine recursive adapter; it cannot relabel B5CT fusion");
    const provider: ?@import("../prover/block_v5_recursive_provider_family_v1.zig").Family = switch (subtype) {
        .ram_lanes_v1 => .ram_lanes,
        .range16_v1 => .range16,
        .rom_v1 => .program_table,
        .six_table_lookup_v1 => .native_lookup,
        else => null,
    };
    if (provider) |family| return @import("../prover/block_v5_recursive_provider_definition_v1.zig").ForFamily(family);
    return struct {
        pub const KIND: Coverage.Kind = switch (subtype) {
            .native_v3, .capacity_v1 => .native_arithmetic,
            .capacity_fused_v1 => .native_fused,
            .caller_family11_v1 => .caller_arithmetic,
            .caller_fused_v1 => .caller_fused,
            else => unreachable,
        };
        pub const Prepared = switch (subtype) {
            .native_v3 => @import("../prover/block_v5_native_recursive_admission_v3.zig").Prepared,
            .capacity_v1 => @import("../prover/block_v5_native_capacity_recursive_admission_v1.zig").Prepared,
            .capacity_fused_v1 => @import("../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig").Prepared,
            .caller_family11_v1 => @import("../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig").Prepared,
            .caller_fused_v1 => @import("../prover/block_v5_caller_fused_recursive_admission_v1.zig").Prepared,
            else => unreachable,
        };
        pub const Bus = switch (subtype) {
            .native_v3 => @import("block_v5_recursive_public_bus_v1.zig"),
            .capacity_v1 => @import("block_v5_capacity_recursive_public_bus_v1.zig"),
            .capacity_fused_v1 => @import("block_v5_native_capacity_fused_recursive_public_bus_v1.zig"),
            .caller_family11_v1 => @import("block_v5_caller_arithmetic_recursive_public_bus_v1.zig"),
            .caller_fused_v1 => @import("block_v5_caller_fused_recursive_public_bus_v1.zig"),
            else => unreachable,
        };
        pub const Protocol = switch (subtype) {
            .native_v3 => @import("block_v5_reusable_native_parent_protocol_v1.zig"),
            .capacity_v1 => @import("block_v5_reusable_capacity_parent_protocol_v1.zig"),
            .capacity_fused_v1 => @import("block_v5_reusable_native_capacity_fused_parent_protocol_v1.zig"),
            .caller_family11_v1 => @import("block_v5_reusable_caller_arithmetic_parent_protocol_v1.zig"),
            .caller_fused_v1 => @import("block_v5_reusable_caller_fused_parent_protocol_v1.zig"),
            else => unreachable,
        };
        pub const Receiver = switch (subtype) {
            .native_v3 => @import("block_v5_reusable_native_leaf_v1.zig"),
            .capacity_v1 => @import("block_v5_capacity_recursive_leaf_v1.zig"),
            .capacity_fused_v1 => @import("block_v5_native_capacity_fused_recursive_leaf_v1.zig"),
            .caller_family11_v1 => @import("block_v5_caller_arithmetic_recursive_leaf_v1.zig"),
            .caller_fused_v1 => @import("block_v5_caller_fused_recursive_leaf_v1.zig"),
            else => unreachable,
        };
        pub const Open = switch (subtype) {
            .native_v3 => @import("../prover/block_v5_native_execution_proof_v3.zig").OpenReceipt,
            .capacity_v1 => @import("../prover/block_v5_native_capacity_proof_v1.zig").OpenReceipt,
            .capacity_fused_v1 => struct {
                projections: []const @import("../prover/block_v5_native_capacity_fused_proof_v1.zig").Claim,
                memory: []const @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim,
            },
            .caller_family11_v1 => struct {
                receipt: @import("../prover/block_v5_precompile_family_proof_v1.zig").OpenReceipt,
                claims: @import("../prover/blake3_ethereum_sha_profile.zig").ExtensionClaim,
            },
            .caller_fused_v1 => @import("../prover/block_v5_caller_fused_proof_v1.zig").ClaimFrames,
            else => unreachable,
        };
        pub fn values(a: std.mem.Allocator, prepared: *const Prepared, open: Open) !Bus.Values {
            return switch (subtype) {
                .native_v3 => Bus.Values.fromNative(a, prepared, open),
                .capacity_v1 => Bus.Values.fromCapacity(a, prepared, open),
                .capacity_fused_v1 => Bus.Values.init(a, prepared, .{ .projection = open.projections, .memory = open.memory }),
                .caller_family11_v1 => Bus.Values.fromCaller(prepared, open.receipt, open.claims),
                .caller_fused_v1 => Bus.Values.init(a, prepared, open),
                else => unreachable,
            };
        }
        pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, id: [32]u8, wires: []const Bus.Wire, prepared: *const Prepared, open: Open) !Receiver.OpenEquation {
            return switch (subtype) {
                .native_v3, .capacity_v1 => Receiver.verify(a, bytes, key, id, wires, prepared, open),
                .capacity_fused_v1 => Receiver.verify(a, bytes, key, id, wires, prepared, open.projections, open.memory),
                .caller_family11_v1 => Receiver.verify(a, bytes, key, id, wires, prepared, open.receipt, open.claims),
                .caller_fused_v1 => Receiver.verify(a, bytes, key, id, wires, prepared, open),
                else => unreachable,
            };
        }
    };
}
pub fn kindRuntime(subtype: Coverage.Subtype) Coverage.Kind {
    return switch (subtype) {
        .native_v3, .capacity_v1 => .native_arithmetic,
        .native_fused_v2, .capacity_fused_v1 => .native_fused,
        .caller_family11_v1 => .caller_arithmetic,
        .caller_fused_v1 => .caller_fused,
        .ram_lanes_v1 => .ram_lanes,
        .range16_v1 => .range16,
        .rom_v1 => .rom,
        .six_table_lookup_v1 => .native_lookup,
    };
}

pub fn kind(comptime subtype: Coverage.Subtype) Coverage.Kind {
    return kindRuntime(subtype);
}
