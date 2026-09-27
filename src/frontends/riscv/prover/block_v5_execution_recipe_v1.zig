//! One independently selected native/caller/register recipe. A source choice
//! never overrides the executable caller AIR or permits mixed base recipes.
const std = @import("std");
const Circuit = @import("ethereum_circuit_profile_v1.zig").CircuitProfileV1;
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Ethereum = @import("../air/guest_precompile/ethereum_statement.zig");
const Statement = @import("blake3_ethereum_sha_statement.zig").Statement;

pub const Recipe = enum(u32) {
    custody_v2 = 0,
    local_zero_v1 = 1,

    pub fn nativeVersion(self: Recipe) u32 {
        return @intFromEnum(self);
    }
    pub fn callerProfile(self: Recipe) Circuit {
        return switch (self) {
            .custody_v2 => .ethereum_v5,
            .local_zero_v1 => .ethereum_local_zero_v1,
        };
    }
    pub fn callerProtocolVersion(self: Recipe) u32 {
        return switch (self) {
            .custody_v2 => 2,
            .local_zero_v1 => 3,
        };
    }
    pub fn windowVersion(self: Recipe) u32 {
        return switch (self) {
            .custody_v2 => 1,
            .local_zero_v1 => 2,
        };
    }
    pub fn requireMode(self: Recipe, register_custody_mode: u32) !void {
        if (register_custody_mode > 1 or (self == .local_zero_v1 and register_custody_mode != 1)) return error.UntrustedV5ExecutionRecipeMode;
    }
    pub fn requireNative(self: Recipe, shape: *const Shape) !void {
        if (shape.x0_local_custody_version != self.nativeVersion()) return error.MixedV5ExecutionRecipe;
        if (self == .local_zero_v1) try @import("../air/x0_local_custody_v1.zig").requirePublic(&shape.public_data);
    }
    pub fn requireCaller(self: Recipe, statement: *const Statement, total_steps: u32) !void {
        try statement.ethereum.validateGeometryWithCircuitProfileV1(total_steps, self.callerProfile());
        try statement.sha.validateForRecipe(total_steps, self == .local_zero_v1);
        if (try std.math.add(u32, statement.ethereum.counts.external_retirements, statement.sha.call_count) > total_steps) return error.InvalidExternalRetirementCount;
    }
    pub fn requireWindowVersion(self: Recipe, version: u32) !void {
        if (version != self.windowVersion()) return error.MixedV5ExecutionRecipe;
    }
    pub fn requireCompiled(self: Recipe) !void {
        if (self != canonical) return error.UnsupportedV5ExecutableRecipe;
    }
    pub fn mixNewSourceIdentity(self: Recipe, channel: anytype) void {
        if (self == .local_zero_v1) {
            channel.mixU32s(&.{ 0x42355250, 1, @intFromEnum(self), @intFromEnum(self.callerProfile()), self.callerProtocolVersion(), self.windowVersion() }); // B5RP
            channel.mixRoot(Ethereum.localZeroSemanticDigest());
            channel.mixRoot(@import("../air/x0_local_custody_v1.zig").abiId());
        }
    }
};

/// Activation changes this one selector only after native/caller/staging and
/// whole receiver body qualification. Production currently retains profile2.
/// Zig tests require an explicit policy test runner: their executable root is
/// the runner, not the tested module. Qualification roots additionally assert
/// their independent expected policy, so omitted/wrong runners fail closed.
pub const canonical: Recipe = if (@hasDecl(@import("root"), "BLOCK_V5_EXECUTION_RECIPE")) switch (@as(u32, @field(@import("root"), "BLOCK_V5_EXECUTION_RECIPE"))) {
    0 => .custody_v2,
    1 => .local_zero_v1,
    else => @compileError("unsupported independently selected block-v5 execution recipe"),
} else .custody_v2;

pub fn fromCallerProfile(profile: Circuit) !Recipe {
    return switch (profile) {
        .ethereum_v5 => .custody_v2,
        .ethereum_local_zero_v1 => .local_zero_v1,
        else => error.UnsupportedV5ExecutionRecipe,
    };
}
