pub const runtime = @import("runtime.zig");
pub const arena_plan = @import("arena_plan.zig");
pub const commit_backend = @import("commit_backend.zig");
pub const merkle_tree = @import("merkle_tree.zig");
pub const prover_engine = @import("prover_engine.zig");
pub const recovery = @import("recovery.zig");
pub const protocol_recipes = @import("protocol_recipes.zig");
pub const shared_runtime = @import("shared_runtime.zig");
pub const telemetry = @import("telemetry.zig");
pub const commit_policy = @import("commit_policy.zig");
pub const source_contract = @import("source_contract.zig");
pub const riscv_polynomial_codegen = struct {
    pub const base = @import("runtime/base_polynomial_codegen.zig");
    pub const lookup = @import("runtime/lookup_polynomial_codegen.zig");
    pub const lookup_v2 = @import("runtime/lookup_polynomial_v2_codegen.zig");
    pub const lookup_v2_owner = @import("runtime/lookup_polynomial_v2_owner.zig");
    pub const aot = @import("runtime/riscv_polynomial_aot_codegen.zig");
    pub const source = @embedFile("shaders/core/riscv_polynomials.metal");
};
pub const recipes = struct {
    pub const relation = @import("recipes/relation.zig");
};
pub const shaders = struct {
    pub const manifest = @import("shaders/manifest.zig");
};
pub const Runtime = runtime.Runtime;
pub const Tree = runtime.Tree;
pub const MetalMerkleTree = merkle_tree.MetalMerkleTree;
pub const MetalCommitBackend = commit_backend.MetalCommitBackend;
pub const MetalProverEngine = prover_engine.MetalProverEngine;
pub const PlainMetalProverEngine = prover_engine.PlainMetalProverEngine;

test "api signature: Metal backend satisfies the declared capability contract" {
    comptime @import("stwo_backend_contracts").assertBackend(MetalCommitBackend);
}

test {
    _ = @import("shaders/manifest_test.zig");
}
