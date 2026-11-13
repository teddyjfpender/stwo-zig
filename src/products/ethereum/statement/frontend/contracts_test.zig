const recursion = @import("stwo_riscv_frontend").recursion;

test "api invariant: native and product VM authority bindings preserve canonical records" {
    try @import("std").testing.expect(@import("rv64/ethereum_services/candidate_services.zig").mulAddMod == @import("stwo_riscv_rv64").service_calls.reference_crypto.mulAddMod);
    const std = @import("std");
    const native = recursion.vm_air_profile_v2;
    const product = @import("recursion/ethereum_vm_air_profile_v2.zig");
    const Selector = @TypeOf(@as(native.ProfileV2, undefined).circuit_profile);
    try std.testing.expect(@typeInfo(Selector).@"enum".tag_type == u16);
    try std.testing.expectEqual(@as(usize, 1), @typeInfo(Selector).@"enum".fields.len);
    try std.testing.expectEqual(@as(u16, 0), @intFromEnum(Selector.legacy_v4));
    try std.testing.expect(@TypeOf(@as(product.ProfileV2, undefined).circuit_profile) == @import("stwo_riscv_air_lang").physical_profile.CircuitProfileV1);
    try std.testing.expect(native.ProfileV2 != product.ProfileV2);
    try std.testing.expect(native.EntryV2 == product.EntryV2 and native.TreeSpanV2 == product.TreeSpanV2 and native.InputProfileV2 == product.InputProfileV2);
    const Support = recursion.vm_composition_graph_support_v2;
    try std.testing.expect(Support.ForExtension(null) == Support.ForExtension(null));
    const no_extension = @TypeOf(@as(Support.ForExtension(null).SampleLayoutV2, undefined).extension);
    try std.testing.expect(no_extension == void);
    try std.testing.expect(@import("recursion/ethereum_vm_composition_graph_base.zig").Result == recursion.vm_composition_graph_base_v2.Result);
    const geometry = recursion.vm_composition_base_geometry_v2;
    const compiler = recursion.vm_selected_lookup_compiler_v2;
    try std.testing.expect(@TypeOf(geometry.ForProfile(product.ProfileV2).init) != @TypeOf(geometry.ForProfile(native.ProfileV2).init));
    try std.testing.expect(@TypeOf(compiler.ForProfile(product.ProfileV2).init) != @TypeOf(compiler.ForProfile(native.ProfileV2).init));
    const hooks = @import("testing.zig");
    const native_hooks = @import("stwo_riscv_frontend").testing;
    inline for (@typeInfo(native_hooks).@"struct".decls) |declaration| {
        try std.testing.expect(@hasDecl(hooks, declaration.name));
        try std.testing.expect(@field(hooks, declaration.name) == @field(native_hooks, declaration.name));
    }
    try std.testing.expect(hooks.EthereumCombinedCandidateExecutionSessionV1 == @import("runner/segment_session.zig").EthereumCombinedCandidateExecutionSessionV1);
    try std.testing.expect(hooks.ethereum_candidate_execution_capability_v1 == @import("runner/guest_precompile/ethereum_candidate_execution_capability.zig"));
    try std.testing.expect(!@hasDecl(native_hooks, "EthereumCombinedCandidateExecutionSessionV1"));
    try std.testing.expect(!@hasDecl(native_hooks, "ethereum_candidate_execution_capability_v1"));
    const product_air = @import("rv64/air.zig");
    const native_air = @import("stwo_riscv_frontend").rv64_air;
    try std.testing.expect(product_air.memory.image.Initial == native_air.memory.image.Initial);
    try std.testing.expect(product_air.memory.image.snapshot == native_air.memory.image.snapshot);
    try std.testing.expect(@hasDecl(product_air.memory.image, "fromEthereumElf"));
    try std.testing.expect(!@hasDecl(native_air.memory.image, "fromEthereumElf"));
    try std.testing.expect(@import("recursion/mod.zig").proof_ingress.Error == recursion.proof_ingress.Error);
    try std.testing.expect(@hasDecl(@import("recursion/mod.zig").proof_ingress, "preflightShapeV2WithCircuitProfileV1"));
    try std.testing.expect(!@hasDecl(recursion.proof_ingress, "preflightShapeV2WithCircuitProfileV1"));
}
