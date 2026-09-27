//! Compile actual production paths; the marker calls no prover or receiver.
const std = @import("std");
const Providers = @import("prover/block_v5_recursive_provider_definition_v1.zig");
const Derive = @import("prover/block_v5_cpu_recursive_template_derivation_v1.zig");
const Profile = @import("recursion/blake3_execution_parent_protocol.zig").Profile;
fn ProviderBody(comptime family: @import("prover/block_v5_recursive_provider_family_v1.zig").Family) type {
    const D = Providers.ForFamily(family);
    return struct {
        fn run(a: std.mem.Allocator, proof: *const D.Native.Proof, prepared: *const D.Prepared, profile: Profile, capacity: u32) anyerror!void {
            var expected = try Derive.provider(family, a, proof, prepared, profile, capacity);
            defer expected.deinit();
        }
    };
}
pub export fn stwo_cpu_recursive_publication_body_gate() void {
    @import("block_v5_cpu_capacity_driver_codegen.zig").stwo_capacity_cpu_driver_body_gate();
    const Sources = @import("prover/block_v5_cpu_recursive_sources_v1.zig").Owner;
    const Session = @import("prover/block_v5_cpu_recursive_publication_v1.zig").Session;
    inline for (.{ &Sources.create, &Sources.require, &Sources.deinit, &Session.create, &Session.deinit, &Session.callerOptions, &Session.requirePublished, &Session.writeOpenManifest, &Derive.arithmetic, &Derive.callerFused, &Derive.nativeFused, &@import("prover/block_v5_cpu_recursive_receive_v1.zig").verify }) |function|
        std.mem.doNotOptimizeAway(function);
    inline for ([_]@import("prover/block_v5_recursive_provider_family_v1.zig").Family{ .range16, .ram_lanes, .program_table, .native_lookup }) |family|
        std.mem.doNotOptimizeAway(&ProviderBody(family).run);
}
