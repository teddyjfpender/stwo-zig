//! Actual independent setup and canonical receiver/forest integration bodies.
//! The exported marker retains function pointers and invokes no PCS/proof body.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Derive = @import("prover/block_v5_cpu_recursive_template_derivation_v1.zig");
const Cache = @import("prover/block_v5_word_expected_setup_cache_v1.zig");
const Definitions = @import("prover/block_v5_recursive_provider_definition_v1.zig");
const Profile = @import("recursion/blake3_execution_parent_protocol.zig").Profile;
fn Bodies(comptime family: Cache.Family) type {
    const D = Definitions.ForFamily(family);
    const C = Cache.ForFamily(family, Cpu);
    return struct {
        fn independent(a: std.mem.Allocator, admitted: *const D.Prepared, profile: Profile, capacity: u32) anyerror!void {
            var expected = try Derive.providerPolicyForBackend(family, Cpu, a, admitted, profile, capacity);
            defer expected.deinit();
        }
        fn original(a: std.mem.Allocator, proof: *const D.Native.Proof, admitted: *const D.Prepared, profile: Profile, capacity: u32) anyerror!void {
            var expected = try Derive.provider(family, a, proof, admitted, profile, capacity);
            defer expected.deinit();
        }
        fn keep() void {
            inline for (.{ &independent, &original, &C.get, &C.init, &C.deinit }) |body| std.mem.doNotOptimizeAway(body);
        }
    };
}
pub export fn stwo_word_expected_setup_body_gate() void {
    @setEvalBranchQuota(100_000);
    Bodies(.ram_lanes).keep();
    Bodies(.range16).keep();
    inline for (.{
        &@import("prover/block_v5_cpu_recursive_receive_v1.zig").verify,
        &@import("prover/block_v5_ram_range_forest_policy_owner_v1.zig").ForBackend(Cpu).build,
        &@import("prover/block_v5_cpu_final_job_v1.zig").ForBackend(Cpu).build,
        &@import("prover/block_v5_cpu_recursive_publication_v1.zig").Session.create,
        &@import("prover/block_v5_cpu_recursive_publication_v1.zig").Session.deinit,
        &@import("prover/block_v5_cpu_driver_common_v1.zig").ForCapacity(true).run,
    }) |body| std.mem.doNotOptimizeAway(body);
}
