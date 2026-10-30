//! Canonical joint composition operands from admitted metadata and physical
//! claims. This is not a verifier-success receipt; the graph proves equations.
//! Finite protocol variants share implementation; window mode is a distinct key.
pub fn ForMode(comptime window: bool) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const Q = core.fields.qm31.QM31;
        const Profile = @import("../block_v7_memory_joint_fixed_profile_v1.zig").ForMode(window);
        const K = if (window) @import("block_v7_window_memory_kernels_v1.zig") else @import("block_v7_memory_composition_v1.zig");
        const E = @import("../../prover/block_v7_execution_epoch_v1.zig");
        pub fn publicInputs(a: std.mem.Allocator, profile: *const Profile.Owned) ![]Q {
            const result = try a.alloc(Q, try profile.publicCount());
            errdefer a.free(result);
            const halt = if (window) try profile.input.policy.window.?.nonhaltConstants() else try @import("../../prover/block_v7_halt_algebra_v1.zig").derive(profile.input.policy.terminal);
            var at: usize = 0;
            for (profile.input.claims.ram) |claim| {
                const values = try K.ramPublic(claim.geometry, claim.sums, halt);
                @memcpy(result[at..][0..values.len], &values);
                at += values.len;
            }
            inline for (if (window) .{ "interval", "range16" } else .{ "interval", "range16", "terminal" }) |name| {
                const values = @field(profile.input.claims, name);
                @memcpy(result[at..][0..values.len], &values);
                at += values.len;
            }
            if (at != result.len) return error.InvalidJointMemoryPublicShape;
            return result;
        }
        pub fn challenges(a: std.mem.Allocator, epoch: E.Epoch) ![106]Q {
            const drawn = try epoch.draw(a);
            var out: [106]Q = undefined;
            for (drawn.word.universal_prefix.elements, 0..) |element, i| {
                out[2 * i] = element.z;
                out[2 * i + 1] = element.alpha;
            }
            inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
                out[94 + 2 * i] = @field(drawn.word, name).z;
                out[95 + 2 * i] = @field(drawn.word, name).alpha;
            }
            var ch = epoch.sharedChannel();
            _ = try @import("../../prover/block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &ch);
            ch.mixU32s(&.{ 0x4237494e, E.VERSION, 6 });
            out[104] = ch.drawSecureFelt();
            out[105] = ch.drawSecureFelt();
            if (!std.meta.eql(ch, drawn.channel)) return error.InvalidJointMemoryChallenges;
            return out;
        }
        pub fn composition(a: std.mem.Allocator, profile: *const Profile.Owned, compiled: *const @import("block_v7_memory_joint_composition_v1.zig").ForMode(window).Compiled, captured: *const core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher)) ![]Q {
            if (captured.sampled_values.len != try profile.sampleCount() or compiled.sources.len != compiled.circuit.input_count) return error.InvalidJointMemoryInputs;
            const public = try publicInputs(a, profile);
            defer a.free(public);
            const draws = try challenges(a, profile.input.epoch);
            const out = try a.alloc(Q, compiled.sources.len);
            errdefer a.free(out);
            for (compiled.sources, out) |source, *value| value.* = switch (source) {
                .sample => |i| if (i < captured.sampled_values.len) captured.sampled_values[i] else return error.InvalidJointMemoryInputs,
                .public_input => |i| if (i < public.len) public[i] else return error.InvalidJointMemoryInputs,
                .challenge => |i| if (i < draws.len) draws[i] else return error.InvalidJointMemoryInputs,
                .composition => captured.composition_randomness,
                .oods => captured.oods_seed,
                else => return error.InvalidJointMemoryInputs,
            };
            return out;
        }
    };
}
