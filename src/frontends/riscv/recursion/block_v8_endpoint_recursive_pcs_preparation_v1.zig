//! Strategy-based shared parent verifier; no original equations duplicated.
const Family = @import("block_v8_endpoint_recursive_source_v1.zig").Family;
pub fn For(comptime family: Family) type {
    return With(@import("block_v8_endpoint_recursive_adapter_v1.zig").For(family));
}
pub fn With(comptime Adapter: type) type {
    return struct {
        // Real joined-original DEEP, FRI and root/nonce witness preparation. This is
        // one part of a recursive verifier: composition and public/global closure are
        // deliberately not represented as completed by these arithmetic witnesses.
        const std = @import("std");
        const Whole = Adapter.Original;
        const Profile = Adapter.Profile;
        const Deep = @import("air/blake3_native_deep.zig");
        const Fri = @import("air/blake3_native_fri.zig");
        const Roots = @import("air/blake3_execution_roots.zig");
        const Transcript = @import("air/blake3_native_transcript.zig");
        pub const Prepared = struct {
            deep: Deep.Prepared,
            fri: Fri.Prepared,
            roots: @import("air/blake3_native_root_nonce.zig").Prepared,
            pub const complete_recursive_verifier = false;
            pub fn deinit(self: *Prepared) void {
                self.roots.deinit();
                self.fri.deinit();
                self.deep.deinit();
                self.* = undefined;
            }
        };
        pub fn prepare(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture, transcript: *const Transcript.Planned) !Prepared {
            try profile.requireCapture(capture);
            return prepareInternal(a, profile, capture, transcript, null, null);
        }
        fn prepareInternal(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Whole.VerifiedCapture, transcript: *const Transcript.Planned, compiled_deep: ?*const @import("air/pcs_deep_circuit.zig").Circuit, compiled_fri: ?*const @import("air/fri_verifier_circuit.zig").Circuit) !Prepared {
            if (capture.proof.commitments.len != profile.shape.columns.len or !std.meta.eql(capture.proof.commitments[0], profile.fixed_root) or !std.meta.eql(transcript.end, capture.final_channel)) return error.UntrustedEndpointPcsPreparation;
            var inputs = try @import("pcs_arithmetic_capture.zig").Owned.init(a, profile.shape.deepProfile(), &capture.proof);
            errdefer inputs.deinit();
            var graph = if (compiled_deep) |g| try @import("air/compiled_pcs_graph_clone_v1.zig").deep(a, g) else try @import("air/pcs_deep_circuit.zig").build(a, profile.shape.deepProfile());
            errdefer graph.deinit();
            var evaluation = try graph.evaluate(a, inputs.inputs);
            errdefer evaluation.deinit();
            const deep = Deep.Prepared{ .inputs = inputs, .graph = graph, .evaluation = evaluation };
            var fri = if (compiled_fri) |g| try Fri.prepareCapturedWithGraph(a, &capture.proof, Adapter.epoch(profile).config, &deep, 1502, 1504, g) else try Fri.prepareCaptured(a, &capture.proof, Adapter.epoch(profile).config, &deep, 1502, 1504);
            errdefer fri.deinit();
            var scratch = std.heap.ArenaAllocator.init(a);
            defer scratch.deinit();
            var reads: std.ArrayList(@TypeOf(transcript.plan.fixed.root_reads[0])) = .empty;
            for (transcript.plan.fixed.root_reads) |read| if (read.source.circuit == @import("air/blake3_root_sources.zig").CIRCUIT) try reads.append(scratch.allocator(), read);
            var pcs = transcript.*;
            pcs.plan.fixed.root_reads = reads.items;
            var roots = try Roots.prepareCapturedExternalBounded(a, &capture.proof, profile.fixed_root, Adapter.epoch(profile).config, &pcs, Adapter.firstRoots(profile), profile.shape.columns.len);
            roots.external_key = true;
            roots.external_main = true;
            return .{ .deep = deep, .fri = fri, .roots = roots };
        }
    };
}
