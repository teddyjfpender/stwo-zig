//! Native four/ten-commitment fixed PCS ports from original trusted emitters.
//! A routing compiler accepts no values/capture/key and confers no admission.
//! The typed RAM/range entrypoint also independently authenticates its original
//! policy, shape and transcript. PAGE's transcript/context port stays separate.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const NativeProfile = @import("block_v5_native_fixed_pcs_profile_v1.zig");
const Word = @import("block_v5_word_recursive_fixed_v1.zig");
const Transcript = @import("block_v5_word_recursive_fixed_transcript_v1.zig");
const Plan = @import("air/blake3_transcript_plan.zig").Plan;
const Deep = @import("air/pcs_deep_circuit.zig");
const Fri = @import("air/fri_verifier_circuit.zig");
const Queries = @import("air/blake3_query_links.zig");
const Paths = @import("air/blake3_stark_paths.zig");
const Ports = @import("air/block_v5_recursive_parent_fixed_pcs_ports_v1.zig");
const Openings = @import("air/block_v5_recursive_parent_fixed_openings_v1.zig");
pub fn ForCommitments(comptime N: usize) type {
    if (N != 4 and N != 10) @compileError("native PCS requires the original four or ten commitment trees");
    return struct {
        pub const Owned = struct {
            const Self = @This();
            allocator: std.mem.Allocator,
            lease: ?*Budget,
            shape_id: [32]u8,
            transcript_id: [32]u8,
            queries: Queries.Prepared,
            paths: Paths.FixedShape,
            ports: *Ports.Owned,
            openings: *Openings.Owned,
            pub const fixed_setup_only = true;
            pub const complete_family_setup = false;
            /// Profile.validate must reconstruct original independent geometry.
            /// This structural compiler is not a received-plan authority API:
            /// typed family owners below establish transcript provenance.
            pub fn compile(a: std.mem.Allocator, profile: anytype, dg: *const Deep.Circuit, fg: *const Fri.Circuit, transcript: *const Plan) !*Self {
                if (@TypeOf(profile.*).commitment_trees != N) @compileError("native commitment profile mismatch");
                try profile.validate();
                try transcript.validate();
                try dg.validate();
                try fg.validate();
                if (!std.meta.eql(dg.profile_digest, profile.deepProfile().identityDigest()) or !std.meta.eql(fg.profile_digest, profile.friProfile().identityDigest())) return error.UntrustedNativeFixedPcsProfile;
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const self = try a.create(Self);
                errdefer a.destroy(self);
                var queries = try Queries.build(a, transcript.fixed.query_outputs, dg, fg, profile.config.fri_config.n_queries, profile.widths.len);
                errdefer queries.deinit();
                var paths = try Paths.compileFixedProfile(N, a, profile, &queries);
                errdefer paths.deinit();
                const ports = try Ports.compileProfile(N, a, profile, dg, fg, &queries);
                errdefer ports.deinit();
                const openings = try Openings.compileProfile(N, a, profile, dg, fg, &paths, &ports.projection);
                errdefer openings.deinit();
                try profile.validate();
                try transcript.validate();
                self.* = .{ .allocator = a, .lease = lease, .shape_id = profile.seal, .transcript_id = transcript.id, .queries = queries, .paths = paths, .ports = ports, .openings = openings };
                return self;
            }
            /// Rebuild every trusted fixed route from the independent profile
            /// and original transcript. A recomputed self identity cannot
            /// authorize mutated sources, multiplicities or root slots.
            pub fn validateAgainst(self: *const Self, profile: anytype, dg: *const Deep.Circuit, fg: *const Fri.Circuit, transcript: *const Plan) !void {
                if (!std.meta.eql(self.shape_id, profile.seal) or !std.meta.eql(self.transcript_id, transcript.id)) return error.UntrustedNativeFixedPcsPorts;
                const cold = try Self.compile(self.allocator, profile, dg, fg, transcript);
                defer cold.deinit();
                try equalRows(self.queries.queries, cold.queries.queries);
                try equalRows(self.queries.fri_derived, cold.queries.fri_derived);
                try equalRows(self.paths.metadata.g_rows, cold.paths.metadata.g_rows);
                try equalRows(self.paths.metadata.xor_rows, cold.paths.metadata.xor_rows);
                inline for (@import("air/blake3_nonhash_emission_v1.zig").slots) |slot| try equalRows(try self.paths.nonhash.rows(slot), try cold.paths.nonhash.rows(slot));
                if (self.paths.openings != cold.paths.openings or !std.meta.eql(self.paths.shape_id, cold.paths.shape_id) or self.paths.input_routes.len != cold.paths.input_routes.len) return error.UntrustedNativeFixedPcsPorts;
                for (self.paths.input_routes, cold.paths.input_routes) |actual, original| {
                    if (actual.tree != original.tree or actual.query != original.query or actual.payload != original.payload) return error.UntrustedNativeFixedPcsPorts;
                    try equalRows(actual.uses, original.uses);
                }
                inline for (.{ 11, 7 }) |slot| try equalRows(try self.ports.projection.rows.metadata(slot), try cold.ports.projection.rows.metadata(slot));
                try equalRows(self.ports.projection.bit_reads, cold.ports.projection.bit_reads);
                for (self.ports.projection.ports, cold.ports.projection.ports) |actual, original| {
                    if ((actual == null) != (original == null)) return error.UntrustedNativeFixedPcsPorts;
                    if (actual) |values| try equalRows(values, original.?);
                }
                if (!std.meta.eql(self.ports.shape_id, cold.ports.shape_id)) return error.UntrustedNativeFixedPcsPorts;
                inline for (.{ 12, 10 }) |slot| try equalRows(try self.ports.query_rows.metadata(slot), try cold.ports.query_rows.metadata(slot));
                try equalRows(try self.ports.answer_rows.metadata(12), try cold.ports.answer_rows.metadata(12));
                if (!std.meta.eql(self.openings.shape_id, cold.openings.shape_id)) return error.UntrustedNativeFixedPcsPorts;
                inline for (.{ 2, 10, 11, 16, 17, 12 }) |slot| try equalRows(try self.openings.rows.metadata(slot), try cold.openings.rows.metadata(slot));
            }
            pub fn deinit(self: *Self) void {
                const a = self.allocator;
                const lease = self.lease;
                self.openings.deinit();
                self.ports.deinit();
                self.paths.deinit();
                self.queries.deinit();
                a.destroy(self);
                if (lease) |owner| owner.destroy();
            }
        };
    };
}
pub fn ForWord(comptime family: @import("air/block_v5_word_recursive_shape_composition_v1.zig").Family) type {
    const Native = Word.ForFamily(family);
    const Profile = NativeProfile.ForWord(family);
    const TypedTranscript = Transcript.ForFamily(family);
    const Admitted = if (family == .ram_lanes) @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig").Prepared else @import("../prover/block_v5_range16_recursive_admission_v1.zig").Prepared;
    return struct {
        pub const Owned = ForCommitments(4).Owned;
        pub fn derive(a: std.mem.Allocator, native: *const Native.Owned, admitted: *const Admitted, expected: [32]u8, transcript: *const TypedTranscript.Owned) !*Owned {
            var profile = try Profile.derive(native, admitted, expected);
            try transcript.validateAgainst(admitted, expected, native.shape);
            const owned = try Owned.compile(a, &profile, &native.deep_graph, &native.fri_graph, &transcript.fixed);
            errdefer owned.deinit();
            try transcript.validateAgainst(admitted, expected, native.shape);
            try profile.validate();
            return owned;
        }
        pub fn validateAgainst(owned: *const Owned, native: *const Native.Owned, admitted: *const Admitted, expected: [32]u8, transcript: *const TypedTranscript.Owned) !void {
            var profile = try Profile.derive(native, admitted, expected);
            try transcript.validateAgainst(admitted, expected, native.shape);
            try owned.validateAgainst(&profile, &native.deep_graph, &native.fri_graph, &transcript.fixed);
            try transcript.validateAgainst(admitted, expected, native.shape);
            try profile.validate();
        }
    };
}
pub fn ForPage(comptime kind: @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig").Kind) type {
    const Native = @import("block_v5_memory_source_page_recursive_fixed_v1.zig").ForKind(kind);
    const Profile = NativeProfile.ForPage(kind);
    const Admitted = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind).Prepared;
    const Claims = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig").Claims;
    const TypedTranscript = @import("block_v5_memory_source_page_recursive_fixed_transcript_v1.zig").ForKind(kind);
    return struct {
        pub const Owned = ForCommitments(10).Owned;
        /// Only the native geometry/PCS ports are admitted here. PAGE's
        /// independently reconstructed prefix/public/context owner must still
        /// authenticate this routing plan before any complete key can be built.
        pub fn compileFromRouting(a: std.mem.Allocator, native: *const Native.Owned, admitted: *const Admitted, expected: [32]u8, claims: Claims, routing: *const Plan) !*Owned {
            var profile = try Profile.derive(native, admitted, expected, claims);
            return Owned.compile(a, &profile, &native.deep_graph, &native.fri_graph, routing);
        }
        /// Genuine original PAGE provenance. No proposed routing Plan can
        /// replace the independently reconstructed typed transcript owner.
        pub fn derive(a: std.mem.Allocator, native: *const Native.Owned, admitted: *const Admitted, expected: [32]u8, claims: Claims, transcript: *const TypedTranscript.Owned) !*Owned {
            var profile = try Profile.derive(native, admitted, expected, claims);
            try transcript.validateAgainst(admitted, expected, native, claims);
            const owned = try Owned.compile(a, &profile, &native.deep_graph, &native.fri_graph, &transcript.fixed);
            errdefer owned.deinit();
            try transcript.validateAgainst(admitted, expected, native, claims);
            try profile.validate();
            return owned;
        }
        pub fn validateAgainst(owned: *const Owned, native: *const Native.Owned, admitted: *const Admitted, expected: [32]u8, claims: Claims, transcript: *const TypedTranscript.Owned) !void {
            var profile = try Profile.derive(native, admitted, expected, claims);
            try transcript.validateAgainst(admitted, expected, native, claims);
            try owned.validateAgainst(&profile, &native.deep_graph, &native.fri_graph, &transcript.fixed);
            try transcript.validateAgainst(admitted, expected, native, claims);
            try profile.validate();
        }
        pub fn requireComplete(_: *const Owned) error{MissingPageFixedTranscriptAndSourceContext}!void {
            return error.MissingPageFixedTranscriptAndSourceContext;
        }
    };
}
fn equalRows(actual: anytype, expected: @TypeOf(actual)) !void {
    if (actual.len != expected.len) return error.UntrustedNativeFixedPcsPorts;
    for (actual, expected) |a, e| if (!std.meta.eql(a, e)) return error.UntrustedNativeFixedPcsPorts;
}
