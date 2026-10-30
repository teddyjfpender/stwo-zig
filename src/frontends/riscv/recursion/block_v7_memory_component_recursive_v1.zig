//! Finite adapters for the unchanged four separate v7 memory proof families.
//! They share PCS/parent plumbing, not family identities or global authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const K = @import("air/block_v7_memory_composition_v1.zig");
const Source = @import("../prover/block_v7_memory_source_v1.zig");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
pub fn For(comptime family: K.Family) type {
    return struct {
        const D = @This();
        const tag: u32 = 0x42378000 + 256 * @as(u32, @intFromEnum(family));
        pub const Profile = @import("block_v7_memory_component_profile_v1.zig").For(family);
        pub const Capture = Profile;
        pub const Equation = struct {
            const Compiler = @import("air/block_v7_memory_shape_composition_v1.zig").For(family);
            pub const Compiled = Compiler.Compiled;
            pub fn compile(a: std.mem.Allocator, profile: *const Profile.Owned) !Compiled {
                try profile.validate();
                return Compiler.compile(a, profile.shape);
            }
        };
        pub const Inputs = struct {
            pub const publicInputs = Profile.publicInputs;
            pub fn composition(a: std.mem.Allocator, profile: *const Profile.Owned, compiled: *const Equation.Compiled, captured: *const core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher)) ![]Q {
                if (captured.sampled_values.len != try profile.shape.sampleCount()) return error.InvalidV7MemoryComponentInputs;
                const public = try publicInputs(a, profile);
                defer a.free(public);
                const draws = try @import("air/block_v7_memory_joint_inputs_v1.zig").challenges(a, profile.input.epoch);
                const out = try a.alloc(Q, compiled.sources.len);
                errdefer a.free(out);
                for (compiled.sources, out) |source, *value| value.* = switch (source) {
                    .sample => |i| if (i < captured.sampled_values.len) captured.sampled_values[i] else return error.InvalidV7MemoryComponentInputs,
                    .public_input => |i| if (i < public.len) public[i] else return error.InvalidV7MemoryComponentInputs,
                    .challenge => |i| if (i < draws.len) draws[i] else return error.InvalidV7MemoryComponentInputs,
                    .composition => captured.composition_randomness,
                    .oods => captured.oods_seed,
                    else => return error.InvalidV7MemoryComponentInputs,
                };
                return out;
            }
        };
        pub const Statement = struct {
            const Frames = @import("air/block_v5_recursive_statement_frames_v1.zig");
            pub const Statement = Frames.Statement;
            pub const PUBLIC_CIRCUIT: u32 = 4_200_071 + @as(u32, @intFromEnum(family));
            pub fn init(a: std.mem.Allocator, profile: *const Profile.Owned) !Frames.Statement {
                var b = Frames.Builder{ .allocator = a, .max_felts = Profile.planes };
                defer b.deinit();
                const epoch = try b.digestWords(profile.input.epoch.digest);
                try Source.recordAfterChallenges(&b, try Profile.entry(profile.input), &profile.input.sums);
                try b.check();
                if (b.root_count != 3) return error.InvalidV7MemoryComponentStatement;
                const roots = [3]u32{ b.root_offsets[1], b.root_offsets[2], 0 };
                const claims = try b.steps.toOwnedSlice(a);
                errdefer a.free(claims);
                const words = try b.data.toOwnedSlice(a);
                errdefer a.free(words);
                const felts = try b.fields.toOwnedSlice(a);
                return .{ .allocator = a, .words = words, .felts = felts, .first = &.{}, .claims = claims, .sealed_offset = epoch, .roots_offset = roots };
            }
        };
        pub const Public = struct {
            const Definition = struct {
                pub const Admission = struct {
                    pub const Prepared = Profile.Owned;
                };
                pub const Statement = D.Statement;
                pub const IDENTITY_TAG: u32 = tag + 0x49;
                pub const SCHEDULE_TAG: u32 = tag + 0x57;
            };
            pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamily(Definition);
            pub const Values = API.Values;
            pub const Wire = API.Wire;
            pub const supply = API.supply;
            pub const scheduleDigest = API.scheduleDigest;
            pub fn reconstruct(a: std.mem.Allocator, profile: *const Profile.Owned) !Values {
                try profile.validate();
                var statement = try Statement.init(a, profile);
                errdefer statement.deinit();
                const public = try Profile.publicInputs(a, profile);
                errdefer a.free(public);
                const result = Values{ .allocator = a, .template = profile.seal, .statement = statement, .public = public, .roots_count = 2 };
                try result.validate();
                return result;
            }
            pub fn requireSameFrame(got: Values, expected: Values) !void {
                try got.validate();
                try expected.validate();
                if (!std.meta.eql(got.template, expected.template) or got.roots_count != expected.roots_count or !std.meta.eql(got.statement.roots_offset, expected.statement.roots_offset) or got.statement.sealed_offset != expected.statement.sealed_offset or !std.mem.eql(u32, got.statement.words, expected.statement.words) or got.statement.felts.len != expected.statement.felts.len or got.public.len != expected.public.len or got.statement.first.len != expected.statement.first.len or got.statement.claims.len != expected.statement.claims.len) return error.UntrustedV7MemoryComponentFrame;
                for (got.statement.felts, expected.statement.felts) |x, y| if (!x.eql(y)) return error.UntrustedV7MemoryComponentFrame;
                for (got.public, expected.public) |x, y| if (!x.eql(y)) return error.UntrustedV7MemoryComponentFrame;
                for (got.statement.first, expected.statement.first) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedV7MemoryComponentFrame;
                for (got.statement.claims, expected.statement.claims) |x, y| if (!std.meta.eql(x, y)) return error.UntrustedV7MemoryComponentFrame;
            }
        };
        pub const Transcript = struct {
            const Recorder = @import("air/blake3_native_recorder.zig");
            const Sink = @import("air/blake3_fixed_operation_recorder_v1.zig");
            const Shared = @import("air/blake3_native_transcript.zig");
            fn begin(r: anytype, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
                r.mixU32s(&.{ profile.input.epoch.sharedTag(), E.VERSION, 2 });
                r.mixPublicRoot(.{ .circuit = Statement.PUBLIC_CIRCUIT, .first_wire = statement.sealed_offset }, profile.input.epoch.digest);
                try r.skipCommittedRoots(2);
            }
            pub fn prefixFixed(a: std.mem.Allocator, r: *Sink.Recorder, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
                try begin(r, profile, statement);
                try @import("air/block_v7_epoch_transcript_v1.zig").fixed(a, r);
                try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
            }
            pub fn prefix(a: std.mem.Allocator, r: *Recorder.Recorder, profile: *const Profile.Owned, statement: *const Statement.Statement) !void {
                if (!r.universal_relations or r.root_count != 0 or r.relation_count != 0) return error.InvalidV7MemoryComponentTranscript;
                try begin(r, profile, statement);
                try @import("air/block_v7_epoch_transcript_v1.zig").live(a, r);
                try statement.recordAt(r, statement.claims, Statement.PUBLIC_CIRCUIT);
                try r.check();
                const drawn = try profile.input.epoch.draw(a);
                const expected = try Source.channel(&drawn, try Profile.entry(profile.input), &profile.input.sums);
                if (r.relation_count != 53 or r.root_count != 2 or !std.meta.eql(expected, r.native)) return error.InvalidV7MemoryComponentTranscript;
            }
            pub fn planReplay(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Profile.VerifiedCapture, capacity: u32) !Shared.Planned {
                if (capacity == 0 or capture.proof.commitments.len != 4 or !std.meta.eql(capture.roots, profile.input.roots) or !std.meta.eql(capture.sums, profile.input.sums) or !std.meta.eql(capture.profile, profile.seal)) return error.InvalidV7MemoryComponentTranscript;
                var arena = std.heap.ArenaAllocator.init(a);
                var owned = true;
                defer if (owned) arena.deinit();
                const temp = arena.allocator();
                var statement = try Statement.init(temp, profile);
                defer statement.deinit();
                var r = Recorder.Recorder{ .a = temp, .universal_relations = true };
                try prefix(temp, &r, profile, &statement);
                r.mixRoot(capture.proof.commitments[2]);
                try r.check();
                var result = try Shared.finishReplay(a, &arena, &r, &capture.proof, profile.config, capacity);
                owned = false;
                errdefer result.deinit();
                if (!std.meta.eql(result.end, capture.final_channel)) return error.InvalidV7MemoryComponentTranscript;
                return result;
            }
        };
        pub const Fixed = @import("block_v7_word_family_fixed_v1.zig").For(D);
        pub const FixedTranscript = @import("block_v7_word_family_fixed_transcript_v1.zig").For(D);
        pub const Preparation = @import("block_v7_word_family_preparation_v1.zig").For(D);
        pub const FixedRoster = @import("block_v7_word_family_fixed_roster_v1.zig").For(D);
        pub const Protocol = @import("block_v7_word_family_protocol_v1.zig").For(Public, tag);
        /// An authenticated OPEN component. Only the complete job receiver may
        /// combine all RAM windows and initialization/range/terminal providers.
        pub const Receiver = struct {
            pub const Verified = struct {
                equation: @import("blake3_native_parent_verifier.zig").Verified,
                sums: [Profile.planes]Q,
                pub fn deinit(self: *@This()) void {
                    self.equation.deinit();
                    self.* = undefined;
                }
            };
            pub fn verify(a: std.mem.Allocator, bytes: []const u8, independent: *const Profile.Owned, key: Protocol.Key, wires: []const Public.Wire) !Verified {
                try @import("block_v7_receiver_security_v1.zig").require(key.config, independent.config, independent.input.epoch.config);
                try Profile.requireFixedRoot(@import("stwo_cpu_backend").CpuBackend, a, independent);
                var values = try Public.reconstruct(a, independent);
                defer values.deinit();
                const expected = [_]Protocol.Bus.Expected{.{ .profile = independent.seal, .epoch = independent.input.epoch.digest, .roots = independent.input.roots }};
                const admission = try Protocol.Admission.init(key, try key.identity(), wires, .{ .children = &.{values} }, &expected);
                const Parent = @import("blake3_execution_parent_proof.zig");
                var decoded = try Parent.codec.decode(a, bytes, &admission);
                var equation = try Parent.verify(&decoded, &admission);
                errdefer equation.deinit();
                try equation.validate(&admission, try key.identity());
                return .{ .equation = equation, .sums = independent.input.sums };
            }
        };
    };
}
