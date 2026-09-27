//! Authentic compact PAGE parent source. Fresh and independent job policy must
//! outlive this source. Only PAGE aggregate equations are closed; endpoint and
//! transition/global compensation still require their genuine child verifiers.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Base = @import("blake3_execution_parent_protocol.zig");
const Norm = @import("block_v5_memory_source_page_forest_normalizer_v1.zig");
const Term = @import("block_v5_open_child_frames_v2.zig").Term;
pub const PUBLIC_CIRCUIT: u32 = 4_300_302;
pub const Coordinate = struct { first_cell: u32, word_count: u32 };
/// One original implementation for strict or summary-only fresh custody.
/// Receiver selection is static; all admission, normalization and claim checks
/// remain in this body. No runtime branch can bypass a descendant verifier.
pub fn ForReceiver(comptime Receiver: type) type {
    return struct {
        pub const Source = SourceImpl;
        const SourceImpl = struct {
            allocator: std.mem.Allocator,
            owner: ?*Budget,
            fresh: *const Receiver.Fresh,
            terms: []Term,
            normal: Norm.Normalized,
            pub const complete_source_authority = false;
            pub const complete_block_authority = false;
            pub fn init(a: std.mem.Allocator, fresh: *const Receiver.Fresh) !SourceImpl {
                try fresh.validate();
                const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
                errdefer if (lease) |owner| owner.destroy();
                const admission = try fresh.authority();
                const summary = &fresh.public.summary;
                var normal = try Norm.Normalized.initWithWords(a, &admission, &summary.value.claims, 0, &summary.header, fresh.policy.public_limits.normalization);
                errdefer normal.deinit();
                if (fresh.policy.schedule.len != 0) return error.ClosedPageForestNodeHasNoPublicTerms;
                const terms = try a.alloc(Term, 0);
                errdefer a.free(terms);
                for (terms, fresh.policy.schedule) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .coordinates = try admission.values.at(wire) };
                return .{ .allocator = a, .owner = lease, .fresh = fresh, .terms = terms, .normal = normal };
            }
            pub fn deinit(self: *SourceImpl) void {
                const lease = self.owner;
                self.allocator.free(self.terms);
                self.normal.deinit();
                self.* = undefined;
                if (lease) |owner| owner.destroy();
            }
            pub fn validate(self: *const SourceImpl) !void {
                try self.fresh.validate();
                const admission = try self.fresh.authority();
                const summary = &self.fresh.public.summary;
                try self.normal.requireWithWords(self.allocator, &admission, &summary.value.claims, 0, &summary.header, self.fresh.policy.public_limits.normalization);
                if (self.terms.len != 0 or self.fresh.policy.schedule.len != 0) return error.UntrustedPageForestNode;
                for (self.terms, self.fresh.policy.schedule) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative != wire.negative or !std.meta.eql(term.coordinates, try admission.values.at(wire))) return error.UntrustedPageForestNode;
            }
            pub fn cell(self: *const SourceImpl, index: u32) ![4]M {
                return self.normal.cell(index);
            }
            pub fn claimFirst(self: *const SourceImpl) u32 {
                return self.normal.claim_first;
            }
            pub fn claim(self: *const SourceImpl, index: u32) !Coordinate {
                if (index >= 22) return error.InvalidPageForestCell;
                return .{ .first_cell = try std.math.add(u32, self.claimFirst(), try std.math.mul(u32, 4, index)), .word_count = 4 };
            }
            pub fn sourceIdentity(self: *const SourceImpl) !Coordinate {
                return self.rootAt(0);
            }
            pub fn pageSeal(self: *const SourceImpl) !Coordinate {
                return self.rootAt(1);
            }
            pub fn sourceEpoch(self: *const SourceImpl) !Coordinate {
                return self.rootAt(2);
            }
            pub fn baseSeal(self: *const SourceImpl) !Coordinate {
                return self.rootAt(3);
            }
            pub fn recipeIdentity(self: *const SourceImpl) !Coordinate {
                return self.rootAt(4);
            }
            fn rootAt(self: *const SourceImpl, index: u32) !Coordinate {
                const first = self.normal.word_first orelse return error.UntrustedPageForestClaimLayout;
                return .{ .first_cell = first + 9 + 8 * index, .word_count = 8 };
            }
            pub fn sourceClaim(self: *const SourceImpl, comptime name: []const u8) !Coordinate {
                const index = std.meta.fieldIndex(@import("air/block_v5_memory_source_equations_v1.zig").Algebra(Q).Sums, name) orelse @compileError("Unknown original source claim");
                return self.claim(@intCast(index));
            }
            pub fn indexedClaim(self: *const SourceImpl) !Coordinate {
                return self.claim(11);
            }
            pub fn foldClaim(self: *const SourceImpl, comptime name: []const u8) !Coordinate {
                const index = std.meta.fieldIndex(@import("air/block_v5_memory_source_batch_equations_v1.zig").Algebra(Q).Sums, name) orelse @compileError("Unknown original fold claim");
                return self.claim(@intCast(12 + index));
            }
            pub fn rangeCoordinates(self: *const SourceImpl) !struct { first: u32, count: u32, raw_pages: u32, fold_pages: u32, raw_rows: u32, fold_rows: u32 } {
                const first = self.normal.word_first orelse return error.UntrustedPageForestClaimLayout;
                return .{ .first = first + 3, .count = first + 4, .raw_pages = first + 5, .fold_pages = first + 6, .raw_rows = first + 7, .fold_rows = first + 8 };
            }
            pub fn replayPublic(self: *const SourceImpl, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
                self.normal.replay(recorder, PUBLIC_CIRCUIT);
            }
        };
        pub const Admission = AdmissionImpl;
        const AdmissionImpl = struct {
            pub const open_parent_v5_v2 = true;
            source: *const SourceImpl,
            key: Base.Key,
            expected_id: [32]u8,
            pc_clock_children: []const @import("block_v5_pc_clock_span_v1.zig").Span = &.{},
            pub fn init(source: *const SourceImpl) AdmissionImpl {
                const k = source.fresh.policy.key;
                return .{ .source = source, .key = .{ .profile = k.profile, .config = k.config, .context = k.context, .log_sizes = k.log_sizes, .preprocessed_root = k.preprocessed_root }, .expected_id = source.fresh.policy.expected_id };
            }
            pub fn validate(self: *const AdmissionImpl) !void {
                try self.source.validate();
                const expected = init(self.source);
                if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedPageForestNode;
            }
            pub fn config(self: *const AdmissionImpl) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const AdmissionImpl, root: [32]u8) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.admitRoot(root);
            }
            pub fn publicInputIdentity(self: *const AdmissionImpl) ![32]u8 {
                try self.validate();
                const actual = try self.source.fresh.authority();
                return actual.publicInputIdentity();
            }
            pub fn mix(self: *const AdmissionImpl, channel: anytype) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.mix(channel);
            }
            pub fn mixClaims(self: *const AdmissionImpl, channel: anytype, claims: []const Q) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.mixClaims(channel, claims);
            }
            pub fn validateClaimsForRelations(self: *const AdmissionImpl, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
                try self.validate();
                const actual = try self.source.fresh.authority();
                try actual.validateClaimsForRelations(claims, relations);
            }
        };
    };
}
const Default = ForReceiver(@import("block_v5_memory_source_page_forest_receiver_v1.zig"));
pub const Source = Default.Source;
pub const Admission = Default.Admission;
