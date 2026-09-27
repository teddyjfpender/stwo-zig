//! Additive exact ORIGINAL leaf source. No legacy H admission is widened.
//! Raw clock extension belongs to a separate parent protocol, never this replay.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Frames = @import("block_v5_open_child_frames_v2.zig");
const Definitions = @import("block_v5_heterogeneous_leaf_definition_v1.zig");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Recipe = @import("../prover/block_v5_execution_recipe_v1.zig").Recipe;
const Span = @import("block_v5_pc_clock_span_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Verified = @import("blake3_native_parent_verifier.zig").Verified;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_300_210;
pub const Limits = struct { max_cells: usize = 1 << 20, max_frames: usize = 1 << 16, max_terms: usize = 1 << 16, max_owned_bytes: usize = 64 << 20 };
const OwnedFrame = struct { frame: Frames.Frame, words_owned: bool = false, felts_owned: bool = false };
fn count(operation: Frames.Operation) !u32 {
    const n: usize = switch (operation) {
        .words => |v| v.len,
        .root => 8,
        .integer => 2,
        .felts => |v| try std.math.mul(usize, v.len, 4),
    };
    return std.math.cast(u32, n) orelse error.WideOriginalSourceResourceLimit;
}
fn same(a: Frames.Operation, b: Frames.Operation) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .words => |v| std.mem.eql(u32, v, b.words),
        .root => |v| std.meta.eql(v, b.root),
        .integer => |v| v == b.integer,
        .felts => |v| blk: {
            if (v.len != b.felts.len) break :blk false;
            for (v, b.felts) |x, y| if (!x.eql(y)) break :blk false;
            break :blk true;
        },
    };
}
const Collector = struct {
    a: std.mem.Allocator,
    limits: Limits,
    frames: std.ArrayList(OwnedFrame) = .empty,
    cells: u32 = 0,
    bytes: usize = 0,
    failure: ?anyerror = null,
    fn deinit(self: *@This()) void {
        for (self.frames.items) |owned| {
            if (owned.words_owned) self.a.free(owned.frame.operation.words);
            if (owned.felts_owned) self.a.free(owned.frame.operation.felts);
        }
        self.frames.deinit(self.a);
    }
    fn add(self: *@This(), operation: Frames.Operation) !void {
        const end = try std.math.add(u32, self.cells, try count(operation));
        const extra = switch (operation) {
            .words => |v| try std.math.mul(usize, v.len, @sizeOf(u32)),
            .felts => |v| try std.math.mul(usize, v.len, @sizeOf(Q)),
            else => 0,
        };
        const extent = try std.math.add(usize, self.bytes, try std.math.add(usize, @sizeOf(OwnedFrame), extra));
        if (end > self.limits.max_cells or end >= core.fields.m31.Modulus or self.frames.items.len >= self.limits.max_frames or extent > self.limits.max_owned_bytes) return error.WideOriginalSourceResourceLimit;
        var owned = OwnedFrame{ .frame = .{ .first = self.cells, .operation = operation } };
        errdefer {
            if (owned.words_owned) self.a.free(owned.frame.operation.words);
            if (owned.felts_owned) self.a.free(owned.frame.operation.felts);
        }
        switch (operation) {
            .words => |v| {
                owned.frame.operation = .{ .words = try self.a.dupe(u32, v) };
                owned.words_owned = true;
            },
            .felts => |v| {
                owned.frame.operation = .{ .felts = try self.a.dupe(Q, v) };
                owned.felts_owned = true;
            },
            else => {},
        }
        try self.frames.ensureTotalCapacityPrecise(self.a, try std.math.add(usize, self.frames.items.len, 1));
        self.frames.appendAssumeCapacity(owned);
        self.cells = end;
        self.bytes = extent;
    }
    fn accept(self: *@This(), operation: Frames.Operation) void {
        if (self.failure != null) return;
        self.add(operation) catch |failure| {
            self.failure = failure;
        };
    }
    pub fn mixU32s(self: *@This(), v: []const u32) void {
        self.accept(.{ .words = v });
    }
    pub fn mixRoot(self: *@This(), v: [32]u8) void {
        self.accept(.{ .root = v });
    }
    pub fn mixU64(self: *@This(), v: u64) void {
        self.accept(.{ .integer = v });
    }
    pub fn mixFelts(self: *@This(), v: []const Q) void {
        self.accept(.{ .felts = v });
    }
};
const Comparison = struct {
    frames: []const OwnedFrame,
    at: usize = 0,
    cells: u32 = 0,
    failure: ?anyerror = null,
    fn accept(self: *@This(), operation: Frames.Operation) void {
        if (self.failure != null) return;
        if (self.at >= self.frames.len or self.frames[self.at].frame.first != self.cells or !same(operation, self.frames[self.at].frame.operation)) {
            self.failure = error.MutatedWideOriginalSource;
            return;
        }
        const extent = count(operation) catch |failure| {
            self.failure = failure;
            return;
        };
        self.cells = std.math.add(u32, self.cells, extent) catch |failure| {
            self.failure = failure;
            return;
        };
        self.at += 1;
    }
    pub fn mixU32s(self: *@This(), v: []const u32) void {
        self.accept(.{ .words = v });
    }
    pub fn mixRoot(self: *@This(), v: [32]u8) void {
        self.accept(.{ .root = v });
    }
    pub fn mixU64(self: *@This(), v: u64) void {
        self.accept(.{ .integer = v });
    }
    pub fn mixFelts(self: *@This(), v: []const Q) void {
        self.accept(.{ .felts = v });
    }
};
fn readCell(frames: []const OwnedFrame, cell_count: u32, coordinate: u32) ![4]M {
    if (coordinate >= cell_count) return error.InvalidWideOriginalCoordinate;
    var low: usize = 0;
    var high = frames.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (frames[mid].frame.first <= coordinate) low = mid + 1 else high = mid;
    }
    if (low == 0) return error.InvalidWideOriginalCoordinate;
    const frame = frames[low - 1].frame;
    const offset = coordinate - frame.first;
    const word: u32 = switch (frame.operation) {
        .words => |v| if (offset < v.len) v[offset] else return error.InvalidWideOriginalCoordinate,
        .root => |v| if (offset < 8) std.mem.readInt(u32, v[4 * @as(usize, offset) ..][0..4], .little) else return error.InvalidWideOriginalCoordinate,
        .integer => |v| if (offset == 0) @truncate(v) else if (offset == 1) @truncate(v >> 32) else return error.InvalidWideOriginalCoordinate,
        .felts => |v| if (offset / 4 < v.len) v[offset / 4].toM31Array()[offset % 4].v else return error.InvalidWideOriginalCoordinate,
    };
    var result: [4]M = undefined;
    for (&result, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
    return result;
}
/// Stateless typed selection belongs to the independent caller policy. It is
/// never selected by received bytes. Provider adapters keep their own grammar.
pub fn ForSubtype(comptime subtype: Coverage.Subtype) type {
    switch (subtype) {
        .native_v3, .capacity_v1, .capacity_fused_v1, .caller_family11_v1, .caller_fused_v1 => {},
        else => @compileError("wide original source accepts genuine native/caller stacks only"),
    }
    const D = Definitions.ForSubtype(subtype);
    return struct {
        pub const Policy = struct {
            admitted: *const D.Prepared,
            proposal: D.Open,
            key: D.Protocol.Key,
            key_id: [32]u8,
            wires: []const D.Bus.Wire,
            physical: Coverage.Physical,
            recipe: Recipe,
            source_seal: [32]u8,
            fn values(self: @This(), a: std.mem.Allocator) !D.Bus.Values {
                const prepared = self.admitted;
                const base = if (subtype == .capacity_fused_v1) prepared.native else prepared;
                try base.validate(if (subtype == .native_v3) base.expected_id else base.template_id);
                if (self.physical.subtype != subtype or self.physical.kind != D.KIND or self.physical.logical_count == 0 or self.physical.logical_count > 2 or !std.meta.eql(base.sealed.digest, self.source_seal)) return error.UntrustedWideOriginalPolicy;
                try self.recipe.requireCompiled();
                if (subtype == .native_v3 or subtype == .capacity_v1 or subtype == .capacity_fused_v1) try self.recipe.requireNative(base.shape) else try self.recipe.requireCaller(&prepared.statement, prepared.total_steps);
                const family: @import("../prover/block_v5_source_seal_v1.zig").Family = switch (subtype) {
                    .native_v3, .capacity_v1 => .execution,
                    .capacity_fused_v1 => .program_request,
                    .caller_family11_v1 => .precompile,
                    .caller_fused_v1 => .program_extension_request,
                    else => unreachable,
                };
                var matched = false;
                for (base.entries) |entry| if (entry.family == family and entry.index == self.physical.index) {
                    if (!std.meta.eql(entry.instance_id, self.physical.instance_id) or !std.meta.eql(entry.roots, self.physical.roots)) return error.UntrustedWideOriginalPolicy;
                    matched = true;
                };
                if (!matched) return error.UntrustedWideOriginalPolicy;
                return D.values(a, self.admitted, self.proposal);
            }
            pub fn expectedSpan(self: @This()) !?Span.Span {
                if (subtype != .native_v3 and subtype != .capacity_v1) return null;
                const prepared = self.admitted;
                const span = try Span.leaf(prepared.pin, prepared.shape, self.source_seal, prepared.sealed.execution_instance_count);
                if (span.first_index != self.physical.index) return error.UntrustedWideOriginalPolicy;
                return span;
            }
        };
        pub const Source = struct {
            allocator: std.mem.Allocator,
            allocation_owner: ?*Budget,
            policy: Policy,
            frames: []OwnedFrame,
            cell_count: u32,
            terms: []Frames.Term,
            public_input_digest: [32]u8,
            span: ?Span.Span,
            pub const complete_source_authority = false;
            pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Source {
                const owner = Budget.fromAllocator(a);
                if (owner) |value| _ = value.retain();
                errdefer if (owner) |value| value.destroy();
                if (policy.wires.len == 0 or policy.wires.len > limits.max_terms) return error.WideOriginalSourceResourceLimit;
                var values = try policy.values(a);
                defer if (@hasDecl(D.Bus.Values, "deinit")) values.deinit();
                const admission = try D.Protocol.Admission.init(policy.key, policy.key_id, policy.wires, values);
                const term_bytes = try std.math.mul(usize, policy.wires.len, @sizeOf(Frames.Term));
                if (term_bytes > limits.max_owned_bytes) return error.WideOriginalSourceResourceLimit;
                const terms = try a.alloc(Frames.Term, policy.wires.len);
                errdefer a.free(terms);
                for (terms, policy.wires) |*term, wire| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try values.at(wire.source, wire.coordinate) };
                var collector = Collector{ .a = a, .limits = limits, .bytes = term_bytes };
                defer collector.deinit();
                try admission.mix(&collector);
                if (collector.failure) |failure| return failure;
                const digest = try admission.publicInputIdentity();
                const expected_span = try policy.expectedSpan();
                return .{ .allocator = a, .allocation_owner = owner, .policy = policy, .frames = try collector.frames.toOwnedSlice(a), .cell_count = collector.cells, .terms = terms, .public_input_digest = digest, .span = expected_span };
            }
            pub fn deinit(self: *Source) void {
                const owner = self.allocation_owner;
                for (self.frames) |owned| {
                    if (owned.words_owned) self.allocator.free(owned.frame.operation.words);
                    if (owned.felts_owned) self.allocator.free(owned.frame.operation.felts);
                }
                self.allocator.free(self.frames);
                self.allocator.free(self.terms);
                self.* = undefined;
                if (owner) |value| value.destroy();
            }
            pub fn validate(self: *const Source) !void {
                var values = try self.policy.values(self.allocator);
                defer if (@hasDecl(D.Bus.Values, "deinit")) values.deinit();
                const admission = try D.Protocol.Admission.init(self.policy.key, self.policy.key_id, self.policy.wires, values);
                if (!std.meta.eql(self.public_input_digest, try admission.publicInputIdentity()) or !std.meta.eql(self.span, try self.policy.expectedSpan()) or self.terms.len != self.policy.wires.len) return error.MutatedWideOriginalSource;
                var comparison = Comparison{ .frames = self.frames };
                try admission.mix(&comparison);
                if (comparison.failure) |failure| return failure;
                if (comparison.at != self.frames.len or comparison.cells != self.cell_count) return error.MutatedWideOriginalSource;
                for (self.terms, self.policy.wires) |term, wire| if (term.circuit != wire.circuit or term.wire != wire.wire or term.uses != wire.uses or term.negative or !std.meta.eql(term.coordinates, try values.at(wire.source, wire.coordinate))) return error.MutatedWideOriginalSource;
            }
            pub fn frameAt(self: *const Source, ordinal: u32) !Frames.Frame {
                if (ordinal >= self.frames.len) return error.InvalidWideOriginalCoordinate;
                return self.frames[ordinal].frame;
            }
            pub fn cell(self: *const Source, coordinate: u32) ![4]M {
                return readCell(self.frames, self.cell_count, coordinate);
            }
            pub fn replayPublic(self: *const Source, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
                for (self.frames) |owned| {
                    const frame = owned.frame;
                    const caller = @import("air/blake3_transcript_witness.zig").Caller{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.first };
                    switch (frame.operation) {
                        .words => |v| recorder.mixPublicWords(caller, v),
                        .root => |v| recorder.mixPublicRoot(caller, v),
                        .integer => |v| recorder.mixPublicInteger(caller, v),
                        .felts => |v| recorder.mixPublicFelts(caller, v),
                    }
                }
            }
            pub fn mix(self: *const Source, channel: anytype) !void {
                var values = try self.policy.values(self.allocator);
                defer if (@hasDecl(D.Bus.Values, "deinit")) values.deinit();
                const admission = try D.Protocol.Admission.init(self.policy.key, self.policy.key_id, self.policy.wires, values);
                try admission.mix(channel);
            }
        };
        /// Facade for the unchanged symbolic verifier of the ORIGINAL proof.
        /// pc_clock_children is deliberately empty: the six-word legacy span
        /// algebra is not used. Wide equations belong to the new parent graph.
        pub const Admission = struct {
            pub const open_parent_v5_v2 = true;
            source: *const Source,
            key: Base.Key,
            expected_id: [32]u8,
            pc_clock_children: []const Span.Span = &.{},
            pub fn init(source: *const Source) Admission {
                const original = source.policy.key;
                return .{ .source = source, .key = .{ .profile = original.profile, .config = original.config, .context = original.context, .log_sizes = original.log_sizes, .preprocessed_root = original.preprocessed_root }, .expected_id = source.policy.key_id };
            }
            pub fn validate(self: *const Admission) !void {
                try self.source.validate();
                const expected = init(self.source);
                if (!std.meta.eql(self.key, expected.key) or !std.meta.eql(self.expected_id, expected.expected_id) or self.pc_clock_children.len != 0) return error.UntrustedWideOriginalPolicy;
            }
            pub fn config(self: *const Admission) !core.pcs.PcsConfig {
                try self.validate();
                return self.key.config;
            }
            pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
                try self.validate();
                if (!std.meta.eql(root, self.source.policy.key.preprocessed_root)) return error.UntrustedBlake3ParentRoot;
            }
            pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
                try self.validate();
                return self.source.public_input_digest;
            }
            pub fn mix(self: *const Admission, channel: anytype) !void {
                try self.validate();
                try self.source.mix(channel);
            }
            pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
                try self.validate();
                var values = try self.source.policy.values(self.source.allocator);
                defer if (@hasDecl(D.Bus.Values, "deinit")) values.deinit();
                const original = try D.Protocol.Admission.init(self.source.policy.key, self.expected_id, self.source.policy.wires, values);
                try original.mixClaims(channel, claims);
            }
            pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: @import("air/universal_challenges.zig").UniversalRelations) !void {
                try self.validate();
                var values = try self.source.policy.values(self.source.allocator);
                defer if (@hasDecl(D.Bus.Values, "deinit")) values.deinit();
                const original = try D.Protocol.Admission.init(self.source.policy.key, self.expected_id, self.source.policy.wires, values);
                try original.validateClaimsForRelations(claims, relations);
            }
        };
        /// Real all-cohort child verifier rows; no proof is generated here.
        /// Caller owns the distinct enclosing public bus, setup/key and graph
        /// supplying these exact original bytes and original packed terms.
        pub fn planOriginal(a: std.mem.Allocator, fresh: *const Fresh, transcript_capacity: u32) !@import("blake3_execution_parent_preparation.zig").Planned {
            try fresh.validate();
            const admitted = Admission.init(&fresh.source);
            return @import("blake3_execution_parent_preparation.zig").State.plan(a, &admitted, &fresh.equation, admitted.expected_id, transcript_capacity);
        }
        pub const Fresh = struct {
            source: Source,
            equation: Verified,
            pub const complete_source_authority = false;
            pub fn deinit(self: *Fresh) void {
                self.equation.deinit();
                self.source.deinit();
                self.* = undefined;
            }
            pub fn validate(self: *const Fresh) !void {
                try self.source.validate();
                var values = try self.source.policy.values(self.source.allocator);
                defer if (@hasDecl(D.Bus.Values, "deinit")) values.deinit();
                const admission = try D.Protocol.Admission.init(self.source.policy.key, self.source.policy.key_id, self.source.policy.wires, values);
                try self.equation.validate(&admission, self.source.policy.key_id);
            }
        };
        /// Only this call acquires genuine original proof authority. Source.init
        /// alone is public admission normalization, never a verified child.
        pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8, limits: Limits) !Fresh {
            var source = try Source.init(a, policy, limits);
            errdefer source.deinit();
            var checked = try D.verify(a, bytes, policy.key, policy.key_id, policy.wires, policy.admitted, policy.proposal);
            defer if (@hasDecl(D.Bus.Values, "deinit")) checked.public_values.deinit();
            errdefer checked.equation.deinit();
            if (subtype == .native_v3 or subtype == .capacity_v1) {
                const original_span = if (@typeInfo(@TypeOf(checked.pc_clock_span)) == .optional)
                    checked.pc_clock_span orelse return error.UntrustedWideOriginalFreshSpan
                else
                    checked.pc_clock_span;
                if (!std.meta.eql(source.span.?, original_span)) return error.UntrustedWideOriginalFreshSpan;
            }
            return .{ .source = source, .equation = checked.equation };
        }
    };
}

fn collectorFixture(a: std.mem.Allocator) !void {
    var collector = Collector{ .a = a, .limits = .{} };
    defer collector.deinit();
    const words = [_]u32{ 0xffffffff, 0x80000000 };
    const secure = [_]Q{Q.fromU32Unchecked(1, 2, 3, 4)};
    collector.mixU32s(&.{});
    collector.mixU32s(&words);
    collector.mixRoot(@splat(0x55));
    collector.mixU64(0xfedcba9876543210);
    collector.mixFelts(&secure);
    collector.mixU32s(&.{});
    if (collector.failure) |failure| return failure;
    var reference = core.channel.blake3.Channel{};
    reference.mixU32s(&.{});
    reference.mixU32s(&words);
    reference.mixRoot(@splat(0x55));
    reference.mixU64(0xfedcba9876543210);
    reference.mixFelts(&secure);
    reference.mixU32s(&.{});
    var rebuilt = core.channel.blake3.Channel{};
    for (collector.frames.items) |owned| switch (owned.frame.operation) {
        .words => |v| rebuilt.mixU32s(v),
        .root => |v| rebuilt.mixRoot(v),
        .integer => |v| rebuilt.mixU64(v),
        .felts => |v| rebuilt.mixFelts(v),
    };
    try std.testing.expectEqualSlices(u8, &reference.digestBytes(), &rebuilt.digestBytes());
    try std.testing.expectEqual(@as(u32, 255), (try readCell(collector.frames.items, collector.cells, 0))[0].v);
    try std.testing.expectEqual(@as(u32, 0x10), (try readCell(collector.frames.items, collector.cells, 10))[0].v);
    try std.testing.expectEqual(@as(u32, 4), (try readCell(collector.frames.items, collector.cells, 15))[0].v);
    try std.testing.expectError(error.InvalidWideOriginalCoordinate, readCell(collector.frames.items, collector.cells, 16));
}
test "wide original bridge: exact unchanged original channel mixed frames and lazy boundary decoding" {
    try collectorFixture(std.testing.allocator);
}
test "wide original bridge: cloned original frame allocation rollback" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, collectorFixture, .{});
}
test "wide original bridge: denied extent records original error before cloning" {
    var collector = Collector{ .a = std.testing.allocator, .limits = .{ .max_cells = 1 } };
    defer collector.deinit();
    collector.mixU64(std.math.maxInt(u64));
    try std.testing.expectEqual(error.WideOriginalSourceResourceLimit, collector.failure.?);
    try std.testing.expectEqual(@as(usize, 0), collector.frames.items.len);
}
