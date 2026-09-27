//! Exact original typed leaf transcript normalization. These frames are policy,
//! not proof authority. Fresh.verify obtains the actual original verifier capture.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Recipes = @import("../prover/block_v5_execution_recipe_v1.zig");
const Definitions = @import("block_v5_heterogeneous_leaf_definition_v1.zig");
const Original = @import("block_v5_open_child_frames_v2.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Span = @import("block_v5_pc_clock_span_v1.zig").Span;
pub const PUBLIC_CIRCUIT: u32 = 4_200_012;
pub const VERSION: u32 = 1;
pub const LIMIT = Original.LIMIT;
pub const Term = Original.Term;
pub const Operation = Original.Operation;
pub const Frame = Original.Frame;
pub const Link = struct {
    execution: [32]u8,
    roots: [2][32]u8,
    caller_key: ?[32]u8 = null,
    caller_instance: ?[32]u8 = null,
    witness: ?[32]u8 = null,
    frame: ?@import("../air/block/memory_event.zig").Frame = null,
};
pub const Child = struct {
    arena: std.heap.ArenaAllocator,
    physical: Coverage.Physical,
    recipe: Recipes.Recipe,
    source_seal: [32]u8,
    key: Base.Key,
    expected_id: [32]u8,
    public_input_digest: [32]u8,
    claim_frame: [3]u32,
    frames: []const Frame,
    cells: []const [4]M,
    terms: []const Term,
    span: ?Span,
    link: ?Link,
    seal: [32]u8,
    pub fn deinit(self: *Child) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn validate(self: *const Child) !void {
        if (self.physical.logical_count == 0 or self.physical.logical_count > 2 or self.frames.len == 0 or self.cells.len == 0 or self.cells.len > LIMIT or self.terms.len == 0 or self.terms.len > LIMIT / 4 or
            std.mem.allEqual(u8, &self.expected_id, 0) or std.mem.allEqual(u8, &self.public_input_digest, 0) or std.mem.allEqual(u8, &self.source_seal, 0)) return error.InvalidHeterogeneousChild;
        if ((self.physical.kind == .native_arithmetic) != (self.span != null)) return error.HeterogeneousProviderHasNativeSpan;
        if (self.span) |span| {
            try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
            if (span.first_index != self.physical.index or span.segment_count != 1 or !std.meta.eql(span.sealed_digest, self.source_seal)) return error.UntrustedHeterogeneousNativeSpan;
        }
        try self.validateCells();
        for (self.cells) |cell| for (cell) |coordinate| {
            if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalHeterogeneousChild;
        };
        for (self.terms) |term| {
            if (term.uses == 0 or term.uses >= core.fields.m31.Modulus or term.circuit >= core.fields.m31.Modulus or term.wire >= core.fields.m31.Modulus) return error.InvalidHeterogeneousChild;
            for (term.coordinates) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalHeterogeneousChild;
        }
        if (!std.meta.eql(self.seal, try self.identity())) return error.MutatedHeterogeneousChild;
    }
    fn checkWord(self: *const Child, index: usize, word: u32) !void {
        if (index >= self.cells.len) return error.InvalidHeterogeneousChild;
        for (self.cells[index], 0..) |byte, part| if (byte.v != ((word >> @as(u5, @intCast(8 * part))) & 255)) return error.MutatedHeterogeneousChild;
    }
    fn validateCells(self: *const Child) !void {
        var at: usize = 0;
        for (self.frames) |frame| {
            if (frame.first != at) return error.InvalidHeterogeneousChild;
            switch (frame.operation) {
                .words => |words| {
                    for (words) |word| {
                        try self.checkWord(at, word);
                        at += 1;
                    }
                },
                .root => |root| {
                    for (0..8) |word| {
                        try self.checkWord(at, std.mem.readInt(u32, root[4 * word ..][0..4], .little));
                        at += 1;
                    }
                },
                .integer => |value| {
                    try self.checkWord(at, @truncate(value));
                    try self.checkWord(at + 1, @truncate(value >> 32));
                    at += 2;
                },
                .felts => |values| {
                    for (values) |value| for (value.toM31Array()) |word| {
                        if (word.v >= core.fields.m31.Modulus) return error.NoncanonicalHeterogeneousChild;
                        try self.checkWord(at, word.v);
                        at += 1;
                    };
                },
            }
        }
        if (at != self.cells.len) return error.InvalidHeterogeneousChild;
    }
    pub fn identity(self: *const Child) ![32]u8 {
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x42354846, VERSION, @intFromEnum(self.physical.kind), @intFromEnum(self.physical.subtype), self.physical.index, self.physical.logical_count });
        c.mixU32s(&self.physical.logical);
        c.mixRoot(self.physical.instance_id);
        for (self.physical.roots) |root| c.mixRoot(root);
        c.mixU32s(&.{@intFromEnum(self.recipe)});
        c.mixRoot(self.source_seal);
        c.mixRoot(try self.key.identity());
        c.mixRoot(self.expected_id);
        c.mixRoot(self.public_input_digest);
        c.mixU32s(&self.claim_frame);
        c.mixU32s(&.{@intFromBool(self.span != null)});
        if (self.span) |span| c.mixRoot(try span.identity());
        c.mixU32s(&.{@intFromBool(self.link != null)});
        if (self.link) |link| {
            c.mixRoot(link.execution);
            for (link.roots) |root| c.mixRoot(root);
            inline for (.{ link.caller_key, link.caller_instance, link.witness }) |optional| {
                c.mixU32s(&.{@intFromBool(optional != null)});
                if (optional) |digest| c.mixRoot(digest);
            }
            c.mixU32s(&.{@intFromBool(link.frame != null)});
            if (link.frame) |frame| {
                c.mixU32s(&.{ @intFromEnum(frame.clock_frame), frame.cycle_count });
                c.mixU64(frame.global_first_cycle);
            }
        }
        self.mix(&c);
        for (self.cells) |cell| c.mixU32s(&.{ cell[0].v, cell[1].v, cell[2].v, cell[3].v });
        for (self.terms) |term| {
            c.mixU32s(&.{ term.circuit, term.wire, term.uses, @intFromBool(term.negative) });
            c.mixFelts(&.{Q.fromM31Array(term.coordinates)});
        }
        return c.digestBytes();
    }
    pub fn mix(self: *const Child, channel: anytype) void {
        for (self.frames) |frame| switch (frame.operation) {
            .words => |v| channel.mixU32s(v),
            .root => |v| channel.mixRoot(v),
            .felts => |v| channel.mixFelts(v),
            .integer => |v| channel.mixU64(v),
        };
    }
    pub fn replayPublic(self: *const Child, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        for (self.frames) |frame| {
            const source = @import("air/blake3_transcript_witness.zig").Caller{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.first };
            switch (frame.operation) {
                .words => |v| recorder.mixPublicWords(source, v),
                .root => |v| recorder.mixPublicRoot(source, v),
                .felts => |v| recorder.mixPublicFelts(source, v),
                .integer => |v| recorder.mixPublicInteger(source, v),
            }
        }
    }
    /// Every root reference selects eight ACTUAL original transcript cells.
    pub fn rootCells(self: *const Child, digest: [32]u8) !u32 {
        return findRoot(self.frames, digest);
    }
};
pub fn PolicyForSubtype(comptime subtype: Coverage.Subtype) type {
    const D = Definitions.ForSubtype(subtype);
    return struct {
        admitted: *const D.Prepared,
        proposal: D.Open,
        key: D.Protocol.Key,
        key_id: [32]u8,
        wires: []const D.Bus.Wire,
        pub fn requireNativeAbsence(self: @This()) !void {
            if (subtype != .native_v3 and subtype != .capacity_v1) return error.InvalidHeterogeneousAbsence;
            const base = self.admitted;
            try base.validate(if (subtype == .native_v3) base.expected_id else base.template_id);
            const a = base.allocator;
            const external = if (subtype == .native_v3) base.template.external_retirements else base.external_retirements;
            const Source = if (subtype == .capacity_v1) @import("../prover/block_v5_native_capacity_fused_source_v1.zig") else @import("../prover/block_v5_native_projection_fused_source_v1.zig");
            const projections = try Source.slotsFromShapeForMode(a, base.shape, external, base.sealed.register_custody_mode);
            defer a.free(projections);
            const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = base.pin.context.first_cycle, .cycle_count = base.shape.public_data.clock };
            const slots = if (subtype == .capacity_v1) try Source.memorySlots(a, base.shape, external, frame, base.sealed.register_custody_mode) else try @import("../prover/block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, base.shape, frame, base.sealed.register_custody_mode);
            defer a.free(slots);
            if (projections.len != 0 or slots.len != 0) return error.InvalidHeterogeneousAbsence;
        }
        pub fn normalize(self: @This(), a: std.mem.Allocator, physical: Coverage.Physical, recipe: Recipes.Recipe, source_seal: [32]u8) !Child {
            if (physical.subtype != subtype or physical.kind != Definitions.kind(subtype)) return error.HeterogeneousLeafFamilyMismatch;
            var values = if (@hasDecl(D, "KIND")) try D.values(a, self.admitted, self.proposal) else try D.values(self.admitted, self.proposal);
            defer if (@hasDecl(D.Bus.Values, "deinit")) values.deinit();
            const authority = try D.Protocol.Admission.init(self.key, self.key_id, self.wires, values);
            try recipe.requireCompiled();
            const prepared = self.admitted;
            const base = if (subtype == .capacity_fused_v1) prepared.native else prepared;
            const expected_template = if (subtype == .native_v3) base.expected_id else base.template_id;
            try base.validate(expected_template);
            if (!std.meta.eql(base.sealed.digest, source_seal)) return error.HeterogeneousSourceSealMismatch;
            const family: @import("../prover/block_v5_source_seal_v1.zig").Family = switch (subtype) {
                .native_v3, .capacity_v1 => .execution,
                .capacity_fused_v1 => .program_request,
                .caller_family11_v1 => .precompile,
                .caller_fused_v1 => .program_extension_request,
                .ram_lanes_v1 => .memory,
                .range16_v1 => .memory_range,
                .rom_v1 => .program,
                .six_table_lookup_v1 => .native_lookup,
                else => unreachable,
            };
            var matched = false;
            for (base.entries) |entry| if (entry.family == family and entry.index == physical.index) {
                if (!std.meta.eql(entry.instance_id, physical.instance_id) or !std.meta.eql(entry.roots, physical.roots)) return error.HeterogeneousPhysicalSourceMismatch;
                matched = true;
            };
            if (!matched) return error.HeterogeneousPhysicalSourceMismatch;
            if (subtype == .native_v3 or subtype == .capacity_v1 or subtype == .capacity_fused_v1) try recipe.requireNative(base.shape);
            if (subtype == .caller_family11_v1 or subtype == .caller_fused_v1) try recipe.requireCaller(&prepared.statement, prepared.total_steps);
            var arena = std.heap.ArenaAllocator.init(a);
            errdefer arena.deinit();
            const temp = arena.allocator();
            var collector = Collector{ .a = temp };
            try authority.mix(&collector);
            if (collector.failure) |err| return err;
            const terms = try temp.alloc(Term, self.wires.len);
            for (self.wires, terms) |wire, *term| term.* = .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .coordinates = try authority.values.at(wire.source, wire.coordinate) };
            const span = if (subtype == .native_v3 or subtype == .capacity_v1) try @import("block_v5_pc_clock_span_v1.zig").leaf(base.pin, base.shape, source_seal, base.sealed.execution_instance_count) else null;
            const link: ?Link = switch (subtype) {
                .native_v3, .capacity_v1 => .{ .execution = self.proposal.instance_id, .roots = self.proposal.first_roots, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = base.pin.context.first_cycle, .cycle_count = base.shape.public_data.clock } },
                .capacity_fused_v1 => .{ .execution = prepared.binding.instance_id, .roots = prepared.binding.first_roots, .witness = prepared.witness_root, .frame = prepared.frame },
                .caller_family11_v1, .caller_fused_v1 => .{ .execution = prepared.binding.execution_instance_id, .roots = prepared.binding.first_roots, .caller_key = prepared.binding.caller_key_id, .caller_instance = prepared.binding.caller_instance_id, .witness = if (subtype == .caller_fused_v1) prepared.witness_root else null, .frame = if (subtype == .caller_fused_v1) prepared.frame else null },
                else => null,
            };
            if (link) |binding| {
                _ = try findRoot(collector.frames.items, binding.execution);
                for (binding.roots) |root| _ = try findRoot(collector.frames.items, root);
                if (binding.caller_key) |digest| _ = try findRoot(collector.frames.items, digest);
                if (binding.caller_instance) |digest| _ = try findRoot(collector.frames.items, digest);
                if (binding.witness) |digest| _ = try findRoot(collector.frames.items, digest);
            }
            var child = Child{ .arena = arena, .physical = physical, .recipe = recipe, .source_seal = source_seal, .key = .{ .profile = self.key.profile, .config = self.key.config, .context = self.key.context, .log_sizes = self.key.log_sizes, .preprocessed_root = self.key.preprocessed_root }, .expected_id = self.key_id, .public_input_digest = try authority.publicInputIdentity(), .claim_frame = .{ if (@hasDecl(D.Protocol, "CLAIM_TAG")) D.Protocol.CLAIM_TAG else 0x42355243, 1, @import("blake3_native_parent_artifact.zig").CLAIM_COUNT }, .frames = try collector.frames.toOwnedSlice(temp), .cells = try collector.cells.toOwnedSlice(temp), .terms = terms, .span = span, .link = link, .seal = undefined };
            child.seal = try child.identity();
            try child.validate();
            return child;
        }
        /// This is the original typed CPU recursive verifier, not normalization.
        pub fn verify(self: @This(), a: std.mem.Allocator, bytes: []const u8, physical: Coverage.Physical, recipe: Recipes.Recipe, source_seal: [32]u8) !Fresh {
            var child = try self.normalize(a, physical, recipe, source_seal);
            errdefer child.deinit();
            var checked = if (@hasDecl(D, "KIND")) try D.verify(a, bytes, self.key, self.key_id, self.wires, self.admitted, self.proposal) else try D.Receiver.verify(a, bytes, self.key, self.key_id, self.wires, self.admitted, self.proposal);
            defer if (@hasDecl(D.Bus.Values, "deinit")) checked.public_values.deinit();
            return .{ .child = child, .equation = checked.equation };
        }
    };
}
fn findRoot(frames: []const Frame, digest: [32]u8) !u32 {
    var expected: [8]u32 = undefined;
    for (&expected, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    for (frames) |frame| switch (frame.operation) {
        .root => |root| {
            if (std.meta.eql(root, digest)) return frame.first;
        },
        // Fused Values deliberately mix original Statement.words as one frame.
        // Locate the same eight authenticated cells; do not invent root frames.
        .words => |words| if (words.len >= expected.len) {
            for (0..words.len - expected.len + 1) |offset| if (std.mem.eql(u32, words[offset..][0..8], &expected)) return frame.first + @as(u32, @intCast(offset));
        },
        else => {},
    };
    return error.MissingHeterogeneousAuthenticatedRoot;
}
pub const Fresh = struct {
    child: Child,
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    pub fn deinit(self: *Fresh) void {
        self.equation.deinit();
        self.child.deinit();
        self.* = undefined;
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    frames: std.ArrayList(Frame) = .empty,
    cells: std.ArrayList([4]M) = .empty,
    failure: ?anyerror = null,
    fn add(self: *Collector, operation: Operation, words: []const u32) !void {
        if (words.len > LIMIT -| self.cells.items.len) return error.V5OpenChildFramesTooLarge;
        try self.frames.append(self.a, .{ .first = @intCast(self.cells.items.len), .operation = operation });
        for (words) |word| {
            var value: [4]M = undefined;
            for (&value, 0..) |*v, i| v.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
            try self.cells.append(self.a, value);
        }
    }
    pub fn mixU32s(self: *Collector, words: []const u32) void {
        if (self.failure != null) return;
        const owned = self.a.dupe(u32, words) catch |err| {
            self.failure = err;
            return;
        };
        self.add(.{ .words = owned }, owned) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixRoot(self: *Collector, root: [32]u8) void {
        if (self.failure != null) return;
        var words: [8]u32 = undefined;
        for (&words, 0..) |*v, i| v.* = std.mem.readInt(u32, root[4 * i ..][0..4], .little);
        self.add(.{ .root = root }, &words) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixFelts(self: *Collector, values: []const Q) void {
        if (self.failure != null) return;
        const owned = self.a.dupe(Q, values) catch |err| {
            self.failure = err;
            return;
        };
        const words = self.a.alloc(u32, values.len * 4) catch |err| {
            self.failure = err;
            return;
        };
        for (values, 0..) |value, i| for (value.toM31Array(), 0..) |v, j| {
            words[4 * i + j] = v.v;
        };
        self.add(.{ .felts = owned }, words) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixU64(self: *Collector, value: u64) void {
        if (self.failure != null) return;
        self.add(.{ .integer = value }, &.{ @truncate(value), @truncate(value >> 32) }) catch |err| {
            self.failure = err;
        };
    }
};

const base_protocol = Base;
const span_mod = @import("block_v5_pc_clock_span_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const Admission = struct {
    pub const open_parent_v5_v2 = true;
    source: *const Child,
    key: base_protocol.Key,
    expected_id: [32]u8,
    pc_clock_children: []const span_mod.Span,
    pub fn init(source: *const Child, pc_clock_children: []const span_mod.Span) Admission {
        return .{ .source = source, .key = source.key, .expected_id = source.expected_id, .pc_clock_children = pc_clock_children };
    }
    pub fn validate(self: *const Admission) !void {
        try self.source.validate();
        if (!std.meta.eql(self.key, self.source.key) or !std.meta.eql(self.expected_id, self.source.expected_id)) return error.UntrustedV5OpenChildFrames;
        if (self.pc_clock_children.len != 0) {
            for (self.pc_clock_children) |span| try @import("block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
            var span = self.pc_clock_children[0];
            for (self.pc_clock_children[1..]) |right| span = try span_mod.merge(&.{ span, right });
        }
    }
    pub fn config(self: *const Admission) !core.pcs.PcsConfig {
        try self.validate();
        return self.key.config;
    }
    pub fn admitRoot(self: *const Admission, root: [32]u8) !void {
        try self.validate();
        if (!std.meta.eql(root, self.key.preprocessed_root)) return error.UntrustedBlake3ParentRoot;
    }
    pub fn publicInputIdentity(self: *const Admission) ![32]u8 {
        try self.validate();
        return self.source.public_input_digest;
    }
    pub fn mix(self: *const Admission, channel: anytype) !void {
        try self.validate();
        self.source.mix(channel);
    }
    pub fn mixClaims(self: *const Admission, channel: anytype, claims: []const Q) !void {
        try self.validate();
        if (claims.len != @import("blake3_native_parent_artifact.zig").CLAIM_COUNT) return error.InvalidBlake3ParentClaims;
        channel.mixU32s(&self.source.claim_frame);
        channel.mixFelts(claims);
    }
    pub fn validateClaimsForRelations(self: *const Admission, claims: @import("blake3_native_parent_artifact.zig").Claims, relations: universal.UniversalRelations) !void {
        try self.validate();
        const element = try relations.getExact(.recursion_wire);
        var total = Q.zero();
        for (self.source.terms) |term| {
            const denominator = try element.combineBase(&(.{ M.fromCanonical(term.circuit), M.fromCanonical(term.wire) } ++ term.coordinates));
            if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
            const value = Q.fromBase(M.fromCanonical(term.uses)).mul(try denominator.inv());
            total = if (term.negative) total.sub(value) else total.add(value);
        }
        for (claims) |claim| total = total.add(claim);
        if (!total.isZero()) return error.InvalidHeterogeneousChildPublicClosure;
    }
};

pub const testing = if (@import("builtin").is_test) struct {
    /// Byte-source slice view only; deliberately produces no Child or receipt.
    pub fn validateFrameCells(frames: []const Frame, cells: []const [4]M) !void {
        var view: Child = undefined;
        view.frames = frames;
        view.cells = cells;
        try view.validateCells();
    }
    pub const rootOffset = findRoot;
} else struct {};
