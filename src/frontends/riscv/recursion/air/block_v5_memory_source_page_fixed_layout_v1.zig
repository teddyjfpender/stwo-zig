//! Original statement coordinates with counts only. This type has no field
//! values, channel, relations, nonce, Frame, successful capture or admission.
const std = @import("std");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Protocol = @import("../../prover/block_v5_memory_source_unified_page_protocol_v1.zig");
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("../../prover/block_v5_memory_source_unified_page_components_v1.zig");
const Page = @import("../../prover/block_v5_memory_source_unified_page_proof_v1.zig");
const Prefix = @import("block_v5_memory_source_page_prefix_v1.zig");
const SourceCircuit = @import("block_v5_memory_source_page_statement_v1.zig");
const Sink = @import("blake3_fixed_operation_recorder_v1.zig");
pub const Limits = struct { max_words: usize = 1 << 20, max_felts: usize = 32768, max_steps: usize = 1 << 16 };
pub const Layout = struct {
    a: std.mem.Allocator,
    first: []Frames.Step,
    claims: []Frames.Step,
    word_count: u32,
    field_count: u32,
    component_claim_first: u32,
    roots_offset: [8]u32,
    pub fn deinit(self: *Layout) void {
        self.a.free(self.claims);
        self.a.free(self.first);
        self.* = undefined;
    }
    pub fn record(self: *const Layout, r: *Sink.Recorder, steps: []const Frames.Step, circuit: u32) !void {
        for (steps) |step| switch (step) {
            .words => |span| {
                try requireSpan(span, self.word_count);
                try r.routedWords(.{ .circuit = circuit, .first_wire = span.first }, span.len);
            },
            .root => |offset| {
                try requireSpan(.{ .first = offset, .len = 8 }, self.word_count);
                r.mixPublicRoot(.{ .circuit = circuit, .first_wire = offset }, @splat(0));
            },
            .integer => |offset| {
                try requireSpan(.{ .first = offset, .len = 2 }, self.word_count);
                r.mixPublicInteger(.{ .circuit = circuit, .first_wire = offset }, 0);
            },
            .felts => |span| {
                try requireSpan(span, self.field_count);
                try r.routedFelts(.{ .circuit = circuit, .first_wire = try std.math.add(u32, self.word_count, try std.math.mul(u32, 4, span.first)) }, span.len);
            },
        };
        try r.check();
    }
};
fn requireSpan(span: Frames.Span, extent: u32) !void {
    if (span.first > extent or span.len > extent - span.first) return error.InvalidSourcePageFixedLayout;
}
pub const Builder = struct {
    a: std.mem.Allocator,
    limits: Limits,
    steps: std.ArrayList(Frames.Step) = .empty,
    words: u32 = 0,
    fields: u32 = 0,
    root_offsets: [32]u32 = undefined,
    root_count: usize = 0,
    failure: ?anyerror = null,
    pub fn deinit(self: *Builder) void {
        self.steps.deinit(self.a);
    }
    pub fn check(self: *const Builder) !void {
        if (self.failure) |failure| return failure;
    }
    fn append(self: *Builder, step: Frames.Step) !void {
        if (self.failure) |failure| return failure;
        if (self.steps.items.len >= self.limits.max_steps) return error.SourcePageFixedLayoutResourceLimit;
        try self.steps.append(self.a, step);
    }
    fn advanceWords(self: *Builder, count: usize) !u32 {
        if (self.failure) |failure| return failure;
        const start = self.words;
        const next = try std.math.add(u32, start, std.math.cast(u32, count) orelse return error.SourcePageFixedLayoutResourceLimit);
        if (next > self.limits.max_words) return error.SourcePageFixedLayoutResourceLimit;
        self.words = next;
        return start;
    }
    fn appendWords(self: *Builder, count: usize) !void {
        const first = try self.advanceWords(count);
        try self.append(.{ .words = .{ .first = first, .len = @intCast(count) } });
    }
    pub fn mixU32s(self: *Builder, values: []const u32) void {
        self.appendWords(values.len) catch |failure| {
            self.failure = failure;
        };
    }
    pub fn mixRoot(self: *Builder, _: [32]u8) void {
        self.mixRootCount();
    }
    pub fn mixRootCount(self: *Builder) void {
        self.appendRoot() catch |failure| {
            self.failure = failure;
        };
    }
    fn appendRoot(self: *Builder) !void {
        if (self.failure) |failure| return failure;
        if (self.root_count >= self.root_offsets.len) return error.SourcePageFixedLayoutResourceLimit;
        const offset = try self.advanceWords(8);
        try self.append(.{ .root = offset });
        self.root_offsets[self.root_count] = offset;
        self.root_count += 1;
    }
    pub fn mixU64(self: *Builder, _: u64) void {
        self.mixIntegerCount();
    }
    pub fn mixIntegerCount(self: *Builder) void {
        self.appendInteger() catch |failure| {
            self.failure = failure;
        };
    }
    fn appendInteger(self: *Builder) !void {
        try self.append(.{ .integer = try self.advanceWords(2) });
    }
    pub fn mixFelts(self: *Builder, values: []const @import("stwo_core").fields.qm31.QM31) void {
        if (self.failure != null) return;
        for (values) |value| if (!@import("universal_provider_relations.zig").secureIsCanonical(&value)) {
            self.failure = error.InvalidRecursiveStatementFrames;
            return;
        };
        self.mixFeltsCount(values.len);
    }
    pub fn mixFeltsCount(self: *Builder, count: usize) void {
        self.appendFelts(count) catch |failure| {
            self.failure = failure;
        };
    }
    fn appendFelts(self: *Builder, count: usize) !void {
        if (self.failure) |failure| return failure;
        const first = self.fields;
        const next = try std.math.add(u32, first, std.math.cast(u32, count) orelse return error.SourcePageFixedLayoutResourceLimit);
        if (next > self.limits.max_felts) return error.SourcePageFixedLayoutResourceLimit;
        try self.append(.{ .felts = .{ .first = first, .len = @intCast(count) } });
        self.fields = next;
    }
};
fn ClaimLengths(comptime kind: Semantic.Kind) type {
    const Claims = Components.ForKind(kind).Claims;
    return struct {
        pub fn core(_: @This(), channel: *Builder) void {
            channel.mixFeltsCount(@typeInfo(@TypeOf(@as(Claims, undefined).core)).array.len);
        }
        pub fn capture(_: @This(), channel: *Builder) void {
            channel.mixFeltsCount(@typeInfo(@TypeOf(@as(Claims, undefined).capture.sums)).array.len);
        }
        pub fn captureRequests(_: @This(), channel: *Builder) void {
            channel.mixIntegerCount();
        }
        pub fn sourceInputs(_: @This(), channel: *Builder) void {
            channel.mixFeltsCount(@typeInfo(@TypeOf(@as(Claims, undefined).source_inputs.sums)).array.len);
        }
        pub fn sourceRequests(_: @This(), channel: *Builder) void {
            channel.mixIntegerCount();
        }
        pub fn captureInputs(_: @This(), channel: *Builder) void {
            channel.mixFeltsCount(@typeInfo(@TypeOf(@as(Claims, undefined).capture_inputs.sums)).array.len);
        }
        pub fn captureInputRequests(_: @This(), channel: *Builder) void {
            channel.mixIntegerCount();
        }
        pub fn arithmetic(_: @This(), channel: *Builder) void {
            channel.mixFeltsCount(@typeInfo(@TypeOf(@as(Claims, undefined).arithmetic)).array.len);
        }
    };
}
/// Mathematical framing compiler. The production owner supplies independently
/// revalidated native policy/graph; no proposed semantic root or claim is used.
pub fn derive(comptime kind: Semantic.Kind, a: std.mem.Allocator, admitted: anytype, graph: *const Semantic.Prepared, public_claims: Semantic.Claims, limits: Limits) !Layout {
    if (limits.max_words == 0 or limits.max_felts == 0 or limits.max_steps == 0) return error.SourcePageFixedLayoutResourceLimit;
    var builder = Builder{ .a = a, .limits = limits };
    defer builder.deinit();
    if (kind == .raw) try Prefix.sourceFirst(kind, &builder, admitted.context.raw_plan, admitted.pin) else try Prefix.sourceFirst(kind, &builder, admitted.context.fold_plan, admitted.pin);
    try builder.check();
    if (builder.root_count != 9) return error.InvalidSourcePageFixedLayout;
    var offsets: [8]u32 = undefined;
    if (kind == .raw) {
        offsets[0..2].* = builder.root_offsets[2..4].*;
        offsets[2..6].* = builder.root_offsets[5..9].*;
    } else offsets[0..6].* = builder.root_offsets[3..9].*;
    const premix = try Page.ForKind(kind).identity(admitted.context, admitted.pin, admitted.limits.page);
    return finish(kind, a, &builder, offsets, admitted.context.epoch, premix, graph, public_claims);
}
/// Original typed metadata framing only. The production derive above obtains
/// every identity and source descriptor from actual independent admission.
/// This port cannot manufacture an admitted owner or successful verifier.
pub fn deriveForMetadata(comptime kind: Semantic.Kind, a: std.mem.Allocator, plan: anytype, pin: anytype, epoch: Protocol.SourceEpoch, premix: [32]u8, graph: *const Semantic.Prepared, public_claims: Semantic.Claims, limits: Limits) !Layout {
    if (limits.max_words == 0 or limits.max_felts == 0 or limits.max_steps == 0) return error.SourcePageFixedLayoutResourceLimit;
    var builder = Builder{ .a = a, .limits = limits };
    defer builder.deinit();
    try Prefix.sourceFirst(kind, &builder, plan, pin);
    try builder.check();
    if (builder.root_count != 9) return error.InvalidSourcePageFixedLayout;
    var offsets: [8]u32 = undefined;
    if (kind == .raw) {
        offsets[0..2].* = builder.root_offsets[2..4].*;
        offsets[2..6].* = builder.root_offsets[5..9].*;
    } else offsets[0..6].* = builder.root_offsets[3..9].*;
    return finish(kind, a, &builder, offsets, epoch, premix, graph, public_claims);
}
fn finish(comptime kind: Semantic.Kind, a: std.mem.Allocator, builder: *Builder, initial_offsets: [8]u32, epoch: Protocol.SourceEpoch, premix: [32]u8, graph: *const Semantic.Prepared, public_claims: Semantic.Claims) !Layout {
    var offsets = initial_offsets;
    try Prefix.beginSemantic(kind, builder, premix, epoch, graph, public_claims);
    const semantic_roots = builder.root_count;
    // The original two dynamic semantic PCS roots are routed from public
    // coordinates later. This compiler counts them, never invents root values.
    builder.mixRootCount();
    builder.mixRootCount();
    try builder.check();
    offsets[6..8].* = builder.root_offsets[semantic_roots..][0..2].*;
    Protocol.mixPageRelationsPrelude(builder);
    try builder.check();
    const first = try builder.steps.toOwnedSlice(a);
    errdefer a.free(first);
    const component_claim_first = builder.fields;
    Page.ForKind(kind).mixClaimsFrom(builder, ClaimLengths(kind){});
    try builder.check();
    const extent = try std.math.add(u32, builder.words, try std.math.mul(u32, 4, builder.fields));
    if (extent >= @import("stwo_core").fields.m31.Modulus) return error.SourcePageFixedLayoutResourceLimit;
    const claims = try builder.steps.toOwnedSlice(a);
    return .{ .a = a, .first = first, .claims = claims, .word_count = builder.words, .field_count = builder.fields, .component_claim_first = component_claim_first, .roots_offset = offsets };
}
pub const publicCircuit = SourceCircuit.publicCircuit;
