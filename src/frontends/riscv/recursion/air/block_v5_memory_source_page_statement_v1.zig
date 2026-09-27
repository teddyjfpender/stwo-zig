//! Recorded original PAGE prefix/claim operations. Roots are located by the
//! exact original invocation grammar, never by searching equal root values.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const suite = core.proof_suites.Blake3;
const Page = @import("../../prover/block_v5_memory_source_unified_page_proof_v1.zig");
const Protocol = @import("../../prover/block_v5_memory_source_unified_page_protocol_v1.zig");
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("../../prover/block_v5_memory_source_unified_page_components_v1.zig");
const Admission = @import("../../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Universal = @import("universal_challenges.zig");
pub const RAW_PUBLIC_CIRCUIT: u32 = 4_200_050;
pub const FOLD_PUBLIC_CIRCUIT: u32 = 4_200_051;
pub fn publicCircuit(comptime kind: Semantic.Kind) u32 {
    return if (kind == .raw) RAW_PUBLIC_CIRCUIT else FOLD_PUBLIC_CIRCUIT;
}
const Channel = struct {
    builder: *Frames.Builder,
    native: suite.Channel = .{},
    pub fn mixRoot(self: *@This(), root: [32]u8) void {
        self.builder.mixRoot(root);
        self.native.mixRoot(root);
    }
    pub fn mixU32s(self: *@This(), words: []const u32) void {
        self.builder.mixU32s(words);
        self.native.mixU32s(words);
    }
    pub fn mixU64(self: *@This(), value: u64) void {
        self.builder.mixU64(value);
        self.native.mixU64(value);
    }
    pub fn mixFelts(self: *@This(), values: []const Q) void {
        self.builder.mixFelts(values);
        self.native.mixFelts(values);
    }
    pub fn drawSecureFelts(self: *@This(), a: std.mem.Allocator, count: usize) ![]Q {
        try self.builder.check();
        return self.native.drawSecureFelts(a, count);
    }
};
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Original = Page.ForKind(kind);
    const C = Components.ForKind(kind);
    return struct {
        const Self = @This();
        frame: Frames.Statement,
        words: []u32,
        felts: []Q,
        roots_offset: [8]u32,
        component_claim_first: u32,
        relations: Universal.UniversalRelations,
        proof_start: suite.Channel,
        pub fn clone(self: *const Self, a: std.mem.Allocator) !Self {
            var result = self.*;
            result.frame = try self.frame.clone(a);
            result.words = result.frame.words;
            result.felts = result.frame.felts;
            return result;
        }
        pub fn deinit(self: *Self) void {
            self.frame.deinit();
            self.* = undefined;
        }
        pub fn init(a: std.mem.Allocator, admitted: *const Admission.ForKind(kind).Prepared, semantic: Protocol.SemanticPin, claims: C.Claims) !Self {
            try admitted.validate(admitted.template_id);
            var builder = Frames.Builder{ .allocator = a };
            defer builder.deinit();
            var channel = Channel{ .builder = &builder };
            var offsets: [8]u32 = undefined;
            if (kind == .raw) {
                try @import("block_v5_memory_source_page_prefix_v1.zig").sourceFirst(kind, &channel, admitted.context.raw_plan, admitted.pin);
                try builder.check();
                // Actual Raw.first2 roots, core ABI, next4 roots. The source
                // first-channel ABI+plan occupy positions0/1.
                if (builder.root_count != 9) return error.InvalidSourcePageStatement;
                offsets[0..2].* = builder.root_offsets[2..4].*;
                offsets[2..6].* = builder.root_offsets[5..9].*;
            } else {
                try @import("block_v5_memory_source_page_prefix_v1.zig").sourceFirst(kind, &channel, admitted.context.fold_plan, admitted.pin);
                try builder.check();
                // Fold.first ABI+plan+inventory precede its six real roots.
                if (builder.root_count != 9) return error.InvalidSourcePageStatement;
                offsets[0..6].* = builder.root_offsets[3..9].*;
            }
            const recipe = try Page.ForKind(kind).Admission.init(a, admitted.context, admitted.pin, admitted.fold_rows, semantic.claims, admitted.limits.page);
            var owned_recipe = recipe;
            defer owned_recipe.deinit();
            try @import("block_v5_memory_source_page_prefix_v1.zig").beginSemantic(kind, &channel, semantic.premix_identity, admitted.context.epoch, recipe.graph, semantic.claims);
            const first_semantic_root = builder.root_count;
            for (semantic.roots) |root| channel.mixRoot(root);
            try builder.check();
            offsets[6..8].* = builder.root_offsets[first_semantic_root..][0..2].*;
            const relations = try Protocol.drawPageRelations(a, &channel, semantic, semantic);
            try builder.check();
            const first = try builder.steps.toOwnedSlice(a);
            errdefer a.free(first);
            const component_claim_first = std.math.cast(u32, builder.fields.items.len) orelse return error.InvalidSourcePageStatement;
            Original.mixClaims(&channel, claims);
            try builder.check();
            const claim_steps = try builder.steps.toOwnedSlice(a);
            errdefer a.free(claim_steps);
            const words = try builder.data.toOwnedSlice(a);
            errdefer a.free(words);
            const felts = try builder.fields.toOwnedSlice(a);
            return .{ .frame = .{ .allocator = a, .words = words, .felts = felts, .first = first, .claims = claim_steps, .sealed_offset = 0, .roots_offset = offsets[0..3].* }, .words = words, .felts = felts, .roots_offset = offsets, .component_claim_first = component_claim_first, .relations = relations, .proof_start = channel.native };
        }
        pub fn claimWord(self: *const Self, index: u32) !u32 {
            const position = try std.math.add(u32, self.component_claim_first, index);
            if (position >= self.frame.felts.len) return error.InvalidSourcePageStatement;
            return std.math.add(u32, std.math.cast(u32, self.frame.words.len) orelse return error.InvalidSourcePageStatement, try std.math.mul(u32, 4, position));
        }
    };
}
