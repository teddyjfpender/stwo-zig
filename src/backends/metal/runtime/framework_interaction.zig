//! AOT-only framework interaction generation. Cold admission owns the
//! program's exact input routing; execution uploads metadata only and returns
//! resident columns plus device-computed claims after checking device status.
const std = @import("std");
const core = @import("stwo_core");
const backend = @import("stwo_prover_engine").air.component_prover;
const runtime = @import("../runtime.zig");
const generator = @import("framework_interaction_codegen.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
extern fn stwo_zig_framework_interaction_prepare(*anyopaque, [*]const u8, usize, [*]const u32, u32, u32, u32, u32, u32) ?*anyopaque;
extern fn stwo_zig_framework_interaction_destroy(*anyopaque) void;
extern fn stwo_zig_framework_interaction_generate(*anyopaque, ?*anyopaque, ?*anyopaque, [*]const u32, [*]const u64, u32, [*]const u32, u32, [*]const u32, u32, u32, u32, *?*anyopaque, *?*anyopaque, *usize, *f64) u32;

pub const Tree = struct {
    buffer: *const runtime.ResidentBuffer,
    /// Actual physical columns of this owned witness arena, in M31 words.
    column_offsets: []const u64,
};
pub const Invocation = struct {
    trace_log_size: u32,
    profile_values: []const M31,
    /// Canonical per-entry z and alpha powers; claims are generated outputs.
    relation_values: []const QM31,
};
pub const Result = struct {
    resident: runtime.ResidentBuffer,
    rows: usize,
    batches: usize,
    claim_count: usize,
    gpu_milliseconds: f64,
    pub fn deinit(self: *Result) void {
        self.resident.deinit();
        self.* = undefined;
    }
    pub fn column(self: *const Result, index: usize) []const M31 {
        std.debug.assert(index < self.batches * 4);
        const words: [*]const M31 = @ptrCast(@alignCast(self.resident.contents));
        return words[index * self.rows ..][0..self.rows];
    }
    pub fn claim(self: *const Result, index: usize) QM31 {
        std.debug.assert(index < self.claim_count);
        const words: [*]const M31 = @ptrCast(@alignCast(self.resident.contents));
        return QM31.fromM31Array(words[self.batches * 4 * self.rows + index * 4 ..][0..4].*);
    }
};
/// Owns an opaque admission snapshot. Source program mutation or destruction
/// cannot alter names, input routing or shape once init returns. The only
/// subsequent mutable field is the retained backend plan, private to this file.
pub const Plan = struct {
    opaque_state: *anyopaque,

    fn state(self: *const Plan) *State {
        return @ptrCast(@alignCast(self.opaque_state));
    }
    pub fn init(allocator: std.mem.Allocator, entry: generator.Entry) !Plan {
        const owned = try allocator.create(State);
        errdefer allocator.destroy(owned);
        owned.* = try State.init(allocator, entry);
        return .{ .opaque_state = owned };
    }
    pub fn deinit(self: *Plan) void {
        const owned = self.state();
        const allocator = owned.allocator;
        owned.deinit();
        allocator.destroy(owned);
        self.* = undefined;
    }
    pub fn prepare(self: *Plan, metal: *runtime.Runtime) !void {
        try self.state().prepare(metal);
    }
    pub fn generate(self: *const Plan, trees: [2]?Tree, invocation: Invocation) !Result {
        return self.state().generate(trees, invocation);
    }
    /// Test compilation is confined to the focused test translation unit. The
    /// factory receives the private admitted ABI; tests cannot substitute shape.
    pub fn prepareForTesting(self: *Plan, source: []const u8, factory: anytype) !void {
        if (!@import("builtin").is_test) @compileError("test-only interaction factory");
        const owned = self.state();
        if (owned.handle != null) return error.FrameworkInteractionAlreadyPrepared;
        const tags = try owned.allocator.alloc(u32, owned.inputs.len);
        defer owned.allocator.free(tags);
        for (owned.inputs, tags) |input, *tag| tag.* = switch (input) {
            .trace_column => |column| column.tree_index,
            .profile_parameter => std.math.maxInt(u32),
        };
        owned.handle = factory(source.ptr, source.len, owned.name.ptr, owned.name.len, tags.ptr, @intCast(owned.inputs.len), @intCast(owned.profile_count), @intCast(owned.relation_count * 4), @intCast(owned.batches), @intFromBool(owned.cumulative)) orelse return error.FrameworkInteractionUnavailable;
    }
    pub fn handleForTesting(self: *const Plan) *anyopaque {
        if (!@import("builtin").is_test) @compileError("test-only interaction handle");
        return self.state().handle.?;
    }
};

const State = struct {
    allocator: std.mem.Allocator,
    name: []const u8,
    inputs: []const backend.TypedPolynomialInputV1,
    tree_counts: [2]usize,
    profile_count: usize,
    relation_count: usize,
    batches: usize,
    program_identity: [32]u8,
    cumulative: bool,
    handle: ?*anyopaque = null,

    pub fn init(allocator: std.mem.Allocator, entry: generator.Entry) !State {
        try generator.validate(entry);
        if (entry.tree_column_counts.len < 2 or entry.program.inputs.len > std.math.maxInt(u32) or
            entry.program.lookupParameterCount() > std.math.maxInt(u32) / 4 or
            entry.program.batches.len > std.math.maxInt(u32) / 4)
            return error.InvalidFrameworkInteraction;
        const name = try generator.kernelName(allocator, entry);
        errdefer allocator.free(name);
        const inputs = try allocator.dupe(backend.TypedPolynomialInputV1, entry.program.inputs);
        return .{ .allocator = allocator, .name = name, .inputs = inputs, .tree_counts = .{ entry.tree_column_counts[0], entry.tree_column_counts[1] }, .profile_count = entry.program.profile_parameter_count, .relation_count = entry.program.lookupParameterCount(), .batches = entry.program.batches.len, .program_identity = entry.program.identity, .cumulative = entry.program.layout == .same_row_prefix_v1 };
    }
    pub fn deinit(self: *State) void {
        if (self.handle) |handle| stwo_zig_framework_interaction_destroy(handle);
        self.allocator.free(self.inputs);
        self.allocator.free(self.name);
        self.* = undefined;
    }
    pub fn prepare(self: *State, metal: *runtime.Runtime) !void {
        if (self.handle != null) return error.FrameworkInteractionAlreadyPrepared;
        const profile = metal.admitted_profile orelse return error.FrameworkInteractionUnavailable;
        if (profile != .recursive_framework_v1) return error.FrameworkInteractionUnavailable;
        for (if (self.cumulative) [_][]const u8{ self.name, "stwo_zig_framework_interaction_cumulative_block_scan_v1", "stwo_zig_framework_interaction_cumulative_scan_blocks_v1", "stwo_zig_framework_interaction_cumulative_finalize_v1" } else [_][]const u8{ self.name, "stwo_zig_framework_interaction_block_scan_v1", "stwo_zig_framework_interaction_scan_blocks_v1", "stwo_zig_framework_interaction_finalize_v1" }) |name| {
            var admitted = false;
            for (profile.exports()) |entry| if (std.mem.eql(u8, entry.name, name)) {
                admitted = true;
                break;
            };
            if (!admitted) return error.FrameworkInteractionUnavailable;
        }
        const tags = try self.allocator.alloc(u32, self.inputs.len);
        defer self.allocator.free(tags);
        for (self.inputs, tags) |input, *tag| tag.* = switch (input) {
            .trace_column => |column| column.tree_index,
            .profile_parameter => std.math.maxInt(u32),
        };
        self.handle = stwo_zig_framework_interaction_prepare(metal.handle, self.name.ptr, self.name.len, tags.ptr, @intCast(self.inputs.len), @intCast(self.profile_count), @intCast(self.relation_count * 4), @intCast(self.batches), @intFromBool(self.cumulative)) orelse return error.FrameworkInteractionUnavailable;
    }
    pub fn generate(self: *const State, trees: [2]?Tree, invocation: Invocation) !Result {
        const handle = self.handle orelse return error.FrameworkInteractionNotPrepared;
        if (invocation.trace_log_size == 0 or invocation.trace_log_size > 24 or
            invocation.profile_values.len != self.profile_count or invocation.relation_values.len != self.relation_count)
            return error.InvalidFrameworkInteraction;
        const rows = @as(usize, 1) << @intCast(invocation.trace_log_size);
        const column_words = try std.math.mul(usize, try std.math.mul(usize, self.batches, 4), rows);
        _ = try std.math.mul(usize, try std.math.add(usize, column_words, self.batches * 4), 4);
        for (invocation.profile_values) |value| if (value.toU32() >= core.fields.m31.Modulus) return error.InvalidFrameworkInteraction;
        for (invocation.relation_values) |value| for (value.toM31Array()) |coordinate|
            if (coordinate.toU32() >= core.fields.m31.Modulus) return error.InvalidFrameworkInteraction;
        // Resolve and bounds-check before allocating descriptors or GPU output.
        for (self.inputs) |input| switch (input) {
            .profile_parameter => {},
            .trace_column => |column| {
                const tree = trees[column.tree_index] orelse return error.InvalidFrameworkInteraction;
                if (tree.column_offsets.len != self.tree_counts[column.tree_index] or tree.buffer.byte_length % 4 != 0 or
                    column.column_index >= tree.column_offsets.len) return error.InvalidFrameworkInteraction;
                const offset = tree.column_offsets[column.column_index];
                if (offset > tree.buffer.byte_length / 4 or rows > tree.buffer.byte_length / 4 - offset) return error.InvalidFrameworkInteraction;
            },
        };
        const offsets = try self.allocator.alloc(u64, self.inputs.len);
        defer self.allocator.free(offsets);
        const tags = try self.allocator.alloc(u32, self.inputs.len);
        defer self.allocator.free(tags);
        for (self.inputs, offsets, tags) |input, *offset, *tag| switch (input) {
            .profile_parameter => {
                offset.* = 0;
                tag.* = std.math.maxInt(u32);
            },
            .trace_column => |column| {
                offset.* = trees[column.tree_index].?.column_offsets[column.column_index];
                tag.* = column.tree_index;
            },
        };
        const profiles = try self.allocator.alloc(u32, self.profile_count);
        defer self.allocator.free(profiles);
        for (invocation.profile_values, profiles) |value, *word| word.* = value.toU32();
        const relations = try self.allocator.alloc(u32, self.relation_count * 4);
        defer self.allocator.free(relations);
        for (invocation.relation_values, 0..) |value, index| {
            for (value.toM31Array(), 0..) |coordinate, k| relations[index * 4 + k] = coordinate.toU32();
        }
        var resident_handle: ?*anyopaque = null;
        var contents: ?*anyopaque = null;
        var bytes: usize = 0;
        var gpu_ms: f64 = 0;
        const status = stwo_zig_framework_interaction_generate(handle, if (trees[0]) |tree| tree.buffer.handle else null, if (trees[1]) |tree| tree.buffer.handle else null, tags.ptr, offsets.ptr, @intCast(offsets.len), profiles.ptr, @intCast(profiles.len), relations.ptr, @intCast(relations.len), @intCast(rows), @intCast(self.batches), &resident_handle, &contents, &bytes, &gpu_ms);
        if (status != 0) return switch (status) {
            1 => error.FrameworkInteractionZeroDenominator,
            2 => error.FrameworkInteractionInvalidSelector,
            4 => error.FrameworkInteractionNoncanonicalInput,
            else => error.FrameworkInteractionExecutionFailed,
        };
        return .{ .resident = .{ .handle = resident_handle.?, .contents = contents.?, .byte_length = bytes }, .rows = rows, .batches = self.batches, .claim_count = if (self.cumulative) 1 else self.batches, .gpu_milliseconds = gpu_ms };
    }
};
