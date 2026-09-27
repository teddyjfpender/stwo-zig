//! Exact NEW protocol transcript normalization without a whole-input cell array.
//! Descriptors own temporaries, borrow one immutable input and read cells lazily.
//! Normalization is admission metadata; only Receiver verifies the proof.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Protocol = @import("block_v5_reusable_global_public_export_protocol_v1.zig");
const Bus = @import("block_v5_global_public_export_bus_v1.zig");
const Public = @import("block_v5_global_public_export_policy_v1.zig");
const Original = @import("block_v5_heterogeneous_child_frames_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_300_200;
/// Independent source recipe for a higher-parent adapter. This value must be
/// admitted there explicitly; publishing it is never source proof authority.
pub fn sourceAuthority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x4235474e, VERSION, PUBLIC_CIRCUIT });
    inline for (.{ @embedFile("block_v5_global_public_export_normalizer_v1.zig"), @embedFile("block_v5_global_expected_public_job_v1.zig"), @embedFile("../prover/block_v5_global_expected_public_file_v1.zig"), @embedFile("block_v5_global_public_owned_receiver_v1.zig"), @embedFile("../prover/block_v5_global_public_owned_stage_v1.zig") }) |bytes| {
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes, &hash, .{});
        channel.mixRoot(hash);
    }
    channel.mixRoot(@import("block_v5_global_public_export_parent_v1.zig").sourceAuthority());
    return channel.digestBytes();
}
pub const Limits = struct { max_cells: usize = 64 << 20, max_frames: usize = 1 << 20, max_metadata_bytes: usize = 256 << 20 };
pub const Coordinate = struct { frame: u32, first_cell: u32, word_count: u32 };
pub const OriginalStart = struct { frame: u32, first_cell: u32, frame_count: u32, cell_count: u32 };
pub const WindowLayout = struct {
    pc_clock: ?Coordinate = null,
    initial: ?Coordinate = null,
    final: ?Coordinate = null,
    clocks: ?Coordinate = null,
    completion: ?Coordinate = null,
    decoded: ?Coordinate = null,
    cycles: ?Coordinate = null,
    pub fn firstCycle(self: WindowLayout) !Coordinate {
        const all = self.cycles orelse return error.MissingPublicExportCoordinate;
        return .{ .frame = all.frame, .first_cell = all.first_cell, .word_count = 2 };
    }
    pub fn lastCycle(self: WindowLayout) !Coordinate {
        const all = self.cycles orelse return error.MissingPublicExportCoordinate;
        return .{ .frame = all.frame, .first_cell = try std.math.add(u32, all.first_cell, 2), .word_count = 2 };
    }
};
const OwnedFrame = struct { frame: Original.Frame, words_owned: bool = false, felts_owned: bool = false };
fn operationCount(operation: Original.Operation) !u32 {
    const count: usize = switch (operation) {
        .words => |v| v.len,
        .root => 8,
        .integer => 2,
        .felts => |v| try std.math.mul(usize, v.len, 4),
    };
    return std.math.cast(u32, count) orelse error.PublicExportNormalizerResourceLimit;
}
fn operationsEqual(a: Original.Operation, b: Original.Operation) bool {
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
fn anchorStart(frames: []const Original.Frame, cell_count: u32, operation: Original.Operation, coordinate: Coordinate) !?OriginalStart {
    if (operation != .words) return null;
    if (frames.len == 0 or frames[0].first != 0 or frames[0].operation != .words or frames[0].operation.words.len == 0) return error.MissingOriginalPublicFrame;
    const first = frames[0].operation.words;
    if (operation.words.ptr != first.ptr or operation.words.len != first.len) return null;
    return .{ .frame = coordinate.frame, .first_cell = coordinate.first_cell, .frame_count = std.math.cast(u32, frames.len) orelse return error.PublicExportNormalizerResourceLimit, .cell_count = cell_count };
}
pub const Normalized = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget = null,
    frames: []OwnedFrame,
    windows: []WindowLayout,
    terms: [][3]Bus.ExportCell,
    originals: []?OriginalStart = &.{},
    cell_count: u32,
    input: ?Coordinate,
    key_id: [32]u8,
    public_input_digest: [32]u8,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Normalized) void {
        const allocation_owner = self.allocation_owner;
        for (self.frames) |owned| {
            if (owned.words_owned) self.allocator.free(owned.frame.operation.words);
            if (owned.felts_owned) self.allocator.free(owned.frame.operation.felts);
        }
        self.allocator.free(self.frames);
        self.allocator.free(self.windows);
        self.allocator.free(self.terms);
        self.allocator.free(self.originals);
        self.* = undefined;
        if (allocation_owner) |owner| owner.destroy();
    }
    pub fn cell(self: *const Normalized, coordinate: u32) ![4]M {
        if (coordinate >= self.cell_count) return error.InvalidPublicExportCoordinate;
        // Upper bound chooses the LAST duplicate start. Empty calls preceding
        // a nonempty frame therefore remain in the exact transcript grammar
        // without adding a linear scan to every byte lookup.
        var first: usize = 0;
        var end: usize = self.frames.len;
        while (first < end) {
            const middle = first + (end - first) / 2;
            if (self.frames[middle].frame.first <= coordinate) first = middle + 1 else end = middle;
        }
        if (first == 0) return error.InvalidPublicExportCoordinate;
        const frame = self.frames[first - 1].frame;
        const offset = coordinate - frame.first;
        const word: u32 = switch (frame.operation) {
            .words => |words| if (offset < words.len) words[offset] else return error.InvalidPublicExportCoordinate,
            .root => |root| if (offset < 8) std.mem.readInt(u32, root[4 * @as(usize, offset) ..][0..4], .little) else return error.InvalidPublicExportCoordinate,
            .integer => |value| if (offset == 0) @truncate(value) else if (offset == 1) @truncate(value >> 32) else return error.InvalidPublicExportCoordinate,
            .felts => |values| if (offset / 4 < values.len) values[offset / 4].toM31Array()[offset % 4].v else return error.InvalidPublicExportCoordinate,
        };
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, part| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * part))) & 255);
        return bytes;
    }
    pub fn window(self: *const Normalized, index: u32) !WindowLayout {
        if (index >= self.windows.len) return error.InvalidPublicExportCoordinate;
        return self.windows[index];
    }
    pub fn exportTerms(self: *const Normalized, index: u32) ![3]Bus.ExportCell {
        if (index >= self.terms.len) return error.InvalidPublicExportCoordinate;
        return self.terms[index];
    }
    pub fn frameAt(self: *const Normalized, index: u32) !Original.Frame {
        if (index >= self.frames.len) return error.InvalidPublicExportCoordinate;
        return self.frames[index].frame;
    }
    /// Translate a qualified semantic source cell to the ACTUAL new lower
    /// public statement. Never search for an equal root/value in other frames.
    pub fn originalCell(self: *const Normalized, child: u32, coordinate: u32) !u32 {
        if (child >= self.originals.len) return error.InvalidPublicExportCoordinate;
        const start = self.originals[child] orelse return error.MissingOriginalPublicFrame;
        if (coordinate >= start.cell_count) return error.InvalidPublicExportCoordinate;
        return std.math.add(u32, start.first_cell, coordinate);
    }
    pub fn originalFrame(self: *const Normalized, child: u32, ordinal: u32) !Coordinate {
        if (child >= self.originals.len) return error.InvalidPublicExportCoordinate;
        const start = self.originals[child] orelse return error.MissingOriginalPublicFrame;
        if (ordinal >= start.frame_count) return error.InvalidPublicExportCoordinate;
        const index = try std.math.add(u32, start.frame, ordinal);
        const operation = try self.frameAt(index);
        return .{ .frame = index, .first_cell = operation.first, .word_count = try operationCount(operation.operation) };
    }
    /// Replace the borrowed input with an equal independently admitted owner's
    /// immutable vector. Caller retains that owner through normalized deinit.
    pub fn rehomeInput(self: *Normalized, input: []const u32) !void {
        const coordinate = self.input orelse {
            if (input.len != 0) return error.UntrustedPublicExportNormalizer;
            return;
        };
        if (coordinate.frame >= self.frames.len) return error.UntrustedPublicExportNormalizer;
        const owned = &self.frames[coordinate.frame];
        if (owned.words_owned or owned.frame.operation != .words or !std.mem.eql(u32, owned.frame.operation.words, input)) return error.UntrustedPublicExportNormalizer;
        owned.frame.operation = .{ .words = input };
    }
    pub fn validate(self: *const Normalized, admission: *const Protocol.Admission) !void {
        try admission.validate();
        const children = admission.values.public.policy.original.children;
        if (!std.meta.eql(self.key_id, admission.expected_id) or !std.meta.eql(self.public_input_digest, try admission.publicInputIdentity()) or self.windows.len != admission.values.public.fields.len or self.terms.len != self.windows.len or self.originals.len != children.len) return error.UntrustedPublicExportNormalizer;
        var comparison = Compare{ .normalized = self, .fields = admission.values.public.fields, .children = children };
        try admission.mix(&comparison);
        if (comparison.failure) |failure| return failure;
        if (comparison.at != self.frames.len or comparison.cells != self.cell_count) return error.UntrustedPublicExportNormalizer;
        for (children, self.originals) |child, optional| {
            const start = optional orelse return error.MissingOriginalPublicFrame;
            if (start.frame_count != child.frames.len or start.cell_count != child.cells.len) return error.UntrustedPublicExportNormalizer;
            for (child.frames, 0..) |frame, ordinal| {
                const root_frame = try self.frameAt(try std.math.add(u32, start.frame, @as(u32, @intCast(ordinal))));
                if (root_frame.first != try std.math.add(u32, start.first_cell, frame.first) or !operationsEqual(root_frame.operation, frame.operation)) return error.UntrustedPublicExportNormalizer;
            }
        }
        for (self.windows) |layout| inline for (std.meta.fields(WindowLayout)) |field| {
            if (@field(layout, field.name) == null) return error.MissingPublicExportCoordinate;
        };
        const term_layout = try admission.exportLayout();
        for (0..self.windows.len) |index| {
            const terms = try term_layout.at(@intCast(index));
            if (!std.meta.eql(terms, self.terms[index])) return error.UntrustedPublicExportNormalizer;
            for (terms) |term| {
                if (term.frame >= self.frames.len or self.frames[term.frame].frame.operation != .felts or term.index >= self.frames[term.frame].frame.operation.felts.len or term.first_cell != self.frames[term.frame].frame.first + 4 * term.index) return error.UntrustedPublicExportNormalizer;
            }
        }
    }
    /// Routed actual hash input cells in a future higher parent. Caller must
    /// supply this same normalized public statement to its authenticated bus.
    pub fn replay(self: *const Normalized, recorder: *@import("air/blake3_native_recorder.zig").Recorder) void {
        for (self.frames) |owned| {
            const frame = owned.frame;
            const source = @import("air/blake3_transcript_witness.zig").Caller{ .circuit = PUBLIC_CIRCUIT, .first_wire = frame.first };
            switch (frame.operation) {
                .words => |v| recorder.mixPublicWords(source, v),
                .root => |v| recorder.mixPublicRoot(source, v),
                .integer => |v| recorder.mixPublicInteger(source, v),
                .felts => |v| recorder.mixPublicFelts(source, v),
            }
        }
    }
};
const Collector = struct {
    a: std.mem.Allocator,
    fields: []const @import("block_v5_global_public_fields_v1.zig").Fields,
    children: []const Original.Child = &.{},
    originals: []?OriginalStart = &.{},
    limits: Limits,
    frames: std.ArrayList(OwnedFrame) = .empty,
    windows: []WindowLayout,
    cells: usize = 0,
    bytes: usize = 0,
    input: ?Coordinate = null,
    failure: ?anyerror = null,
    fn deinit(self: *Collector) void {
        for (self.frames.items) |owned| {
            if (owned.words_owned) self.a.free(owned.frame.operation.words);
            if (owned.felts_owned) self.a.free(owned.frame.operation.felts);
        }
        self.frames.deinit(self.a);
    }
    fn append(self: *Collector, operation: Original.Operation) !void {
        const count: usize = switch (operation) {
            .words => |v| v.len,
            .root => 8,
            .integer => 2,
            .felts => |v| try std.math.mul(usize, v.len, 4),
        };
        const end = try std.math.add(usize, self.cells, count);
        if (end > self.limits.max_cells or end >= core.fields.m31.Modulus or self.frames.items.len >= self.limits.max_frames) return error.PublicExportNormalizerResourceLimit;
        const borrowed = operation == .words and operation.words.len != 0 and operation.words.ptr == self.fields[0].borrowed_input.ptr and operation.words.len == self.fields[0].borrowed_input.len;
        const extra: usize = switch (operation) {
            .words => |v| if (borrowed) 0 else try std.math.mul(usize, v.len, @sizeOf(u32)),
            .felts => |v| try std.math.mul(usize, v.len, @sizeOf(Q)),
            else => 0,
        };
        const extent = try std.math.add(usize, self.bytes, try std.math.add(usize, extra, @sizeOf(OwnedFrame)));
        if (extent > self.limits.max_metadata_bytes) return error.PublicExportNormalizerResourceLimit;
        const coordinate = Coordinate{ .frame = @intCast(self.frames.items.len), .first_cell = @intCast(self.cells), .word_count = @intCast(count) };
        if (operation == .words) for (self.children, self.originals) |child, *start| {
            const found = try anchorStart(child.frames, @intCast(child.cells.len), operation, coordinate) orelse continue;
            if (start.* != null) return error.RepeatedOriginalPublicFrame;
            start.* = found;
        };
        var owned = OwnedFrame{ .frame = .{ .first = @intCast(self.cells), .operation = operation } };
        errdefer {
            if (owned.words_owned) self.a.free(owned.frame.operation.words);
            if (owned.felts_owned) self.a.free(owned.frame.operation.felts);
        }
        switch (operation) {
            .words => |words| {
                if (borrowed) {
                    if (self.input != null) return error.RepeatedPublicInputVector;
                    self.input = coordinate;
                } else {
                    owned.frame.operation = .{ .words = try self.a.dupe(u32, words) };
                    owned.words_owned = true;
                }
                for (self.fields, self.windows) |field, *layout| inline for (std.meta.fields(WindowLayout)) |slot| {
                    const original_first = @field(field.layout, slot.name);
                    for (field.chunks) |chunk| if (chunk.first == original_first and chunk.words.len != 0 and chunk.words.ptr == words.ptr and chunk.words.len == words.len) {
                        if (@field(layout, slot.name) != null) return error.RepeatedPublicExportCoordinate;
                        @field(layout, slot.name) = coordinate;
                    };
                };
            },
            .felts => |values| {
                owned.frame.operation = .{ .felts = try self.a.dupe(Q, values) };
                owned.felts_owned = true;
            },
            else => {},
        }
        try self.frames.ensureTotalCapacityPrecise(self.a, try std.math.add(usize, self.frames.items.len, 1));
        self.frames.appendAssumeCapacity(owned);
        self.cells = end;
        self.bytes = extent;
    }
    pub fn mixU32s(self: *Collector, v: []const u32) void {
        if (self.failure != null) return;
        self.append(.{ .words = v }) catch |failure| {
            self.failure = failure;
        };
    }
    pub fn mixRoot(self: *Collector, v: [32]u8) void {
        if (self.failure != null) return;
        self.append(.{ .root = v }) catch |failure| {
            self.failure = failure;
        };
    }
    pub fn mixU64(self: *Collector, v: u64) void {
        if (self.failure != null) return;
        self.append(.{ .integer = v }) catch |failure| {
            self.failure = failure;
        };
    }
    pub fn mixFelts(self: *Collector, v: []const Q) void {
        if (self.failure != null) return;
        self.append(.{ .felts = v }) catch |failure| {
            self.failure = failure;
        };
    }
};
const Compare = struct {
    normalized: *const Normalized,
    fields: []const @import("block_v5_global_public_fields_v1.zig").Fields,
    children: []const Original.Child = &.{},
    at: usize = 0,
    cells: u32 = 0,
    failure: ?anyerror = null,
    fn check(self: *Compare, operation: Original.Operation) void {
        if (self.failure != null) return;
        if (self.at >= self.normalized.frames.len) {
            self.failure = error.UntrustedPublicExportNormalizer;
            return;
        }
        const frame = self.normalized.frames[self.at].frame;
        if (frame.first != self.cells or std.meta.activeTag(frame.operation) != std.meta.activeTag(operation)) {
            self.failure = error.UntrustedPublicExportNormalizer;
            return;
        }
        const equal = operationsEqual(operation, frame.operation);
        if (!equal) {
            self.failure = error.UntrustedPublicExportNormalizer;
            return;
        }
        if (operation == .words) {
            const words = operation.words;
            const coordinate = Coordinate{ .frame = @intCast(self.at), .first_cell = self.cells, .word_count = @intCast(words.len) };
            for (self.children, self.normalized.originals) |child, optional| {
                const expected = anchorStart(child.frames, @intCast(child.cells.len), operation, coordinate) catch |failure| {
                    self.failure = failure;
                    return;
                } orelse continue;
                if (optional == null or !std.meta.eql(optional.?, expected)) {
                    self.failure = error.UntrustedPublicExportNormalizer;
                    return;
                }
            }
            const input = self.fields[0].borrowed_input;
            if (words.len != 0 and words.ptr == input.ptr and words.len == input.len) {
                if (self.normalized.input == null or !std.meta.eql(self.normalized.input.?, coordinate)) {
                    self.failure = error.UntrustedPublicExportNormalizer;
                    return;
                }
            }
            for (self.fields, self.normalized.windows) |field, layout| inline for (std.meta.fields(WindowLayout)) |slot| {
                const first = @field(field.layout, slot.name);
                for (field.chunks) |chunk| if (chunk.first == first and chunk.words.len != 0 and chunk.words.ptr == words.ptr and chunk.words.len == words.len) {
                    if (@field(layout, slot.name) == null or !std.meta.eql(@field(layout, slot.name).?, coordinate)) {
                        self.failure = error.UntrustedPublicExportNormalizer;
                        return;
                    }
                };
            };
        }
        const count: usize = switch (operation) {
            .words => |v| v.len,
            .root => 8,
            .integer => 2,
            .felts => |v| std.math.mul(usize, v.len, 4) catch {
                self.failure = error.Overflow;
                return;
            },
        };
        self.cells = std.math.add(u32, self.cells, std.math.cast(u32, count) orelse {
            self.failure = error.Overflow;
            return;
        }) catch {
            self.failure = error.Overflow;
            return;
        };
        self.at += 1;
    }
    pub fn mixU32s(self: *Compare, v: []const u32) void {
        self.check(.{ .words = v });
    }
    pub fn mixRoot(self: *Compare, v: [32]u8) void {
        self.check(.{ .root = v });
    }
    pub fn mixU64(self: *Compare, v: u64) void {
        self.check(.{ .integer = v });
    }
    pub fn mixFelts(self: *Compare, v: []const Q) void {
        self.check(.{ .felts = v });
    }
};
pub fn normalize(a: std.mem.Allocator, admission: *const Protocol.Admission, limits: Limits) !Normalized {
    try admission.validate();
    const allocation_owner = Budget.fromAllocator(a);
    if (allocation_owner) |owner| _ = owner.retain();
    errdefer if (allocation_owner) |owner| owner.destroy();
    const children = admission.values.public.policy.original.children;
    const layout_bytes = try std.math.add(usize, try std.math.mul(usize, admission.values.public.fields.len, @sizeOf(WindowLayout) + @sizeOf([3]Bus.ExportCell)), try std.math.mul(usize, children.len, @sizeOf(?OriginalStart)));
    if (layout_bytes > limits.max_metadata_bytes) return error.PublicExportNormalizerResourceLimit;
    const windows = try a.alloc(WindowLayout, admission.values.public.fields.len);
    errdefer a.free(windows);
    @memset(windows, .{});
    const terms = try a.alloc([3]Bus.ExportCell, windows.len);
    errdefer a.free(terms);
    const term_layout = try admission.exportLayout();
    for (terms, 0..) |*entry, index| entry.* = try term_layout.at(@intCast(index));
    const originals = try a.alloc(?OriginalStart, children.len);
    errdefer a.free(originals);
    @memset(originals, null);
    var collector = Collector{ .a = a, .fields = admission.values.public.fields, .children = children, .originals = originals, .limits = limits, .windows = windows, .bytes = layout_bytes };
    defer collector.deinit();
    try admission.mix(&collector);
    if (collector.failure) |failure| return failure;
    const public_input_digest = try admission.publicInputIdentity();
    const frames = try collector.frames.toOwnedSlice(a);
    errdefer {
        for (frames) |owned| {
            if (owned.words_owned) a.free(owned.frame.operation.words);
            if (owned.felts_owned) a.free(owned.frame.operation.felts);
        }
        a.free(frames);
    }
    var result = Normalized{ .allocator = a, .allocation_owner = allocation_owner, .frames = frames, .windows = windows, .terms = terms, .originals = originals, .cell_count = @intCast(collector.cells), .input = collector.input, .key_id = admission.expected_id, .public_input_digest = public_input_digest };
    if (admission.values.public.fields[0].borrowed_input.len != 0 and result.input == null) return error.MissingPublicExportCoordinate;
    try result.validate(admission);
    return result;
}

// These are descriptor/byte fixtures only. They never construct a fake
// Protocol.Admission, proof receipt or successful cryptographic receiver.
fn descriptorFixture(a: std.mem.Allocator) !void {
    const P = @import("../air/public_data.zig");
    const F = @import("block_v5_global_public_fields_v1.zig");
    const input = [_]u32{ 0xffee12a5, 0x80000000 };
    const data = P.Blake3PublicData{ .initial_pc = 0x1000, .final_pc = 0x1004, .clock = 2, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(0xA5) }, .initial_rw_root = null, .final_rw_root = null, .completion = P.Completion.canonicalSelfLoop(0x1004), .io_entries = .{ .input_start = 0x10000, .input_len = 8, .input_words = &input, .output_len = 0, .output_len_addr = 0x20000, .output_data_addr = 0x20004, .output_words = &.{} } };
    var fields: [2]F.Fields = undefined;
    fields[0] = try F.init(a, &data, .rv32im_zkvm_v1, 0x100000001, 0x100000002, .{});
    defer fields[0].deinit();
    fields[1] = try F.init(a, &data, .rv32im_zkvm_v1, 0x200000003, 0x200000004, .{});
    defer fields[1].deinit();
    const layouts = try a.alloc(WindowLayout, 2);
    defer a.free(layouts);
    @memset(layouts, .{});
    var collector = Collector{ .a = a, .fields = &fields, .limits = .{}, .windows = layouts };
    defer collector.deinit();
    collector.mixU32s(&input);
    for (fields) |field| for (field.chunks, 0..) |chunk, index| {
        if (index != 12) collector.mixU32s(chunk.words);
    };
    if (collector.failure) |failure| return failure;
    const frames = try collector.frames.toOwnedSlice(a);
    // Only owned descriptors/cell arithmetic is checked. The placeholder IDs
    // below have no proof authority and never enter normalize/receiver.
    var normalized = Normalized{ .allocator = a, .frames = frames, .windows = &.{}, .terms = &.{}, .cell_count = @intCast(collector.cells), .input = collector.input, .key_id = @splat(0), .public_input_digest = @splat(0) };
    defer normalized.deinit();
    normalized.windows = layouts;
    defer normalized.windows = &.{};
    try std.testing.expect(!normalized.frames[normalized.input.?.frame].words_owned);
    try std.testing.expectEqual(@as(u32, 2), normalized.input.?.word_count);
    const first = try (try normalized.window(0)).firstCycle();
    const last = try (try normalized.window(1)).lastCycle();
    try std.testing.expectEqual(@as(u32, 1), wordOf(try normalized.cell(first.first_cell)));
    try std.testing.expectEqual(@as(u32, 1), wordOf(try normalized.cell(first.first_cell + 1)));
    try std.testing.expectEqual(@as(u32, 4), wordOf(try normalized.cell(last.first_cell)));
    try std.testing.expectEqual(@as(u32, 2), wordOf(try normalized.cell(last.first_cell + 1)));
    var comparison = Compare{ .normalized = &normalized, .fields = &fields };
    comparison.mixU32s(&input);
    for (fields) |field| for (field.chunks, 0..) |chunk, index| {
        if (index != 12) comparison.mixU32s(chunk.words);
    };
    if (comparison.failure) |failure| return failure;
    const old = layouts[0].cycles;
    layouts[0].cycles.?.first_cell = layouts[0].decoded.?.first_cell;
    comparison = .{ .normalized = &normalized, .fields = &fields };
    comparison.mixU32s(&input);
    for (fields) |field| for (field.chunks, 0..) |chunk, index| {
        if (index != 12) comparison.mixU32s(chunk.words);
    };
    try std.testing.expectEqual(error.UntrustedPublicExportNormalizer, comparison.failure.?);
    layouts[0].cycles = old;
}
fn wordOf(bytes: [4]M) u32 {
    var result: u32 = 0;
    for (bytes, 0..) |byte, part| {
        result |= byte.v << @as(u5, @intCast(8 * part));
    }
    return result;
}
test "global expected public: exact lazy full-u64 descriptors reject changed cycle source" {
    try descriptorFixture(std.testing.allocator);
}
test "global expected public: lazy descriptor construction exhaustively rolls back allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, descriptorFixture, .{});
}

test "global expected public: actual new public serializer crosses old one-million-cell bound with one borrowed input" {
    const a = std.testing.allocator;
    const P = @import("../air/public_data.zig");
    const F = @import("block_v5_global_public_fields_v1.zig");
    const C = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
    const count = (1 << 20) + 1;
    const input = try a.alloc(u32, count);
    defer a.free(input);
    @memset(input, 0);
    input[count - 1] = 0xfeed1234;
    const data = P.Blake3PublicData{ .initial_pc = 0x1000, .final_pc = 0x1004, .clock = 2, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(0xA5) }, .initial_rw_root = null, .final_rw_root = null, .completion = P.Completion.canonicalSelfLoop(0x1004), .io_entries = .{ .input_start = 0x10000, .input_len = count * 4, .input_words = input, .output_len = 0, .output_len_addr = 0x800000, .output_data_addr = 0x800004, .output_words = &.{} } };
    var fields = [_]F.Fields{try F.init(a, &data, .rv32im_zkvm_v1, 1, 2, .{})};
    defer fields[0].deinit();
    var layouts = [_]WindowLayout{.{}};
    const config = @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var sources: [C.SOURCE_COUNT]C.SourceRequirement = undefined;
    for (&sources, 0..) |*source, index| source.* = .{ .kind = @enumFromInt(index), .identity = @splat(0), .count = 0 };
    // Incomplete zero-child PUBLIC proposal solely to exercise the actual
    // serializer. It is NOT an admitted Protocol, proof, positive Policy or
    // receiver fixture, and cannot pass the genuine Policy.validate route.
    const plan = C.Plan{ .a = a, .meta = .{ .version = C.VERSION, .recipe = .custody_v2, .native_protocol = .capacity_v1, .security = .{ .base = config, .recursive = config }, .seal_digest = @splat(0), .ram_events = 0, .program_fetches = 0, .register_window_version = 1, .fan_in = .pair, .logical = &.{}, .mappings = &.{}, .physical = &.{}, .sources = sources, .nodes = &.{}, .root = .{ .leaf = 0 } }, .logical_owner = &.{}, .mappings_owner = &.{}, .physical_owner = &.{}, .nodes_owner = &.{}, .pinned_digest = @splat(0xAA) };
    const W = @import("../prover/block_v5_register_windows_v1.zig").Window;
    const windows = [_]W{W.fromPublic(0, 1, &data)};
    var terms = [_]Public.Terms{.{ Q.zero(), Q.zero(), Q.zero() }};
    const owner = Public.Owner{ .allocator = a, .policy = .{ .original = .{ .plan = &plan, .children = &.{}, .expected = &.{} }, .windows = .{ .version = 1, .initial_registers = data.initial_regs, .final_registers = data.final_regs, .windows = &windows } }, .fields = &fields, .terms = &terms };
    const values = Bus.Values{ .public = &owner };
    try std.testing.expectError(error.MutatedV5CoverageIndependentPolicy, values.validate());
    var collector = Collector{ .a = a, .fields = &fields, .limits = .{ .max_cells = 64 << 20, .max_metadata_bytes = 64 << 10 }, .windows = &layouts };
    defer collector.deinit();
    values.mix(&collector);
    if (collector.failure) |failure| return failure;
    try std.testing.expect(collector.cells > Original.LIMIT);
    try std.testing.expect(collector.bytes < 64 << 10);
    try std.testing.expectEqual(@as(u32, count), collector.input.?.word_count);
    const frames = try collector.frames.toOwnedSlice(a);
    var normalized = Normalized{ .allocator = a, .frames = frames, .windows = &.{}, .terms = &.{}, .cell_count = @intCast(collector.cells), .input = collector.input, .key_id = @splat(0), .public_input_digest = @splat(0) };
    defer normalized.deinit();
    normalized.windows = &layouts;
    defer normalized.windows = &.{};
    try std.testing.expectEqual(@as(u32, 0xfeed1234), wordOf(try normalized.cell(normalized.input.?.first_cell + count - 1)));
    var comparison = Compare{ .normalized = &normalized, .fields = &fields };
    values.mix(&comparison);
    if (comparison.failure) |failure| return failure;
    var reference = core.channel.blake3.Channel{};
    values.mix(&reference);
    var replay = core.channel.blake3.Channel{};
    for (normalized.frames) |owned| switch (owned.frame.operation) {
        .words => |v| replay.mixU32s(v),
        .root => |v| replay.mixRoot(v),
        .integer => |v| replay.mixU64(v),
        .felts => |v| replay.mixFelts(v),
    };
    try std.testing.expectEqualSlices(u8, &reference.digestBytes(), &replay.digestBytes());
}

test "global expected public: binary cell lookup handles first last and duplicate empty frames after allocator owner release" {
    const shared = try Budget.create(std.testing.allocator, 4096);
    const a = shared.allocator();
    const frames = try a.alloc(OwnedFrame, 7);
    const words = [_]u32{ 0xffffffff, 0x80000000 };
    const felts = [_]Q{Q.fromU32Unchecked(1, 2, 3, 4)};
    frames[0] = .{ .frame = .{ .first = 0, .operation = .{ .words = &.{} } } };
    frames[1] = .{ .frame = .{ .first = 0, .operation = .{ .words = &words } } };
    frames[2] = .{ .frame = .{ .first = 2, .operation = .{ .words = &.{} } } };
    frames[3] = .{ .frame = .{ .first = 2, .operation = .{ .integer = 0x0123456789abcdef } } };
    frames[4] = .{ .frame = .{ .first = 4, .operation = .{ .words = &.{} } } };
    frames[5] = .{ .frame = .{ .first = 4, .operation = .{ .felts = &felts } } };
    frames[6] = .{ .frame = .{ .first = 8, .operation = .{ .words = &.{} } } };
    // Descriptor fixture only. No fake admission/capture is constructed.
    var normalized = Normalized{ .allocator = a, .allocation_owner = shared.retain(), .frames = frames, .windows = &.{}, .terms = &.{}, .cell_count = 8, .input = null, .key_id = @splat(0), .public_input_digest = @splat(0) };
    shared.destroy();
    defer normalized.deinit();
    const expected = [_]u32{ 0xffffffff, 0x80000000, 0x89abcdef, 0x01234567, 1, 2, 3, 4 };
    for (expected, 0..) |word, index| try std.testing.expectEqual(word, wordOf(try normalized.cell(@intCast(index))));
    try std.testing.expectError(error.InvalidPublicExportCoordinate, normalized.cell(8));
    try std.testing.expectError(error.InvalidPublicExportCoordinate, normalized.cell(std.math.maxInt(u32)));
}

test "global expected public: original typed frame locator rejects equal-value unrelated spans and preserves claim coordinates" {
    const a = std.testing.allocator;
    const header = try a.dupe(u32, &.{ 0x42354350, 1, 1 });
    defer a.free(header);
    const unrelated = try a.dupe(u32, header);
    defer a.free(unrelated);
    const claim = [_]Q{Q.fromU32Unchecked(1, 2, 3, 4)};
    const original = [_]Original.Frame{ .{ .first = 0, .operation = .{ .words = header } }, .{ .first = 3, .operation = .{ .root = @splat(0x55) } }, .{ .first = 11, .operation = .{ .felts = &claim } } };
    const coordinate = Coordinate{ .frame = 2, .first_cell = 10, .word_count = 3 };
    try std.testing.expect((try anchorStart(&original, 15, .{ .words = unrelated }, coordinate)) == null);
    const start = (try anchorStart(&original, 15, .{ .words = header }, coordinate)).?;
    const frames = try a.alloc(OwnedFrame, 5);
    var frames_owned = true;
    defer if (frames_owned) a.free(frames);
    const starts = try a.alloc(?OriginalStart, 1);
    var starts_owned = true;
    defer if (starts_owned) a.free(starts);
    starts[0] = start;
    frames[0] = .{ .frame = .{ .first = 0, .operation = .{ .root = @splat(0x77) } } };
    frames[1] = .{ .frame = .{ .first = 8, .operation = .{ .integer = 123 } } };
    for (original, frames[2..]) |source, *destination| destination.* = .{ .frame = .{ .first = 10 + source.first, .operation = source.operation } };
    // Metadata-only fixture, never passed to a positive verifier/admission.
    var normalized = Normalized{ .allocator = a, .frames = frames, .windows = &.{}, .terms = &.{}, .originals = starts, .cell_count = 25, .input = null, .key_id = @splat(0), .public_input_digest = @splat(0) };
    frames_owned = false;
    starts_owned = false;
    defer normalized.deinit();
    try std.testing.expectEqual(@as(u32, 21), try normalized.originalCell(0, 11));
    const mapped = try normalized.originalFrame(0, 2);
    try std.testing.expectEqual(@as(u32, 4), mapped.frame);
    try std.testing.expectEqual(@as(u32, 21), mapped.first_cell);
    try std.testing.expectEqual(@as(u32, 4), mapped.word_count);
    for (0..4) |limb| try std.testing.expectEqual(@as(u32, @intCast(limb + 1)), wordOf(try normalized.cell(mapped.first_cell + @as(u32, @intCast(limb)))));
    try std.testing.expectError(error.InvalidPublicExportCoordinate, normalized.originalCell(0, 15));
    try std.testing.expectError(error.InvalidPublicExportCoordinate, normalized.originalFrame(0, 3));
}
