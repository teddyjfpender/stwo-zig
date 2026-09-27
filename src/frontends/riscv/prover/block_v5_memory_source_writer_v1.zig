//! Production prechallenge source files from a complete initial image and a
//! canonical sorted replay. Returned pins are candidate metadata, never proofs.
//! No allocation is proportional to transitions, first touches or endpoints.
const std = @import("std");
const replay = @import("block_memory_replay.zig");
const sorted_mod = @import("block_v5_memory_replay_adapter_v1.zig");
const transition = @import("../air/block/memory_transition.zig");
const layout_mod = @import("../runner/memory_state.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const sparse = @import("block_v5_sparse_state_stream_v1.zig");
const initial = @import("block_v5_initial_sources_v1.zig");
const endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
const registers = @import("block_v5_register_endpoints_v1.zig");
pub const SortedSource = sorted_mod.SortedSource;
pub const filenames = [_][]const u8{ "v5-input-words.bin", "v5-initial-rw.bin", "v5-first-touches.bin", "v5-rw-endpoints.bin" };
/// Fixed logical workspace allowance for four 8 KiB output buffers, the
/// bounded replay reader, final-file buffer and depth30 sparse traversal.
/// Caller-owned replay/initial-image allocations remain outside this bound.
pub const WORKSPACE_BOUND_BYTES: u64 = 128 * 1024;

pub const Caps = struct {
    /// Borrowed initial image is admitted before traversal, not copied.
    max_initial_words: u64 = initial.MAX_RW_WORDS + initial.MAX_INPUT_WORDS,
    max_events: u64 = 1_000_000_000,
    max_first_touches: u64 = initial.MAX_TOUCHES,
    /// Aggregate length of the four files, checked before every write.
    max_file_bytes: u64 = 512 * 1024 * 1024,
    max_workspace_bytes: u64 = WORKSPACE_BOUND_BYTES,
};
pub const Input = struct {
    layout: layout_mod.MemoryLayout,
    /// Full runner initial image, including untouched words and program words.
    /// Program words are independently classified then excluded from RW files.
    initial_words: []const replay.InitialWord,
    public_input: []const u8,
    initial_registers: [32]u32,
    expected_final_registers: [32]u32,
    expected_initial_rw_root: [32]u8,
    expected_final_rw_root: [32]u8,
    expected_total_events: u64,
    register_custody_mode: u32 = 0,
    register_window_plan_digest: [32]u8 = @splat(0),
    caps: Caps = .{},
};
pub const Result = struct {
    initial_pins: initial.Pins,
    endpoint_file_pin: initial.FilePin,
    register_pins: registers.Pins,
    final_rw_root: [32]u8,
    event_count: u64,
    file_bytes: u64,
    opened: [4]std.fs.File,
    register_custody_mode: u32 = 0,
    register_window_plan_digest: [32]u8 = @splat(0),

    pub fn registerPlanDigest(self: *const Result) ![32]u8 {
        return if (self.register_custody_mode == 1) self.register_window_plan_digest else self.register_pins.digest();
    }

    pub fn files(self: *const Result) endpoint.Sources {
        return .{ .initial = .{ .input_words = self.opened[0], .rw_words = self.opened[1], .first_touches = self.opened[2] }, .endpoints = self.opened[3] };
    }
    /// Bind the actual roots-only memory plan after its independently sized
    /// census completes. The driver must pin these candidates before B5SS.
    pub fn endpointPins(self: *const Result, memory_plan_digest: [32]u8) endpoint.Pins {
        return .{ .initial = self.initial_pins, .memory_plan_digest = memory_plan_digest, .expected_final_rw_root = self.final_rw_root, .endpoints = self.endpoint_file_pin };
    }
    pub fn deinit(self: *Result) void {
        for (self.opened) |file| file.close();
        self.* = undefined;
    }
};

const FileWriter = struct {
    file: std.fs.File,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    records: u64 = 0,
    buffer: [8192]u8 = undefined,
    used: usize = 0,
    fn append(self: *FileWriter, bytes: []const u8, total_bytes: *u64, cap: u64, max_records: u64) !void {
        if (self.records >= max_records) return error.V5SourceFileCapExceeded;
        const next_bytes = try std.math.add(u64, total_bytes.*, bytes.len);
        if (next_bytes > cap) return error.V5SourceFileCapExceeded;
        if (bytes.len > self.buffer.len) return error.V5SourceFileCapExceeded;
        if (self.used + bytes.len > self.buffer.len) try self.flush();
        @memcpy(self.buffer[self.used..][0..bytes.len], bytes);
        self.used += bytes.len;
        self.hash.update(bytes);
        self.records += 1;
        total_bytes.* = next_bytes;
    }
    fn flush(self: *FileWriter) !void {
        try self.file.writeAll(self.buffer[0..self.used]);
        self.used = 0;
    }
    fn pin(self: *const FileWriter) initial.FilePin {
        var hash = self.hash;
        return .{ .sha256 = hash.finalResult(), .records = self.records };
    }
};

/// Early source-policy admission, before native/caller work or event sorting.
/// This validates metadata and the complete initial-image classification only;
/// it neither creates files nor authenticates the sparse initial/final roots.
/// `write` still recomputes both independently pinned full-image roots.
pub fn validateInitial(input: Input) !initial.Pins {
    if (input.register_custody_mode > 1 or (input.register_custody_mode == 0 and !std.meta.eql(input.register_window_plan_digest, @as([32]u8, @splat(0))))) return error.InvalidV5RegisterCustodyMode;
    const provisional = initial.Pins{ .layout = input.layout, .initial_rw_root = input.expected_initial_rw_root, .initial_registers = input.initial_registers, .public_input_sha256 = initial.sha256(input.public_input), .public_input_len = input.public_input.len, .input_words = .{ .sha256 = @splat(0), .records = 0 }, .rw_words = .{ .sha256 = @splat(0), .records = 0 }, .first_touches = .{ .sha256 = @splat(0), .records = 0 } };
    try provisional.validate();
    if (input.initial_words.len > input.caps.max_initial_words or input.expected_total_events > input.caps.max_events or input.caps.max_first_touches > initial.MAX_TOUCHES or input.caps.max_workspace_bytes < WORKSPACE_BOUND_BYTES) return error.V5SourceFileCapExceeded;
    if (input.expected_final_registers[0] != 0) return error.InvalidV5RegisterEndpointPolicy;
    try validateImage(input, provisional);
    return provisional;
}

pub fn write(dir: std.fs.Dir, input: Input, sorted: SortedSource) !Result {
    if (input.register_custody_mode == 1 and std.meta.eql(input.register_window_plan_digest, @as([32]u8, @splat(0)))) return error.MissingV5RegisterWindowPlan;
    var provisional = try validateInitial(input);
    var image = Image.init(input, provisional);
    const max_initial_leaves = try std.math.add(u64, input.caps.max_initial_words, initial.MAX_INPUT_WORDS);
    const initial_root = try sparse.root(&image, max_initial_leaves);
    if (!std.meta.eql(initial_root.bytes, input.expected_initial_rw_root)) return error.UntrustedV5WriterInitialRoot;

    var writers: [4]FileWriter = undefined;
    var created: usize = 0;
    errdefer for (writers[0..created], filenames[0..created]) |*writer, name| {
        writer.file.close();
        dir.deleteFile(name) catch {};
    };
    for (&writers, filenames) |*writer, name| {
        writer.* = .{ .file = try dir.createFile(name, .{ .exclusive = true, .read = true }) };
        created += 1;
    }
    var file_bytes: u64 = 0;
    image = Image.init(input, provisional);
    while (try image.next()) |leaf| {
        const address = leaf.index * 4;
        const is_input = input.layout.isInputAddr(address);
        try writers[if (is_input) @as(usize, 0) else 1].append(&wordRecord(address, leaf.value), &file_bytes, input.caps.max_file_bytes, if (is_input) initial.MAX_INPUT_WORDS else initial.MAX_RW_WORDS);
    }
    var reg = registers.Pins{ .first_touch_mask = 0, .initial_registers = input.initial_registers, .final_registers = if (input.register_custody_mode == 1) input.initial_registers else input.expected_final_registers, .final_clocks = @splat(0) };
    var reader = try sorted.open(sorted.context);
    defer reader.deinit();
    var previous: ?transition.Transition = null;
    var event_count: u64 = 0;
    while (try reader.next()) |current| {
        if (input.register_custody_mode == 1 and current.space != 1) return error.MixedV5RegisterCustody;
        if (event_count >= input.expected_total_events or event_count >= input.caps.max_events) return error.InvalidV5WriterEventCensus;
        if (current.clock == 0) return error.InvalidV5WriterTransition;
        const same = if (previous) |prior| sameKey(prior, current) else false;
        if (previous) |prior| {
            if (current.space < prior.space or (current.space == prior.space and (current.address < prior.address or (current.address == prior.address and current.clock <= prior.clock)))) return error.InvalidV5WriterTransition;
            if (same) {
                if (current.before != prior.after) return error.InvalidV5WriterTransition;
            } else try finishKey(prior, &reg, &writers[3], &file_bytes, input.caps);
        }
        if (!same) {
            const expected = try initialValue(input, provisional, current.space, current.address);
            if (current.before != expected) return error.InvalidV5WriterFirstTouch;
            var touch: [9]u8 = undefined;
            touch[0] = current.space;
            std.mem.writeInt(u32, touch[1..5], current.address, .little);
            std.mem.writeInt(u32, touch[5..9], current.before, .little);
            try writers[2].append(&touch, &file_bytes, input.caps.max_file_bytes, input.caps.max_first_touches);
        }
        if (current.space == 0 and current.address == 0 and current.after != 0) return error.InvalidV5WriterTransition;
        previous = current;
        event_count += 1;
    }
    if (event_count != input.expected_total_events) return error.InvalidV5WriterEventCensus;
    if (previous) |last| try finishKey(last, &reg, &writers[3], &file_bytes, input.caps);
    _ = try reg.digest();
    for (&writers) |*writer| {
        try writer.flush();
        try writer.file.sync();
    }

    var merged = try FinalImage.init(Image.init(input, provisional), writers[3].file, writers[3].records);
    const final_root = try sparse.root(&merged, try std.math.add(u64, max_initial_leaves, input.caps.max_first_touches));
    if (!std.meta.eql(final_root.bytes, input.expected_final_rw_root)) return error.UntrustedV5WriterFinalRoot;
    provisional.input_words = writers[0].pin();
    provisional.rw_words = writers[1].pin();
    provisional.first_touches = writers[2].pin();
    _ = try provisional.digest();
    return .{ .initial_pins = provisional, .endpoint_file_pin = writers[3].pin(), .register_pins = reg, .final_rw_root = final_root.bytes, .event_count = event_count, .file_bytes = file_bytes, .opened = .{ writers[0].file, writers[1].file, writers[2].file, writers[3].file }, .register_custody_mode = input.register_custody_mode, .register_window_plan_digest = input.register_window_plan_digest };
}

fn validateImage(input: Input, pins: initial.Pins) !void {
    var previous: ?u32 = null;
    for (input.initial_words) |word| {
        _ = try tree.memoryIndex(word.address);
        if (previous != null and word.address <= previous.?) return error.InvalidV5WriterInitialImage;
        previous = word.address;
        const wanted: replay.InitialSource = if (input.layout.isProgramAddr(word.address)) .program_root else if (input.layout.isInputAddr(word.address)) .public_input else if (input.layout.isRwAddr(word.address)) .rw_root else return error.InvalidV5WriterInitialImage;
        if (word.source != wanted) return error.InvalidV5WriterInitialImage;
        if (wanted == .public_input and word.value != try initial.inputWord(pins, input.public_input, word.address)) return error.InvalidV5WriterInitialImage;
    }
}
fn initialValue(input: Input, pins: initial.Pins, space: u1, address: u32) !u32 {
    if (space == 0) {
        if (address >= 32) return error.InvalidV5WriterFirstTouch;
        return input.initial_registers[address];
    }
    _ = try tree.memoryIndex(address);
    if (input.layout.isProgramAddr(address)) return error.ProgramTouchRequiresVerifiedRomReceipt;
    if (input.layout.isInputAddr(address)) return initial.inputWord(pins, input.public_input, address);
    if (!input.layout.isRwAddr(address)) return error.UnclassifiedV5FirstTouch;
    var low: usize = 0;
    var high = input.initial_words.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (input.initial_words[mid].address < address) low = mid + 1 else high = mid;
    }
    return if (low < input.initial_words.len and input.initial_words[low].address == address) input.initial_words[low].value else 0;
}
fn finishKey(last: transition.Transition, reg: *registers.Pins, writer: *FileWriter, file_bytes: *u64, caps: Caps) !void {
    if (last.space == 0) {
        if (last.address >= 32 or last.after != reg.final_registers[last.address]) return error.InvalidV5WriterRegisterEndpoint;
        reg.first_touch_mask |= @as(u32, 1) << @intCast(last.address);
        reg.final_clocks[last.address] = last.clock;
    } else {
        var row: [16]u8 = undefined;
        std.mem.writeInt(u32, row[0..4], last.address, .little);
        std.mem.writeInt(u64, row[4..12], last.clock, .little);
        std.mem.writeInt(u32, row[12..16], last.after, .little);
        try writer.append(&row, file_bytes, caps.max_file_bytes, caps.max_first_touches);
    }
}
fn sameKey(left: transition.Transition, right: transition.Transition) bool {
    return left.space == right.space and left.address == right.address;
}
fn wordRecord(address: u32, value: u32) [8]u8 {
    var row: [8]u8 = undefined;
    std.mem.writeInt(u32, row[0..4], address, .little);
    std.mem.writeInt(u32, row[4..8], value, .little);
    return row;
}

const Image = struct {
    input: Input,
    pins: initial.Pins,
    word_at: usize = 0,
    input_at: u64 = 0,
    rw: ?tree.Leaf = null,
    public: ?tree.Leaf = null,
    initialized: bool = false,
    fn init(input: Input, pins: initial.Pins) Image {
        return .{ .input = input, .pins = pins };
    }
    fn nextRw(self: *Image) ?tree.Leaf {
        while (self.word_at < self.input.initial_words.len) {
            const word = self.input.initial_words[self.word_at];
            self.word_at += 1;
            if (word.source == .rw_root and word.value != 0) return .{ .index = word.address / 4, .value = word.value };
        }
        return null;
    }
    fn nextInput(self: *Image) !?tree.Leaf {
        while (self.input_at < self.input.public_input.len) {
            const address: u32 = @intCast(@as(u64, self.input.layout.input_base) + self.input_at);
            self.input_at += 4;
            const value = try initial.inputWord(self.pins, self.input.public_input, address);
            if (value != 0) return .{ .index = address / 4, .value = value };
        }
        return null;
    }
    pub fn next(self: *Image) !?tree.Leaf {
        if (!self.initialized) {
            self.rw = self.nextRw();
            self.public = try self.nextInput();
            self.initialized = true;
        }
        if (self.rw == null and self.public == null) return null;
        if (self.public == null or (self.rw != null and self.rw.?.index < self.public.?.index)) {
            const leaf = self.rw;
            self.rw = self.nextRw();
            return leaf;
        }
        const leaf = self.public;
        self.public = try self.nextInput();
        return leaf;
    }
};
const FinalImage = struct {
    image: Image,
    file: std.fs.File,
    remaining: u64,
    offset: u64 = 0,
    buffer: [8192]u8 = undefined,
    buffered: usize = 0,
    cursor: usize = 0,
    initial_leaf: ?tree.Leaf = null,
    endpoint_leaf: ?tree.Leaf = null,
    fn init(image: Image, file: std.fs.File, records: u64) !FinalImage {
        var self = FinalImage{ .image = image, .file = file, .remaining = records };
        self.initial_leaf = try self.image.next();
        self.endpoint_leaf = try self.readEndpoint();
        return self;
    }
    fn readEndpoint(self: *FinalImage) !?tree.Leaf {
        if (self.remaining == 0) return null;
        if (self.cursor == self.buffered) {
            const records: usize = @intCast(@min(self.remaining, @as(u64, self.buffer.len / 16)));
            const bytes = records * 16;
            if (try self.file.preadAll(self.buffer[0..bytes], self.offset) != bytes) return error.TruncatedV5WriterEndpoint;
            self.offset += bytes;
            self.buffered = bytes;
            self.cursor = 0;
        }
        const row = self.buffer[self.cursor..][0..16];
        self.cursor += 16;
        self.remaining -= 1;
        return .{ .index = (try tree.memoryIndex(initial.readWord(row[0..4]))), .value = initial.readWord(row[12..16]) };
    }
    pub fn next(self: *FinalImage) !?tree.Leaf {
        while (self.initial_leaf != null or self.endpoint_leaf != null) {
            if (self.endpoint_leaf == null or (self.initial_leaf != null and self.initial_leaf.?.index < self.endpoint_leaf.?.index)) {
                const leaf = self.initial_leaf;
                self.initial_leaf = try self.image.next();
                return leaf;
            }
            const leaf = self.endpoint_leaf.?;
            if (self.initial_leaf != null and self.initial_leaf.?.index == leaf.index) self.initial_leaf = try self.image.next();
            self.endpoint_leaf = try self.readEndpoint();
            if (leaf.value != 0) return leaf;
        }
        return null;
    }
};
