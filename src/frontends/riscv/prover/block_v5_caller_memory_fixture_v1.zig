//! Rooted, sorted caller-memory fixture; no program or block authority.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const helper = @import("block_v5_initial_source_test.zig");
const capture_mod = @import("block_v5_word_memory_join_fixture_v1.zig");
const initial = @import("block_v5_initial_sources_v1.zig");
const endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
const registers = @import("block_v5_register_endpoints_v1.zig");
const memory = @import("../air/block/memory_component.zig");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const trace = @import("../air/block/word_memory_trace_v5.zig");
const artifact = @import("block_v5_word_memory_artifact_v1.zig");
const receiver = @import("block_v5_word_memory_receiver_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
const Artifact = artifact.ForBackend(Cpu);
pub const Capture = capture_mod.Capture;
const Source = struct {
    a: std.mem.Allocator,
    events: []Transition,
    claim: memory.Claim,
    fn load(ctx: *anyopaque, index: u32) anyerror!trace.Trace {
        const self: *Source = @ptrCast(@alignCast(ctx));
        if (index != 0) return error.InvalidCallerMemoryFixture;
        var result = try trace.Trace.init(self.a, self.claim);
        errdefer result.deinit();
        for (self.events) |event| try result.append(event);
        try result.seal();
        const direct = @import("../air/block/word_memory_v5.zig");
        for (0..result.domainSize()) |logical| {
            const previous = (logical + result.domainSize() - 1) % result.domainSize();
            const checks = direct.constraints(result.claim, result.fixedAt(logical), result.rowAt(logical), result.rowAt(previous));
            for (checks, 0..) |value, index_| if (!value.isZero()) {
                std.debug.print("CALLER_MEMORY_DIRECT row={d} constraint={d}\n", .{ logical, index_ });
                return error.InvalidCallerMemoryDirectConstraint;
            };
        }
        return result;
    }
    fn interface(self: *Source) artifact.Source {
        return .{ .context = self, .load = load };
    }
};
fn less(_: void, left: Transition, right: Transition) bool {
    if (left.space != right.space) return left.space < right.space;
    if (left.address != right.address) return left.address < right.address;
    return left.clock < right.clock;
}
fn sameKey(left: Transition, right: Transition) bool {
    return left.space == right.space and left.address == right.address;
}
pub const Fixture = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    opened: helper.OpenFiles,
    endpoint_file: std.fs.File,
    source: Source,
    first: Artifact,
    endpoint_pins: endpoints.Pins,
    register_pins: registers.Pins,
    pub fn init(a: std.mem.Allocator, unsorted: []const Transition, first_regs: [32]u32, final_regs: [32]u32, layout: @import("../runner/memory_state.zig").MemoryLayout, config: core.pcs.PcsConfig) !Fixture {
        if (unsorted.len == 0 or unsorted.len > 256) return error.InvalidCallerMemoryFixture;
        const events = try a.dupe(Transition, unsorted);
        errdefer a.free(events);
        std.mem.sort(Transition, events, {}, less);
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var touches: std.ArrayList([9]u8) = .empty;
        defer touches.deinit(a);
        var rw: std.ArrayList([8]u8) = .empty;
        defer rw.deinit(a);
        var final_records: std.ArrayList([16]u8) = .empty;
        defer final_records.deinit(a);
        var initial_leaves: std.ArrayList(tree.Leaf) = .empty;
        defer initial_leaves.deinit(a);
        var final_leaves: std.ArrayList(tree.Leaf) = .empty;
        defer final_leaves.deinit(a);
        var register_pins = registers.Pins{ .first_touch_mask = 0, .initial_registers = first_regs, .final_registers = final_regs, .final_clocks = @splat(0) };
        for (events, 0..) |event, index| {
            if (index == 0 or !sameKey(events[index - 1], event)) {
                try touches.append(a, helper.recordTouch(event.space, event.address, event.before));
                if (event.space == 1 and event.before != 0) {
                    if (layout.isInputAddr(event.address)) return error.NonemptyCallerFixtureInput;
                    try rw.append(a, helper.recordWord(event.address, event.before));
                    try initial_leaves.append(a, .{ .index = try tree.memoryIndex(event.address), .value = event.before });
                }
            }
            if (index + 1 == events.len or !sameKey(events[index + 1], event)) {
                if (event.space == 0) {
                    if (event.address >= 32) return error.InvalidCallerMemoryFixture;
                    register_pins.first_touch_mask |= @as(u32, 1) << @intCast(event.address);
                    register_pins.final_clocks[event.address] = event.clock;
                } else {
                    var record: [16]u8 = undefined;
                    std.mem.writeInt(u32, record[0..4], event.address, .little);
                    std.mem.writeInt(u64, record[4..12], event.clock, .little);
                    std.mem.writeInt(u32, record[12..16], event.after, .little);
                    try final_records.append(a, record);
                    if (event.after != 0) try final_leaves.append(a, .{ .index = try tree.memoryIndex(event.address), .value = event.after });
                }
            }
        }
        try helper.writeFile(tmp.dir, "input.bin", &.{});
        try helper.writeFile(tmp.dir, "rw.bin", std.mem.sliceAsBytes(rw.items));
        try helper.writeFile(tmp.dir, "touches.bin", std.mem.sliceAsBytes(touches.items));
        try helper.writeFile(tmp.dir, "endpoints.bin", std.mem.sliceAsBytes(final_records.items));
        var opened = try helper.OpenFiles.open(tmp.dir);
        errdefer opened.deinit();
        const endpoint_file = try tmp.dir.openFile("endpoints.bin", .{});
        errdefer endpoint_file.close();
        const hasher = tree.TreeHasher.init(.memory);
        const root = (try hasher.root(initial_leaves.items)).bytes;
        const final_root = (try hasher.root(final_leaves.items)).bytes;
        const source_pins = initial.Pins{ .layout = layout, .initial_rw_root = root, .initial_registers = first_regs, .public_input_sha256 = initial.sha256(&.{}), .public_input_len = 0, .input_words = .{ .sha256 = initial.sha256(&.{}), .records = 0 }, .rw_words = .{ .sha256 = initial.sha256(std.mem.sliceAsBytes(rw.items)), .records = rw.items.len }, .first_touches = .{ .sha256 = initial.sha256(std.mem.sliceAsBytes(touches.items)), .records = touches.items.len } };
        const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = @intCast(events.len), .first = events[0], .last = events[events.len - 1] }, events.len, 8, null);
        var source = Source{ .a = a, .events = events, .claim = claim };
        var first = try Artifact.collect(a, source.interface(), &.{claim}, events.len, config);
        errdefer first.deinit(a);
        return .{ .a = a, .tmp = tmp, .opened = opened, .endpoint_file = endpoint_file, .source = source, .first = first, .endpoint_pins = .{ .initial = source_pins, .memory_plan_digest = first.plan_digest, .expected_final_rw_root = final_root, .endpoints = .{ .sha256 = initial.sha256(std.mem.sliceAsBytes(final_records.items)), .records = final_records.items.len } }, .register_pins = register_pins };
    }
    pub fn deinit(self: *Fixture) void {
        self.first.deinit(self.a);
        self.a.free(self.source.events);
        self.opened.deinit();
        self.endpoint_file.close();
        self.tmp.cleanup();
        self.* = undefined;
    }
    pub fn files(self: *Fixture) endpoints.Sources {
        return .{ .initial = self.opened.files, .endpoints = self.endpoint_file };
    }
    pub fn prove(self: *Fixture, capture: *Capture, v5_pins: seal.Pins, entries: []const seal.Entry, sealed: seal.Sealed) !void {
        try self.first.prove(self.a, self.source.interface(), capture.sink(), v5_pins, entries, sealed.digest, sealed);
    }
    pub fn pins(self: *Fixture, v5_pins: seal.Pins, entries: []const seal.Entry, sealed: seal.Sealed) receiver.Pins {
        return .{ .seal = v5_pins, .expected_seal_digest = sealed.digest, .first_round = entries, .claims = self.first.claims, .request_counts = self.first.counts, .memory_roots = self.first.memory_roots, .range_roots = self.first.range_roots, .expected_total_events = self.source.events.len, .source = self.endpoint_pins, .register_endpoints = self.register_pins };
    }
};
