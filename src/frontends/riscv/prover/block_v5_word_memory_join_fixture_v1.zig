//! Small rooted memory capture for the genuine fresh native/packed join gate.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const helper = @import("tests/block_v5_initial_source_test.zig");
const initial = @import("block_v5_initial_sources_v1.zig");
const endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
const registers = @import("block_v5_register_endpoints_v1.zig");
const memory = @import("../air/block/memory_component.zig");
const trace = @import("../air/block/word_memory_trace_v5.zig");
const artifact = @import("block_v5_word_memory_artifact_v1.zig");
const request = @import("block_v5_word_memory_proof_v1.zig");
const table = @import("block_v5_range16_proof_v1.zig");
const receiver = @import("block_v5_word_memory_receiver_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
const Artifact = artifact.ForBackend(Cpu);
pub const Capture = struct {
    sorted: ?request.Proof = null,
    range: ?table.Proof = null,
    fn memorySink(ctx: *anyopaque, index: u32, proof: *request.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0 or self.sorted != null) return error.InvalidJoinMemoryCapture;
        self.sorted = proof.*;
        proof.* = undefined;
    }
    fn rangeSink(ctx: *anyopaque, index: u32, proof: *table.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0 or self.range != null) return error.InvalidJoinMemoryCapture;
        self.range = proof.*;
        proof.* = undefined;
    }
    fn takeMemory(ctx: *anyopaque, index: u32) anyerror!request.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0) return error.InvalidJoinMemoryCapture;
        const result = self.sorted orelse return error.InvalidJoinMemoryCapture;
        self.sorted = null;
        return result;
    }
    fn takeRange(ctx: *anyopaque, index: u32) anyerror!table.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0 or self.sorted != null) return error.InvalidJoinMemoryCapture;
        const result = self.range orelse return error.InvalidJoinMemoryCapture;
        self.range = null;
        return result;
    }
    pub fn sink(self: *Capture) artifact.Sink {
        return .{ .context = self, .memory = memorySink, .range = rangeSink };
    }
    pub fn loader(self: *Capture) receiver.Loader {
        return .{ .context = self, .take_memory = takeMemory, .take_range = takeRange };
    }
    pub fn deinit(self: *Capture, a: std.mem.Allocator) void {
        if (self.sorted) |*owned| owned.deinit(a);
        if (self.range) |*owned| owned.deinit(a);
        self.* = .{};
    }
};
const Source = struct {
    a: std.mem.Allocator,
    events: [2]Transition,
    claim: memory.Claim,
    fn load(ctx: *anyopaque, index: u32) anyerror!trace.Trace {
        const self: *Source = @ptrCast(@alignCast(ctx));
        if (index != 0) return error.InvalidJoinSource;
        var result = try trace.Trace.init(self.a, self.claim);
        errdefer result.deinit();
        for (self.events) |event| try result.append(event);
        try result.seal();
        return result;
    }
    fn interface(self: *Source) artifact.Source {
        return .{ .context = self, .load = load };
    }
};
pub const Fixture = struct {
    a: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    opened: helper.OpenFiles,
    endpoint_file: std.fs.File,
    source: Source,
    first: Artifact,
    endpoint_pins: endpoints.Pins,
    register_pins: registers.Pins,
    pub fn init(a: std.mem.Allocator, events: [2]Transition, first_regs: [32]u32, final_regs: [32]u32, config: core.pcs.PcsConfig) !Fixture {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const touches = [_][9]u8{ helper.recordTouch(0, events[0].address, events[0].before), helper.recordTouch(0, events[1].address, events[1].before) };
        if (events[0].space != 0 or events[1].space != 0 or events[0].address != 0 or events[1].address != 1) return error.UnexpectedJoinFixtureAccesses;
        try helper.writeFile(tmp.dir, "input.bin", &.{});
        try helper.writeFile(tmp.dir, "rw.bin", &.{});
        try helper.writeFile(tmp.dir, "touches.bin", std.mem.sliceAsBytes(&touches));
        try helper.writeFile(tmp.dir, "endpoints.bin", &.{});
        var opened = try helper.OpenFiles.open(tmp.dir);
        errdefer opened.deinit();
        const endpoint_file = try tmp.dir.openFile("endpoints.bin", .{});
        errdefer endpoint_file.close();
        const root = (try @import("../air/memory_commitment/blake3_state_tree.zig").TreeHasher.init(.memory).root(&.{})).bytes;
        const source_pins = initial.Pins{ .layout = helper.layout, .initial_rw_root = root, .initial_registers = first_regs, .public_input_sha256 = initial.sha256(&.{}), .public_input_len = 0, .input_words = .{ .sha256 = initial.sha256(&.{}), .records = 0 }, .rw_words = .{ .sha256 = initial.sha256(&.{}), .records = 0 }, .first_touches = .{ .sha256 = initial.sha256(std.mem.sliceAsBytes(&touches)), .records = 2 } };
        const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = events[0], .last = events[1] }, 2, 8, null);
        var source = Source{ .a = a, .events = events, .claim = claim };
        var first = try Artifact.collect(a, source.interface(), &.{claim}, 2, config);
        errdefer first.deinit(a);
        var register_pins = registers.Pins{ .first_touch_mask = 3, .initial_registers = first_regs, .final_registers = final_regs, .final_clocks = @splat(0) };
        for (events) |event| register_pins.final_clocks[event.address] = event.clock;
        return .{ .a = a, .tmp = tmp, .opened = opened, .endpoint_file = endpoint_file, .source = source, .first = first, .endpoint_pins = .{ .initial = source_pins, .memory_plan_digest = first.plan_digest, .expected_final_rw_root = root, .endpoints = .{ .sha256 = initial.sha256(&.{}), .records = 0 } }, .register_pins = register_pins };
    }
    pub fn deinit(self: *Fixture) void {
        self.first.deinit(self.a);
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
        return .{ .seal = v5_pins, .expected_seal_digest = sealed.digest, .first_round = entries, .claims = self.first.claims, .request_counts = self.first.counts, .memory_roots = self.first.memory_roots, .range_roots = self.first.range_roots, .expected_total_events = 2, .source = self.endpoint_pins, .register_endpoints = self.register_pins };
    }
};
