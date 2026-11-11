//! Exact, bounded retirement-PC observation for Ethereum autoresearch.
//!
//! This diagnostic executes a segment-zero prefix of an already sealed V3
//! journal.  It publishes the complete PC histogram and every adjacency edge
//! between observed core rows.  Profile-extension retirements are deliberately
//! absent from the observer stream and the output says so explicitly.  The
//! result is execution evidence only: it neither proves nor verifies anything.

const std = @import("std");
const journal_support = @import("observation_journal");
const JournalAuthority = journal_support.JournalAuthority;
const readPathAlloc = journal_support.readPathAlloc;
const digest = journal_support.digest;
const frontend = @import("stwo_riscv_frontend");

const runner = frontend.runner;
const TraceRow = runner.trace.TraceRow;
const Family = frontend.witness_layout.Family;

const schema = "stwo.riscv.retirement-pc-hotspot-observation.v1";
const status = "captured-diagnostic-only";
const profile_name = "rv32im-zkvm-ethereum-v1";
const clock_frame = "leaf_local";
const transition_scope =
    "within-segment-adjacent-observed-core-rows-external-retirements-omitted";
const maximum_input_bytes: usize = 64 << 20;
const maximum_elf_bytes: usize = 64 << 20;
const maximum_journal_bytes: usize = 64 << 20;
const Options = @import("options.zig").Options;

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    const options = try Options.parse(arguments);

    const elf = try readPathAlloc(allocator, options.elf, maximum_elf_bytes);
    defer allocator.free(elf);
    const input = try readPathAlloc(allocator, options.input, maximum_input_bytes);
    defer allocator.free(input);
    const journal = try readPathAlloc(
        allocator,
        options.execution_journal,
        maximum_journal_bytes,
    );
    defer allocator.free(journal);

    const elf_sha256 = digest(elf);
    const input_sha256 = digest(input);
    const source_sha256 = digest(journal);
    var expected = try JournalAuthority.parse(
        allocator,
        journal,
        elf_sha256,
        input_sha256,
        options.segment_count,
    );
    defer expected.deinit(allocator);

    var capture = Capture.init(allocator);
    defer capture.deinit();
    var session = try runner.EthereumExecutionSession.init(allocator, elf, .{
        .input = input,
        .stop_on_halt_flag = true,
        .strict_completion = true,
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
        .retirement_observer = capture.observer(),
    });
    defer session.deinit();

    var continuation: ?runner.result_mod.ContinuationToken = null;
    for (expected.segments, 0..) |wanted, index| {
        var segment = if (index == 0)
            try session.startSegment(expected.segment_step_budget)
        else
            try session.resumeSegment(
                continuation orelse return error.MissingContinuation,
                expected.segment_step_budget,
            );
        defer segment.deinit();
        if (segment.base.segment_index != wanted.segment_index or
            segment.base.global_first_cycle != wanted.global_first_cycle or
            segment.base.cycle_count != wanted.cycle_count or
            segment.base.execution_trace.rows.items.len != wanted.core_trace_rows)
        {
            return error.JournalExecutionMismatch;
        }
        if (capture.current_segment_rows != wanted.core_trace_rows)
            return error.ObserverExecutionMismatch;
        continuation = segment.base.continuation;
        if (index + 1 < expected.segments.len and continuation == null)
            return error.ExecutionCompletedBeforeSample;
    }

    try capture.validate(expected.retired_instructions, expected.segments.len);
    const encoded = try encodeObservation(
        allocator,
        &capture,
        expected,
        elf_sha256,
        input_sha256,
        source_sha256,
    );
    defer allocator.free(encoded);
    try std.fs.File.stdout().writeAll(encoded);
}

const PcValue = struct {
    family: Family,
    count: u64,
};

const Capture = struct {
    allocator: std.mem.Allocator,
    pc: std.AutoHashMap(u32, PcValue),
    edges: std.AutoHashMap(u64, u64),
    current_segment_rows: usize = 0,
    completed_segment_rows: u64 = 0,
    previous_pc: ?u32 = null,
    segment_count: u32 = 0,

    fn init(allocator: std.mem.Allocator) Capture {
        return .{
            .allocator = allocator,
            .pc = std.AutoHashMap(u32, PcValue).init(allocator),
            .edges = std.AutoHashMap(u64, u64).init(allocator),
        };
    }

    fn deinit(self: *Capture) void {
        self.pc.deinit();
        self.edges.deinit();
        self.* = undefined;
    }

    fn observer(self: *Capture) runner.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = beginSegmentOpaque,
            .core_row_fn = observeRowOpaque,
        };
    }

    fn beginSegmentOpaque(context: *anyopaque, segment_index: u32) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (segment_index != self.segment_count)
            return error.ObserverSegmentOrderMismatch;
        self.completed_segment_rows = std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        ) catch return error.ObserverCountOverflow;
        self.current_segment_rows = 0;
        self.previous_pc = null;
        self.segment_count += 1;
    }

    fn observeRowOpaque(context: *anyopaque, row: TraceRow) !void {
        const self: *Capture = @ptrCast(@alignCast(context));
        const family = try runner.trace.proofOpcodeFamily(row.opcode);
        const pc = try self.pc.getOrPut(row.pc);
        if (!pc.found_existing) {
            pc.value_ptr.* = .{ .family = family, .count = 0 };
        } else if (pc.value_ptr.family != family) {
            return error.ProgramCounterFamilyMismatch;
        }
        pc.value_ptr.count = std.math.add(u64, pc.value_ptr.count, 1) catch
            return error.ObserverCountOverflow;
        if (self.previous_pc) |previous| {
            const key = (@as(u64, previous) << 32) | row.pc;
            const edge = try self.edges.getOrPut(key);
            if (!edge.found_existing) edge.value_ptr.* = 0;
            edge.value_ptr.* = std.math.add(u64, edge.value_ptr.*, 1) catch
                return error.ObserverCountOverflow;
        }
        self.previous_pc = row.pc;
        self.current_segment_rows = std.math.add(
            usize,
            self.current_segment_rows,
            1,
        ) catch return error.ObserverCountOverflow;
    }

    fn totalRows(self: *const Capture) !u64 {
        return std.math.add(
            u64,
            self.completed_segment_rows,
            self.current_segment_rows,
        );
    }

    fn validate(self: *const Capture, expected_rows: u64, segments: usize) !void {
        if (self.segment_count != segments or try self.totalRows() != expected_rows)
            return error.ObserverExecutionMismatch;
        var pc_total: u64 = 0;
        var pc_iterator = self.pc.iterator();
        while (pc_iterator.next()) |entry|
            pc_total = std.math.add(u64, pc_total, entry.value_ptr.count) catch
                return error.ObserverCountOverflow;
        var edge_total: u64 = 0;
        var edge_iterator = self.edges.iterator();
        while (edge_iterator.next()) |entry|
            edge_total = std.math.add(u64, edge_total, entry.value_ptr.*) catch
                return error.ObserverCountOverflow;
        if (pc_total != expected_rows or
            edge_total != expected_rows - segments)
        {
            return error.ObserverExecutionMismatch;
        }
    }
};

const PerPc = struct {
    count: u64,
    opcode_family: []const u8,
    pc: u32,
};

const BasicEdge = struct {
    count: u64,
    from_pc: u32,
    to_pc: u32,
};

const OpcodeTransition = struct {
    count: u64,
    from_family: []const u8,
    to_family: []const u8,
};

fn encodeObservation(
    allocator: std.mem.Allocator,
    capture: *const Capture,
    expected: JournalAuthority,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    source_sha256: [32]u8,
) ![]u8 {
    const pcs = try collectPcs(allocator, capture);
    defer allocator.free(pcs);
    const edges = try collectEdges(allocator, capture);
    defer allocator.free(edges);
    const transitions = try collectTransitions(allocator, pcs, edges);
    defer allocator.free(transitions);
    const elf_hex = std.fmt.bytesToHex(elf_sha256, .lower);
    const input_hex = std.fmt.bytesToHex(input_sha256, .lower);
    const source_hex = std.fmt.bytesToHex(source_sha256, .lower);
    const transition_count = expected.retired_instructions - expected.segments.len;
    const unsigned = UnsignedWire{
        .basic_edges = edges,
        .clock_frame = clock_frame,
        .distinct_basic_edge_count = edges.len,
        .distinct_pc_count = pcs.len,
        .elf_sha256 = &elf_hex,
        .execution_profile = profile_name,
        .first_global_cycle = expected.first_global_cycle,
        .first_segment_index = 0,
        .input_sha256 = &input_hex,
        .opcode_transitions = transitions,
        .per_pc = pcs,
        .production = false,
        .retired_instructions = expected.retired_instructions,
        .sampled_cycles = expected.sampled_cycles,
        .schema = schema,
        .segment_count = @intCast(expected.segments.len),
        .source_sha256 = &source_hex,
        .status = status,
        .transition_count = transition_count,
        .transition_scope = transition_scope,
    };
    const unsigned_json = try std.json.Stringify.valueAlloc(
        allocator,
        unsigned,
        .{},
    );
    defer allocator.free(unsigned_json);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(unsigned_json);
    hasher.update("\n");
    var content_digest: [32]u8 = undefined;
    hasher.final(&content_digest);
    const content_hex = std.fmt.bytesToHex(content_digest, .lower);
    const sealed = Wire{
        .basic_edges = unsigned.basic_edges,
        .clock_frame = unsigned.clock_frame,
        .content_sha256 = &content_hex,
        .distinct_basic_edge_count = unsigned.distinct_basic_edge_count,
        .distinct_pc_count = unsigned.distinct_pc_count,
        .elf_sha256 = unsigned.elf_sha256,
        .execution_profile = unsigned.execution_profile,
        .first_global_cycle = unsigned.first_global_cycle,
        .first_segment_index = unsigned.first_segment_index,
        .input_sha256 = unsigned.input_sha256,
        .opcode_transitions = unsigned.opcode_transitions,
        .per_pc = unsigned.per_pc,
        .production = unsigned.production,
        .retired_instructions = unsigned.retired_instructions,
        .sampled_cycles = unsigned.sampled_cycles,
        .schema = unsigned.schema,
        .segment_count = unsigned.segment_count,
        .source_sha256 = unsigned.source_sha256,
        .status = unsigned.status,
        .transition_count = unsigned.transition_count,
        .transition_scope = unsigned.transition_scope,
    };
    const body = try std.json.Stringify.valueAlloc(allocator, sealed, .{});
    defer allocator.free(body);
    const encoded = try allocator.alloc(u8, body.len + 1);
    @memcpy(encoded[0..body.len], body);
    encoded[body.len] = '\n';
    return encoded;
}

const UnsignedWire = struct {
    basic_edges: []const BasicEdge,
    clock_frame: []const u8,
    distinct_basic_edge_count: usize,
    distinct_pc_count: usize,
    elf_sha256: []const u8,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    opcode_transitions: []const OpcodeTransition,
    per_pc: []const PerPc,
    production: bool,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    source_sha256: []const u8,
    status: []const u8,
    transition_count: u64,
    transition_scope: []const u8,
};

const Wire = struct {
    basic_edges: []const BasicEdge,
    clock_frame: []const u8,
    content_sha256: []const u8,
    distinct_basic_edge_count: usize,
    distinct_pc_count: usize,
    elf_sha256: []const u8,
    execution_profile: []const u8,
    first_global_cycle: u64,
    first_segment_index: u32,
    input_sha256: []const u8,
    opcode_transitions: []const OpcodeTransition,
    per_pc: []const PerPc,
    production: bool,
    retired_instructions: u64,
    sampled_cycles: u64,
    schema: []const u8,
    segment_count: u32,
    source_sha256: []const u8,
    status: []const u8,
    transition_count: u64,
    transition_scope: []const u8,
};

fn collectPcs(allocator: std.mem.Allocator, capture: *const Capture) ![]PerPc {
    const result = try allocator.alloc(PerPc, capture.pc.count());
    var index: usize = 0;
    var iterator = capture.pc.iterator();
    while (iterator.next()) |entry| : (index += 1) {
        result[index] = .{
            .count = entry.value_ptr.count,
            .opcode_family = @tagName(entry.value_ptr.family),
            .pc = entry.key_ptr.*,
        };
    }
    std.mem.sort(PerPc, result, {}, lessPc);
    return result;
}

fn collectEdges(
    allocator: std.mem.Allocator,
    capture: *const Capture,
) ![]BasicEdge {
    const result = try allocator.alloc(BasicEdge, capture.edges.count());
    var index: usize = 0;
    var iterator = capture.edges.iterator();
    while (iterator.next()) |entry| : (index += 1) {
        result[index] = .{
            .count = entry.value_ptr.*,
            .from_pc = @truncate(entry.key_ptr.* >> 32),
            .to_pc = @truncate(entry.key_ptr.*),
        };
    }
    std.mem.sort(BasicEdge, result, {}, lessEdge);
    return result;
}

fn collectTransitions(
    allocator: std.mem.Allocator,
    pcs: []const PerPc,
    edges: []const BasicEdge,
) ![]OpcodeTransition {
    var families = std.AutoHashMap(u32, Family).init(allocator);
    defer families.deinit();
    for (pcs) |pc|
        try families.put(pc.pc, std.meta.stringToEnum(Family, pc.opcode_family) orelse
            return error.ObserverExecutionMismatch);
    const family_count = std.meta.fields(Family).len;
    const counts = try allocator.alloc(u64, family_count * family_count);
    defer allocator.free(counts);
    @memset(counts, 0);
    for (edges) |edge| {
        const from = families.get(edge.from_pc) orelse
            return error.ObserverExecutionMismatch;
        const to = families.get(edge.to_pc) orelse
            return error.ObserverExecutionMismatch;
        const slot = @as(usize, @intFromEnum(from)) * family_count +
            @as(usize, @intFromEnum(to));
        counts[slot] = std.math.add(u64, counts[slot], edge.count) catch
            return error.ObserverCountOverflow;
    }
    var nonzero: usize = 0;
    for (counts) |count| nonzero += @intFromBool(count != 0);
    const result = try allocator.alloc(OpcodeTransition, nonzero);
    var index: usize = 0;
    inline for (std.meta.fields(Family), 0..) |from_field, from_index| {
        inline for (std.meta.fields(Family), 0..) |to_field, to_index| {
            const count = counts[from_index * family_count + to_index];
            if (count != 0) {
                result[index] = .{
                    .count = count,
                    .from_family = from_field.name,
                    .to_family = to_field.name,
                };
                index += 1;
            }
        }
    }
    std.mem.sort(OpcodeTransition, result, {}, lessTransition);
    return result;
}

fn lessPc(_: void, left: PerPc, right: PerPc) bool {
    return left.pc < right.pc;
}

fn lessEdge(_: void, left: BasicEdge, right: BasicEdge) bool {
    return left.from_pc < right.from_pc or
        (left.from_pc == right.from_pc and left.to_pc < right.to_pc);
}

fn lessTransition(_: void, left: OpcodeTransition, right: OpcodeTransition) bool {
    const from = std.mem.order(u8, left.from_family, right.from_family);
    return from == .lt or
        (from == .eq and std.mem.order(u8, left.to_family, right.to_family) == .lt);
}
