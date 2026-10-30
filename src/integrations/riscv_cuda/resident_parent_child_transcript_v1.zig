//! Original native-child transcript grammar, with raw packet routes and complete
//! bounded draw traces. No CPU channel execution or child capture is used.
const std = @import("std");
const core = @import("stwo_core");
const Packet = @import("resident_parent_child_packet_v1.zig");
const Profile = @import("../../frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
const Statement = @import("../../frontends/riscv/recursion/air/block_v7_native_statement_v1.zig");
const Cold = @import("../../frontends/riscv/recursion/air/blake3_fixed_operation_recorder_v1.zig");
const T = @import("../../frontends/riscv/recursion/air/blake3_transcript_witness.zig");
const Schema = @import("../../frontends/riscv/recursion/air/blake3_pcs_operation_schema_v1.zig");
const Plan = @import("../../frontends/riscv/recursion/air/blake3_transcript_plan.zig");
pub const Ref = extern struct { kind: u32, index: u32 };
pub const Port = struct { circuit: u32, wire: u32, value: Ref }; //0 literal,1 raw packet
pub const Task = extern struct { kind: u32, first: u32 = 0, count: u32 = 0, output: u32 = 0, aux: u32 = 0, trace_first: u32 = 0, attempt_first: u32 = 0, attempt_count: u32 = 0 };
// kinds:0 init,1 words,2 felts,3 integer,4 root,5 secure,6 pow check,7 queries.
// Every task has20 state words (before/after digest8+counter2). Every attempt
// has32 words: raw8,reduced8,pending,status,counter_before2,counter_after2,
// digest_before8,pending_after,consumed_attempts. Dummy attempts after selection are retained.
pub const Limits = struct { max_operations: usize = 1 << 16, max_words: usize = 1 << 24, max_attempts: u32 = 8 };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    tasks: []const Task,
    refs: []const Ref,
    ports: []const Port,
    output_words: u32,
    trace_words: u32,
    query_first: u32,
    composition_first: u32,
    oods_first: u32,
    deep_first: u32,
    fri_first: u32,
    plan_id: [32]u8,
    profile_id: [32]u8,
    pub fn initNative(a: std.mem.Allocator, profile: *const Profile.Owned, packet: *const Packet.Owned, capacity: u32, limits: Limits) !Owned {
        if (capacity == 0 or capacity > limits.max_attempts or !std.meta.eql(packet.profile_id, profile.seal)) return error.InvalidResidentChildTranscript;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        const Fused = @import("../../frontends/riscv/prover/block_v5_native_projection_fused_proof_v2.zig");
        const Memory = @import("../../frontends/riscv/prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
        const claims = try temp.alloc(Fused.Claim, profile.projections.len);
        for (claims, profile.projections) |*c, s| c.* = .{ .sum = core.fields.qm31.QM31.zero(), .row_count = s.n_rows };
        const memory = try temp.alloc(Memory.Claim, profile.slots.len);
        for (memory) |*m| m.* = .{ .transition_sum = core.fields.qm31.QM31.zero(), .universal_sum = core.fields.qm31.QM31.zero(), .range_claims = @splat(core.fields.qm31.QM31.zero()), .active_count = 0 };
        var statement = try Statement.init(temp, profile, claims, memory);
        defer statement.deinit();
        const words = try temp.alloc(Ref, statement.words.len);
        for (words, statement.words) |*r, w| r.* = .{ .kind = 0, .index = w };
        const fields = try temp.alloc(Ref, statement.felts.len * 4);
        var f: usize = 0;
        for (packet.projection_sums) |s| {
            for (0..4) |j| {
                fields[f] = .{ .kind = 1, .index = s.first + @as(u32, @intCast(j)) };
                f += 1;
            }
        }
        for (packet.memory) |m| {
            for ([_]Packet.Span{ m.transition, m.universal } ++ m.ranges) |s| {
                for (0..4) |j| {
                    if (f >= fields.len) return error.InvalidResidentChildTranscript;
                    fields[f] = .{ .kind = 1, .index = s.first + @as(u32, @intCast(j)) };
                    f += 1;
                }
            }
        }
        if (f != fields.len) return error.InvalidResidentChildTranscript;
        // Each physical projection count or access census is immediately followed
        // by that claim's first felt. Other u64 words are fixed frame/roster data.
        var mapped: usize = 0;
        for (statement.claims, 0..) |step, i| if (step == .integer and i + 1 < statement.claims.len and statement.claims[i + 1] == .felts) {
            const field = statement.claims[i + 1].felts.first;
            const span = if (field < packet.projection_counts.len) packet.projection_counts[field] else blk: {
                const m = (field - packet.projection_counts.len) / 9;
                if (m >= packet.memory.len or (field - packet.projection_counts.len) % 9 != 0) return error.InvalidResidentChildTranscript;
                break :blk packet.memory[m].count;
            };
            const at = step.integer;
            if (at + 2 > words.len) return error.InvalidResidentChildTranscript;
            words[at] = .{ .kind = 1, .index = span.first };
            words[at + 1] = .{ .kind = 1, .index = span.first + 1 };
            mapped += 1;
        };
        if (mapped != packet.projection_counts.len + packet.memory.len) return error.InvalidResidentChildTranscript;
        var recorder = Cold.Recorder{ .a = temp, .limits = .{ .max_operations = limits.max_operations, .max_routed_words = limits.max_words } };
        try @import("../../frontends/riscv/recursion/air/block_v7_native_transcript_v1.zig").prefixFixed(temp, &recorder, profile, &statement);
        try recorder.suffix(.{ .commitment = .{ .slot = profile.trace_count - 1, .source = try @import("../../frontends/riscv/recursion/air/blake3_root_sources.zig").caller(profile.trace_count - 1) } });
        var suffix: std.ArrayList(Schema.Operation) = .empty;
        try Schema.appendPcsSuffix(temp, &suffix, profile.epoch.config, profile.shape.deepProfile(), profile.shape.friProfile(), profile.trace_count + 1);
        for (suffix.items) |op| try recorder.suffix(op);
        try recorder.check();
        var fixed = try Plan.Plan.initCompact(temp, .{ .namespace = 1_000_000, .attempt_capacity = capacity }, recorder.operations.items);
        defer fixed.deinit();
        var b = Builder{ .a = temp, .packet = packet, .words = words, .fields = fields, .capacity = capacity, .limit = limits.max_words };
        const composition: u32 = 106 * 4;
        const oods = composition + 4;
        const deep = oods + 4;
        const fri = deep + 4;
        b.next_output = fri + @as(u32, @intCast(profile.shape.widths.len)) * 4;
        b.query_first = b.next_output;
        b.next_output += packet.query_count;
        try b.append(.{ .kind = 0 });
        for (recorder.operations.items) |op| try b.operation(op, composition, oods, deep, fri);
        return .{ .arena = arena, .tasks = try b.tasks.toOwnedSlice(temp), .refs = try b.refs.toOwnedSlice(temp), .ports = try b.ports.toOwnedSlice(temp), .output_words = b.next_output, .trace_words = b.next_trace, .query_first = b.query_first, .composition_first = composition, .oods_first = oods, .deep_first = deep, .fri_first = fri, .plan_id = fixed.id, .profile_id = profile.seal };
    }
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    packet: *const Packet.Owned,
    words: []const Ref,
    fields: []const Ref,
    capacity: u32,
    limit: usize,
    tasks: std.ArrayList(Task) = .empty,
    refs: std.ArrayList(Ref) = .empty,
    ports: std.ArrayList(Port) = .empty,
    next_output: u32 = 0,
    next_trace: u32 = 0,
    query_first: u32 = 0,
    fn append(self: *Builder, value: Task) !void {
        var t = value;
        t.trace_first = self.next_trace;
        self.next_trace = try std.math.add(u32, self.next_trace, 20);
        if (t.attempt_count > 0) {
            t.attempt_first = self.next_trace;
            self.next_trace = try std.math.add(u32, self.next_trace, try std.math.mul(u32, t.attempt_count, 32));
        }
        if (self.next_trace > self.limit) return error.ResidentChildTranscriptLimit;
        try self.tasks.append(self.a, t);
    }
    fn payload(self: *Builder, kind: u32, values: []const Ref, aux: u32) !void {
        if (self.refs.items.len + values.len > self.limit) return error.ResidentChildTranscriptLimit;
        const first = self.refs.items.len;
        try self.refs.appendSlice(self.a, values);
        try self.append(.{ .kind = kind, .first = @intCast(first), .count = @intCast(values.len), .aux = aux });
    }
    fn raw(self: *Builder, kind: u32, s: Packet.Span, aux: u32) !void {
        const refs = try self.a.alloc(Ref, s.count);
        for (refs, 0..) |*r, i| r.* = .{ .kind = 1, .index = s.first + @as(u32, @intCast(i)) };
        try self.payload(kind, refs, aux);
    }
    fn constants(self: *Builder, kind: u32, values: []const u32) !void {
        const refs = try self.a.alloc(Ref, values.len);
        for (refs, values) |*r, v| r.* = .{ .kind = 0, .index = v };
        try self.payload(kind, refs, 0);
    }
    fn route(self: *Builder, kind: u32, source: T.Caller, n: usize) !void {
        const first = self.refs.items.len;
        try self.routeInner(kind, source, n);
        if (self.refs.items.len - first != n) return error.InvalidResidentChildTranscript;
        for (self.refs.items[first..], 0..) |value, i| try self.ports.append(self.a, .{ .circuit = source.circuit, .wire = try std.math.add(u32, source.first_wire, @intCast(i)), .value = value });
    }
    fn routeInner(self: *Builder, kind: u32, source: T.Caller, n: usize) !void {
        if (source.circuit == Statement.PUBLIC_CIRCUIT) {
            const at = source.first_wire;
            if (at < self.words.len) {
                if (n > self.words.len - at) return error.InvalidResidentChildTranscript;
                return self.payload(kind, self.words[at..][0..n], 0);
            }
            const first = at - self.words.len;
            if (first > self.fields.len or n > self.fields.len - first) return error.InvalidResidentChildTranscript;
            return self.payload(kind, self.fields[first..][0..n], 0);
        }
        const shared = @import("../../frontends/riscv/recursion/air/blake3_native_transcript.zig");
        if (source.circuit == shared.SAMPLE_SOURCE.circuit and source.first_wire == shared.SAMPLE_SOURCE.first_wire) {
            if (n != self.packet.samples.count) return error.InvalidResidentChildTranscript;
            return self.raw(kind, self.packet.samples, 0);
        }
        if (source.circuit == shared.TERMINAL_SOURCE.circuit and source.first_wire == shared.TERMINAL_SOURCE.first_wire) {
            if (n != self.packet.terminal.count) return error.InvalidResidentChildTranscript;
            return self.raw(kind, self.packet.terminal, 0);
        }
        if (source.circuit == 4_100_001 and source.first_wire == 2 and n == 2) return self.raw(kind, self.packet.nonce, 0);
        if (source.circuit == @import("../../frontends/riscv/recursion/air/blake3_root_sources.zig").CIRCUIT and n == 8 and source.first_wire % 8 == 0) {
            const index = source.first_wire / 8;
            if (index < self.packet.roots.len) return self.raw(kind, self.packet.roots[index], 0);
            const layer = index - self.packet.roots.len;
            if (layer >= self.packet.layers.len) return error.InvalidResidentChildTranscript;
            return self.raw(kind, self.packet.layers[layer].root, 0);
        }
        return error.InvalidResidentChildTranscript;
    }
    fn operation(self: *Builder, op: T.Operation, composition: u32, oods: u32, deep: u32, fri: u32) !void {
        switch (op) {
            .restart => try self.append(.{ .kind = 0 }),
            .integer => |v| try self.constants(3, &.{ @truncate(v), @truncate(v >> 32) }),
            .words => |v| try self.constants(1, v),
            .root => |v| {
                var words: [8]u32 = undefined;
                for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, v[i * 4 ..][0..4], .little);
                try self.constants(4, &words);
            },
            .felts => |values| {
                const words = try self.a.alloc(u32, values.len * 4);
                for (values, 0..) |v, i| for (v.toM31Array(), 0..) |f, j| {
                    words[4 * i + j] = f.v;
                };
                try self.constants(2, words);
            },
            .routed_integer => |v| try self.route(3, v.source, 2),
            .routed_root => |v| try self.route(4, v.source, 8),
            .routed_words => |v| try self.route(1, v.source, v.values.len),
            .routed_felts => |v| try self.route(2, v.source, v.values.len * 4),
            .secure => |v| {
                const role = v.output orelse return error.InvalidResidentChildTranscript;
                const at: u32 = switch (role) {
                    .universal => |i| @intCast(i * 8),
                    .universal_half => |h| @intCast(h.relation * 8 + 4 * @as(usize, h.half)),
                    .composition => composition,
                    .oods => oods,
                    .deep => deep,
                    .fri => |i| fri + @as(u32, @intCast(4 * i)),
                    else => return error.InvalidResidentChildTranscript,
                };
                const n: u32 = @intCast(v.consumption.words());
                if (@as(u64, at) + n > self.next_output) return error.InvalidResidentChildTranscript;
                try self.append(.{ .kind = 5, .count = n, .output = at, .attempt_count = self.capacity });
            },
            .pow => |v| try self.raw(6, self.packet.nonce, v.bits),
            .queries => |v| {
                if (v.values.len != self.packet.query_count or v.log_domain_size != self.packet.domain_log) return error.InvalidResidentChildTranscript;
                try self.append(.{ .kind = 7, .count = self.packet.query_count, .output = self.query_first, .aux = v.log_domain_size, .attempt_count = @intCast((v.values.len + 7) / 8) });
            },
        }
    }
};
