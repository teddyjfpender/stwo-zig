//! Independently selected complete endpoint states for nonterminal v7 execution.
//! No replay result, old Merkle proof or mutable receipt supplies authority.
const std = @import("std");
const core = @import("stwo_core");
const C = @import("block_v7_real_window_capture_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v7_program_image_v1.zig");
const Memory = @import("../runner/memory.zig").Memory;
const Cpu = @import("../runner/cpu.zig").Cpu;
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Sparse = @import("block_v7_window_sparse_initial_v1.zig");
pub const VERSION: u32 = 2;
pub const Trusted = struct { elf_sha256: C.Digest, incoming_sha256: C.Digest, outgoing_sha256: C.Digest, window: C.Window };
pub const Change = struct { address: u32, before: u32, after: u32 };
/// New, explicitly separated B8 global-span policy. CPU clocks are bounded
/// inside each local original; global RAM uses coarse cohort ordinals. A large
/// total span must not be interpreted as one oversized native trace.
pub const CohortPolicy = struct {
    cohort_count: u32,
    max_cohort_cycles: u32,
    pub fn validate(self: CohortPolicy, cycles: u32) !void {
        if (self.cohort_count == 0 or self.cohort_count > 4096 or self.max_cohort_cycles == 0 or self.max_cohort_cycles > 1 << 24 or
            cycles < self.cohort_count or cycles >= core.fields.m31.Modulus or
            @as(u64, cycles) > @as(u64, self.cohort_count) * self.max_cohort_cycles or
            @as(u64, cycles) + self.cohort_count >= core.fields.m31.Modulus)
            return error.InvalidB8GlobalCohortSpan;
    }
};
pub const SpanMode = union(enum) { native_window, endpoint_cohorts: CohortPolicy };
fn validateSpan(mode: SpanMode, cycles: u32) !void {
    switch (mode) {
        .native_window => if (cycles == 0 or cycles >= 1 << 26) return error.UntrustedV7WindowState,
        .endpoint_cohorts => |policy| try policy.validate(cycles),
    }
}
pub const Boundary = struct {
    initial_cpu: Cpu,
    final_cpu: Cpu,
    skip_cycles: u64,
    cycles: u32,
    incoming_sha256: C.Digest,
    outgoing_sha256: C.Digest,
};
pub const Owned = struct {
    a: std.mem.Allocator,
    initial: Initial.Owned,
    program_root: [32]u8,
    boundary: Boundary,
    changes: []Change,
    span_mode: SpanMode = .native_window,
    boundary_options: @import("block_v8_execution_boundary_ports_v1.zig").Options = .{},
    /// Complete admitted initialization authority remains distinct from the
    /// selected prover table. It is cloned from pinned endpoint derivation,
    /// never decoded from an untrusted proof's interval cells.
    selection: ?struct { source: Initial.Owned, addresses: []u32 } = null,
    pub fn deriveForAddresses(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, addresses: []const u32, limits: Initial.Limits) !Owned {
        var result = try derive(a, elf, incoming, outgoing, trusted, limits);
        errdefer result.deinit();
        try result.selectAddresses(addresses, limits);
        return result;
    }
    /// Selection is fixed before provider commitments and epoch challenges.
    /// All changed cells and the halt word remain covered independently of the
    /// producer's requested first-touch list. An omitted actual access is then
    /// forbidden by the same first-touch AIR, not silently initialized to zero.
    pub fn selectAddresses(self: *Owned, requested: []const u32, limits: Initial.Limits) !void {
        try self.validate();
        if (self.selection != null) return error.AlreadySelectedV7WindowInitialization;
        const count = try std.math.add(usize, requested.len, try std.math.add(usize, self.changes.len, if (self.boundary_options.terminal != null) @as(usize, 14) else 1));
        if (count > limits.max_initialized_words) return error.V7InitializationResourceLimit;
        const addresses = try self.a.alloc(u32, count);
        defer self.a.free(addresses);
        @memcpy(addresses[0..requested.len], requested);
        for (self.changes, addresses[requested.len..][0..self.changes.len]) |change, *address| address.* = change.address;
        addresses[requested.len + self.changes.len] = self.initial.info.halt_flag;
        if (self.boundary_options.terminal) |terminal| {
            const base = requested.len + self.changes.len + 1;
            addresses[base] = terminal.policy.halt_address;
            addresses[base + 1] = terminal.policy.length_address;
            for (0..11) |i| addresses[base + 2 + i] = terminal.policy.data_address + @as(u32, @intCast(i)) * 4;
        }
        var sparse = try Sparse.derive(self.a, &self.initial, addresses, limits);
        errdefer sparse.deinit();
        var selected = self.*;
        selected.selection = .{ .source = self.initial, .addresses = sparse.addresses };
        selected.initial.intervals = sparse.intervals;
        try selected.validate();
        self.* = selected;
    }
    pub fn derive(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, limits: Initial.Limits) !Owned {
        return deriveSpan(a, elf, incoming, outgoing, trusted, .native_window, limits);
    }
    /// Complete global snapshots are admitted ONCE for a declared multi-cohort
    /// window. This is not terminal-block admission and proves no prefix.
    pub fn deriveCohorts(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, cohort_policy: CohortPolicy, limits: Initial.Limits) !Owned {
        return deriveSpan(a, elf, incoming, outgoing, trusted, .{ .endpoint_cohorts = cohort_policy }, limits);
    }
    pub fn deriveCohortsForAddresses(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, cohort_policy: CohortPolicy, addresses: []const u32, limits: Initial.Limits) !Owned {
        var result = try deriveCohorts(a, elf, incoming, outgoing, trusted, cohort_policy, limits);
        errdefer result.deinit();
        try result.selectAddresses(addresses, limits);
        return result;
    }
    pub fn deriveCohortsWithBoundary(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, cohort_policy: CohortPolicy, options: @import("block_v8_execution_boundary_ports_v1.zig").Options, limits: Initial.Limits) !Owned {
        return deriveSpanBoundary(a, elf, incoming, outgoing, trusted, .{ .endpoint_cohorts = cohort_policy }, options, limits);
    }
    pub fn deriveCohortsForAddressesWithBoundary(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, cohort_policy: CohortPolicy, addresses: []const u32, options: @import("block_v8_execution_boundary_ports_v1.zig").Options, limits: Initial.Limits) !Owned {
        var result = try deriveSpanBoundary(a, elf, incoming, outgoing, trusted, .{ .endpoint_cohorts = cohort_policy }, options, limits);
        errdefer result.deinit();
        try result.selectAddresses(addresses, limits);
        return result;
    }
    fn deriveSpan(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, span_mode: SpanMode, limits: Initial.Limits) !Owned {
        return deriveSpanBoundary(a, elf, incoming, outgoing, trusted, span_mode, .{}, limits);
    }
    fn deriveSpanBoundary(a: std.mem.Allocator, elf: []const u8, incoming: C.Snapshot, outgoing: C.Snapshot, trusted: Trusted, span_mode: SpanMode, options: @import("block_v8_execution_boundary_ports_v1.zig").Options, limits: Initial.Limits) !Owned {
        try options.validate();
        if (options.initial) |first| if (trusted.window.skip_cycles != 0 or !std.meta.eql(incoming.identity(), first.snapshot_id) or !std.meta.eql(incoming.cpu, first.cpu)) return error.UntrustedFullInitialBoundary;
        if (options.terminal) |last| if (try std.math.add(u64, trusted.window.skip_cycles, trusted.window.cycles) != last.policy.final_cycle) return error.UntrustedFullTerminalCoverage;

        try validateSpan(span_mode, trusted.window.cycles);
        if (!std.meta.eql(incoming.identity(), trusted.incoming_sha256) or !std.meta.eql(outgoing.identity(), trusted.outgoing_sha256)) return error.UntrustedV7WindowState;
        _ = try std.math.add(u64, trusted.window.skip_cycles, trusted.window.cycles);
        var initial = try Initial.Owned.derive(a, elf, trusted.elf_sha256, .rv32im_zkvm_ethereum_sha_v1, limits);
        errdefer initial.deinit();
        const loaded = try Initial.loadAddresses(a, elf, limits);
        defer a.free(loaded);
        var memory = try Memory.initFallible(a);
        defer memory.deinit();
        try memory.prepareAlignedWordWrites(loaded);
        _ = try @import("../runner/elf_loader.zig").loadElfForProfile(elf, &memory, .rv32im_zkvm_ethereum_sha_v1);
        try validateSnapshot(incoming, &memory, loaded, initial.info.memory_layout, limits);
        try validateSnapshot(outgoing, &memory, loaded, initial.info.memory_layout, limits);
        if (valueAt(incoming.words, initial.info.halt_flag) != 0) return error.NonterminalWindowHalted;
        if (options.terminal) |last| {
            const t = last.policy;
            if (t.halt_address != initial.info.halt_flag or t.length_address != initial.info.output_len or t.data_address != initial.info.output_data or t.output_end != initial.info.output_end) return error.UntrustedFullTerminalAbi;
            try requireTerminalWords(outgoing.words, t);
        } else if (valueAt(outgoing.words, initial.info.halt_flag) != 0) return error.NonterminalWindowHalted;
        var image = try Image.Owned.init(a, elf, &initial, limits);
        defer image.deinit();
        const intervals = try snapshotIntervals(a, incoming.words, initial.info.memory_layout, limits);
        a.free(initial.intervals);
        initial.intervals = intervals;
        var changes: std.ArrayList(Change) = .empty;
        errdefer changes.deinit(a);
        var left: usize = 0;
        var right: usize = 0;
        while (left < incoming.words.len or right < outgoing.words.len) {
            const address = @min(if (left < incoming.words.len) incoming.words[left].address else std.math.maxInt(u32), if (right < outgoing.words.len) outgoing.words[right].address else std.math.maxInt(u32));
            const before = if (left < incoming.words.len and incoming.words[left].address == address) incoming.words[left].value else 0;
            const after = if (right < outgoing.words.len and outgoing.words[right].address == address) outgoing.words[right].value else 0;
            if (left < incoming.words.len and incoming.words[left].address == address) left += 1;
            if (right < outgoing.words.len and outgoing.words[right].address == address) right += 1;
            if (before != after) try changes.append(a, .{ .address = address, .before = before, .after = after });
        }
        var result = Owned{ .a = a, .initial = initial, .program_root = image.root.bytes, .boundary = .{ .initial_cpu = incoming.cpu, .final_cpu = outgoing.cpu, .skip_cycles = trusted.window.skip_cycles, .cycles = trusted.window.cycles, .incoming_sha256 = trusted.incoming_sha256, .outgoing_sha256 = trusted.outgoing_sha256 }, .changes = try changes.toOwnedSlice(a), .span_mode = span_mode, .boundary_options = options };
        errdefer a.free(result.changes);
        try result.validate();
        return result;
    }
    pub fn validate(self: *const Owned) !void {
        try self.boundary_options.validate();
        try Initial.validatePartition(self.initial.intervals);
        if (self.selection) |*selected| {
            if (!std.meta.eql(selected.source.elf_sha256, self.initial.elf_sha256) or !std.meta.eql(selected.source.info, self.initial.info)) return error.UntrustedV7SparseInitialization;
            for (selected.source.intervals) |row| if (row.private) return error.PrivateV7WindowInitialization;
            try Sparse.require(&selected.source, selected.addresses, self.initial.intervals);
        }
        const b = self.boundary;
        validateSpan(self.span_mode, b.cycles) catch return error.InvalidV7WindowPolicy;
        if (b.initial_cpu.regs[0] != 0 or b.final_cpu.regs[0] != 0 or
            (b.initial_cpu.pc | b.final_cpu.pc) & 3 != 0 or !self.initial.info.memory_layout.isProgramAddr(b.initial_cpu.pc) or
            !self.initial.info.memory_layout.isProgramAddr(b.final_cpu.pc) or std.mem.allEqual(u8, &self.program_root, 0) or
            std.mem.allEqual(u8, &b.incoming_sha256, 0) or std.mem.allEqual(u8, &b.outgoing_sha256, 0)) return error.InvalidV7WindowPolicy;
        const end_cycle = try std.math.add(u64, b.skip_cycles, b.cycles);
        if (self.boundary_options.initial) |first| if (b.skip_cycles != 0 or !std.meta.eql(first.snapshot_id, b.incoming_sha256) or !std.meta.eql(first.cpu, b.initial_cpu)) return error.UntrustedFullInitialBoundary;
        if (self.boundary_options.terminal) |last| if (last.policy.final_cycle != end_cycle or last.policy.halt_address != self.initial.info.halt_flag or last.policy.length_address != self.initial.info.output_len or last.policy.data_address != self.initial.info.output_data or last.policy.output_end != self.initial.info.output_end) return error.UntrustedFullTerminalAbi;
        for (self.initial.intervals) |row| if (row.private) return error.PrivateV7WindowInitialization;
        const halt = try self.initial.find(self.initial.info.halt_flag);
        if (!halt.allowed or halt.private or halt.value != 0) return error.NonterminalWindowHalted;
        for (self.changes, 0..) |change, i| {
            if (change.address & 3 != 0 or change.before == change.after or (i != 0 and self.changes[i - 1].address >= change.address) or
                (change.address == self.initial.info.halt_flag and self.boundary_options.terminal == null)) return error.InvalidV7WindowDelta;
            const original = try self.initial.find(change.address);
            if (!original.allowed or original.private or original.value != change.before) return error.UntrustedV7WindowDelta;
        }
        if (self.boundary_options.terminal) |last| {
            for (0..13) |i| {
                const address = if (i == 0) last.policy.halt_address else if (i == 1) last.policy.length_address else last.policy.data_address + @as(u32, @intCast(i - 2)) * 4;
                const initial_row = try self.initial.find(address);
                var after = initial_row.value;
                for (self.changes) |change| {
                    if (change.address == address) {
                        after = change.after;
                        break;
                    }
                    if (change.address > address) break;
                }
                try requireTerminalWord(last.policy, i, after);
                if (self.selection) |selected| if (std.sort.binarySearch(u32, selected.addresses, address, struct {
                    fn order(key: u32, item: u32) std.math.Order {
                        return std.math.order(key, item);
                    }
                }.order) == null) return error.MissingTerminalBoundaryWord;
            }
        }
    }
    pub fn mix(self: *const Owned, ch: anytype) void {
        self.boundary_options.mix(ch);
        if (self.span_mode == .endpoint_cohorts) {
            const policy = self.span_mode.endpoint_cohorts;
            ch.mixU32s(&.{ 0x42384757, 1, policy.cohort_count, policy.max_cohort_cycles });
        }
        if (self.selection) |selected| {
            ch.mixU32s(&.{ 0x42375349, Sparse.VERSION });
            ch.mixU64(selected.addresses.len);
            ch.mixU32s(selected.addresses);
        }
        ch.mixU32s(&.{ 0x42375753, VERSION, self.boundary.cycles, self.boundary.initial_cpu.pc, self.boundary.final_cpu.pc });
        ch.mixU64(self.boundary.skip_cycles);
        ch.mixU32s(&self.boundary.initial_cpu.regs);
        ch.mixU32s(&self.boundary.final_cpu.regs);
        ch.mixRoot(self.boundary.incoming_sha256);
        ch.mixRoot(self.boundary.outgoing_sha256);
        ch.mixRoot(self.initial.elf_sha256);
        ch.mixRoot(self.program_root);
        ch.mixU64(self.changes.len);
        for (self.changes) |change| ch.mixU32s(&.{ change.address, change.before, change.after });
    }
    /// Public state-delta identity, evaluated only after the policy and all
    /// source roots are fixed. First-touch incoming authority is indispensable.
    pub fn delta(self: *const Owned, relation: @FieldType(Word.Challenges, "initial")) !Q {
        try self.validate();
        var result = Q.zero();
        for (self.changes) |change| {
            result = result.add(try relation.combineBase(valueTuple(change.address, change.after)).inv());
            result = result.sub(try relation.combineBase(valueTuple(change.address, change.before)).inv());
        }
        return result;
    }
    /// All real native/caller source clocks are positive. Clock zero is an
    /// explicit impossible permission for a nonzero halt word, not a fake end.
    pub fn nonhaltConstants(self: *const Owned) !@import("block_v7_halt_algebra_v1.zig").Constants(Q) {
        try self.validate();
        const address = self.initial.info.halt_flag;
        return .{ .address = .{ Q.fromBase(M.fromCanonical(address & 65535)), Q.fromBase(M.fromCanonical(address >> 16)) }, .clocks = @splat(@splat(Q.zero())) };
    }
    pub fn cloneAlloc(self: *const Owned, a: std.mem.Allocator) !*Owned {
        try self.validate();
        const out = try a.create(Owned);
        errdefer a.destroy(out);
        const intervals = try a.dupe(Initial.Interval, self.initial.intervals);
        errdefer a.free(intervals);
        const changes = try a.dupe(Change, self.changes);
        errdefer a.free(changes);
        var selection: @FieldType(Owned, "selection") = null;
        if (self.selection) |selected| {
            const addresses = try a.dupe(u32, selected.addresses);
            errdefer a.free(addresses);
            const source_rows = try a.dupe(Initial.Interval, selected.source.intervals);
            var source = selected.source;
            source.a = a;
            source.intervals = source_rows;
            selection = .{ .source = source, .addresses = addresses };
        }
        out.* = self.*;
        out.a = a;
        out.initial.a = a;
        out.initial.intervals = intervals;
        out.changes = changes;
        out.selection = selection;
        return out;
    }
    pub fn cloneInitial(self: *const Owned, a: std.mem.Allocator) !Initial.Owned {
        try self.validate();
        return .{ .a = a, .elf_sha256 = self.initial.elf_sha256, .info = self.initial.info, .intervals = try a.dupe(Initial.Interval, self.initial.intervals) };
    }
    pub fn deinit(self: *Owned) void {
        if (self.selection) |*selected| {
            selected.source.deinit();
            self.a.free(selected.addresses);
        }
        self.initial.deinit();
        self.a.free(self.changes);
        self.* = undefined;
    }
};
pub fn valueTuple(address: u32, value: u32) [5]M {
    return .{ M.one(), M.fromCanonical(address & 65535), M.fromCanonical(address >> 16), M.fromCanonical(value & 65535), M.fromCanonical(value >> 16) };
}
pub fn valueAt(words: []const C.Word, address: u32) u32 {
    var lo: usize = 0;
    var hi = words.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (words[mid].address < address) lo = mid + 1 else hi = mid;
    }
    return if (lo < words.len and words[lo].address == address) words[lo].value else 0;
}
pub fn validateSnapshot(snapshot: C.Snapshot, elf: *const Memory, loaded: []const u32, layout: @import("../runner/memory_state.zig").MemoryLayout, limits: Initial.Limits) !void {
    if (snapshot.words.len > limits.max_initialized_words or snapshot.cpu.regs[0] != 0) return error.InvalidV7WindowSnapshot;
    for (snapshot.words, 0..) |word, i| {
        if (word.address & 3 != 0 or (i != 0 and snapshot.words[i - 1].address >= word.address)) return error.InvalidV7WindowSnapshot;
        if (layout.isRwAddr(word.address) and !layout.isProgramAddr(word.address)) continue;
        var lo: usize = 0;
        var hi = loaded.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (loaded[mid] < word.address) lo = mid + 1 else hi = mid;
        }
        if (lo == loaded.len or loaded[lo] != word.address) return error.UntrustedV7WindowReadonly;
        if (elf.readU32(word.address) != word.value) return error.UntrustedV7WindowReadonly;
    }
    // A missing nonzero readonly word is also a changed machine value.
    for (loaded) |address| if (!layout.isRwAddr(address) or layout.isProgramAddr(address)) {
        if (valueAt(snapshot.words, address) != elf.readU32(address)) return error.UntrustedV7WindowReadonly;
    };
}
fn snapshotIntervals(a: std.mem.Allocator, words: []const C.Word, layout: @import("../runner/memory_state.zig").MemoryLayout, limits: Initial.Limits) ![]Initial.Interval {
    var edges: std.ArrayList(u32) = .empty;
    defer edges.deinit(a);
    try edges.appendSlice(a, &.{ 0, Initial.WORD_LIMIT });
    inline for (.{ "program_base", "program_end", "data_base", "data_end", "stack_bottom", "stack_top", "io_base", "io_end", "input_base", "input_end" }) |name|
        try edges.append(a, @intCast((@as(u64, @field(layout, name)) + 3) / 4));
    for (words) |word| {
        if (word.value == 0 or !layout.isRwAddr(word.address) or layout.isProgramAddr(word.address)) continue;
        if (edges.items.len + 2 > limits.max_intervals) return error.V7InitializationResourceLimit;
        try edges.appendSlice(a, &.{ word.address / 4, word.address / 4 + 1 });
    }
    std.mem.sort(u32, edges.items, {}, std.sort.asc(u32));
    var rows: std.ArrayList(Initial.Interval) = .empty;
    errdefer rows.deinit(a);
    var lower: u32 = 0;
    for (edges.items) |upper| {
        if (upper == lower) continue;
        const address = lower * 4;
        const allowed = layout.isRwAddr(address) and !layout.isProgramAddr(address);
        const value = if (allowed) valueAt(words, address) else 0;
        if (rows.items.len != 0) {
            const previous = &rows.items[rows.items.len - 1];
            if (previous.allowed == allowed and previous.value == value) {
                previous.upper = upper;
                lower = upper;
                continue;
            }
        }
        try rows.append(a, .{ .lower = lower, .upper = upper, .allowed = allowed, .private = false, .value = value });
        lower = upper;
    }
    try Initial.validatePartition(rows.items);
    return rows.toOwnedSlice(a);
}

fn requireTerminalWords(words: []const C.Word, policy: @import("block_v7_terminal_protocol_v1.zig").Policy) !void {
    for (0..13) |i| {
        const address = if (i == 0) policy.halt_address else if (i == 1) policy.length_address else policy.data_address + @as(u32, @intCast(i - 2)) * 4;
        try requireTerminalWord(policy, i, valueAt(words, address));
    }
}
fn requireTerminalWord(policy: @import("block_v7_terminal_protocol_v1.zig").Policy, index: usize, actual: u32) !void {
    if (index < 2) {
        if (actual != (if (index == 0) @as(u32, 1) else @as(u32, 43))) return error.UntrustedFullTerminalOutput;
        return;
    }
    const offset = (index - 2) * 4;
    for (0..@min(@as(usize, 4), 43 - offset)) |byte| if (@as(u8, @truncate(actual >> @as(u5, @intCast(8 * byte)))) != policy.output[offset + byte]) return error.UntrustedFullTerminalOutput;
}
