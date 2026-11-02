const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const R = frontend.rv64_air.memory;
const proof = @import("../rv64_ram_private.zig");

test "private RAM transition STARK: roots private cells policy and hash graph verify with explicit open CPU debt" {
    const a = std.testing.allocator;
    var cache = try R.values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var mappings = try R.policy.Policy.init(a, &.{ .{ .first = 0x1000, .last = 0x11ff, .flags = 3 }, .{ .first = 0x2000, .last = 0x2007, .flags = 1 }, .{ .first = 0x20f8, .last = 0x20ff, .flags = 3 } });
    defer mappings.deinit();
    const before: [2][64]u64 = @splat(@splat(0));
    var after = before;
    after[0][0] = 17;
    after[1][31] = 29;
    var clocks: [2][64]u32 = @splat(@splat(0));
    clocks[0][0] = 4;
    clocks[1][0] = 8;
    clocks[1][31] = 12;
    var rights: [2][64]u2 = .{ @splat(3), @splat(0) };
    rights[1][0] = 1;
    rights[1][31] = 3;
    var openings: [2]R.batch.Opening = undefined;
    for (&openings, 0..) |*opening, i| opening.* = .{ .index = if (i == 0) 8 else 16, .before = &before[i], .after = &after[i], .terminal_clocks = &clocks[i], .rights = &rights[i] };
    var trace = try R.private_trace.Trace.init(a, &cache, &mappings, &openings);
    defer trace.deinit();
    const public = proof.Statement{ .geometry = .chunk512, .before = trace.witness.before, .after = trace.witness.after, .policy = &mappings };
    var reference = try R.private_trace.Trace.init(a, &cache, &mappings, &openings);
    defer reference.deinit();
    var borrowed_source = proof.Source.fromTrace(&reference);
    borrowed_source.metadata = null;
    const reference_proof = try proof.proveSourceOpenState(a, public, borrowed_source);
    defer a.free(reference_proof);
    const bytes = try proof.proveOpenState(a, public, &trace);
    defer a.free(bytes);
    // The owned source is adopted/mutated before interactions. Narrow metadata
    // produces EXACTLY the original physical rows/claims and final proof bytes.
    try std.testing.expectEqualSlices(u8, reference_proof, bytes);
    try std.testing.expectEqual(@as(usize, 0), trace.main_backing.len);
    try std.testing.expectEqual(@as(usize, 0), trace.provider.len);
    try std.testing.expect(trace.captured == null);
    try std.testing.expectEqual(R.private_trace.Phase.retired, trace.phase);
    const open = try proof.verifyOpenState(a, public, bytes);
    try std.testing.expect(!proof.OpenState.cpu_closed);
    var expected = @import("stwo_core").fields.qm31.QM31.zero();
    for (openings) |opening| for (opening.before, opening.after, opening.terminal_clocks, opening.rights, 0..) |initial, final, clock, flags, i| if (clock != 0) {
        const address = (opening.index << 9) + i * 8;
        expected = expected.sub(try open.challenge.denominator(frontend.rv64_air.relations.boundaryTuple(1, address, 0, initial, flags & 1 != 0, flags & 2 != 0)).inv()).add(try open.challenge.denominator(frontend.rv64_air.relations.boundaryTuple(1, address, clock, final, flags & 1 != 0, flags & 2 != 0)).inv());
    };
    try std.testing.expectEqualDeep(expected, open.claim);
    var false_public = public;
    false_public.after[8] ^= 1;
    try std.testing.expectError(error.UnbalancedPrivateRamGraph, proof.verifyOpenState(a, false_public, bytes));
    try std.testing.expectError(error.InvalidPrivateRamProofShape, proof.verifyReceiptOpenState(a, public, bytes));
}

test "private RAM fresh transcript: unused BEFORE side cannot launder an unopened digest into the AFTER root" {
    const a = std.testing.allocator;
    const M = @import("stwo_core").fields.m31.M31;
    const physical = frontend.rv64_air.witness.physical;
    const universal = frontend.testing.component_proof.universal_air;
    var cache = try R.values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var mappings = try R.policy.Policy.init(a, &.{.{ .first = 0x1000, .last = 0x11ff, .flags = 3 }});
    defer mappings.deinit();
    const before: [64]u64 = @splat(0);
    var changed = before;
    changed[0] = 17;
    var clocks: [64]u32 = @splat(0);
    clocks[0] = 4;
    const rights: [64]u2 = @splat(3);
    const read_opening = [_]R.batch.Opening{.{ .index = 8, .before = &before, .after = &before, .terminal_clocks = &clocks, .rights = &rights }};
    const write_opening = [_]R.batch.Opening{.{ .index = 8, .before = &before, .after = &changed, .terminal_clocks = &clocks, .rights = &rights }};
    var read = try R.private_trace.Trace.init(a, &cache, &mappings, &read_opening);
    defer read.deinit();
    var write = try R.private_trace.Trace.init(a, &cache, &mappings, &write_opening);
    defer write.deinit();
    const counts = proof.Counts{ .hashes = 1, .common_chunks = 1, .edge_chunks = 0, .nodes = write.shapes.node.nodes, .sides = write.shapes.side.sides + 1, .edge_permits = 0 };
    const shapes = try counts.shapes(.chunk512);
    var source = proof.Source.fromTrace(&read);
    source.metadata = null; // Exercise arbitrary committed rows, not native-builder metadata.
    source.rows.shapes = shapes;
    // BEFORE/AFTER internal nodes are genuine hashes of the two different roots.
    source.rows.mains[@intFromEnum(R.private_trace.Table.node)] = write.node;
    // The value-changing leaf hash/cells are deliberately absent: the CPU debt
    // is read-only. An orphan BEFORE side tries to supply that digest to AFTER.
    const side = try a.dupe(M, write.side);
    defer a.free(side);
    const forged = try R.side_air.fill(.chunk512, 0, 8, write.witness.leaves[0].graph.after, true);
    const side_size = @as(usize, 1) << @intCast(shapes.side.log_size);
    for (forged, 0..) |value, col| side[col * side_size + physical(write.shapes.side.sides, shapes.side.log_size)] = value;
    source.rows.mains[@intFromEnum(R.private_trace.Table.side)] = side;
    // Keep only the read-only leaf calls and the genuine write-tree node calls.
    const records = try a.alloc(R.values.PermutationIO, 38 + write.recorder.calls.items.len - 76);
    defer a.free(records);
    @memcpy(records[0..38], read.recorder.calls.items[0..38]);
    @memcpy(records[38..], write.recorder.calls.items[76..]);
    source.rows.records = records;
    const size = @as(usize, 1) << @intCast(shapes.provider_log);
    const provider_main = try a.alloc(M, universal.N_MAIN_COLUMNS * size);
    defer a.free(provider_main);
    const padding = universal.paddingRow();
    for (padding, 0..) |value, col| @memset(provider_main[col * size ..][0..size], value);
    for (0..records.len) |i| {
        const from_read = i < 38;
        const src = if (from_read) read.provider else write.provider;
        const src_log = if (from_read) read.shapes.provider_log else write.shapes.provider_log;
        const src_size = @as(usize, 1) << @intCast(src_log);
        const src_row = physical(if (from_read) i else i - 38 + 76, src_log);
        const dst = physical(i, shapes.provider_log);
        for (0..universal.N_MAIN_COLUMNS) |col| provider_main[col * size + dst] = src[col * src_size + src_row];
    }
    source.provider_main = provider_main;
    source.byte_counts = write.byte_counts;
    source.policy_counts = write.policy_counts;
    // Match the ACTUAL committed rows, not a host assertion about the attack.
    const cell_size = @as(usize, 1) << @intCast(read.shapes.common_cells.log_size);
    for (0..64) |i| for (0..19) |col| {
        const at = physical(i, read.shapes.common_cells.log_size);
        source.byte_counts[write.common_cells[col * cell_size + at].toU32()] -= 1;
        source.byte_counts[read.common_cells[col * cell_size + at].toU32()] += 1;
    };
    for (forged[R.side_air.INDEX_BYTES..][0..7]) |value| source.byte_counts[value.toU32()] += 1;
    const public = proof.Statement{ .geometry = .chunk512, .before = read.witness.before, .after = write.witness.after, .policy = &mappings };
    // The coordinator seals this malicious MAIN/count roster, draws fresh
    // challenges, then rejects its sole remaining orphan BEFORE graph debt.
    try std.testing.expectError(error.UnbalancedPrivateRamGraph, proof.proveSourceOpenState(a, public, source));
}

test "private RAM owned source: release main before interactions failure retry guards and metadata retirement" {
    const a = std.testing.allocator;
    var cache = try R.values.Cache.empty(a, .chunk512);
    defer cache.deinit();
    var mappings = try R.policy.Policy.init(a, &.{.{ .first = 0x1000, .last = 0x11ff, .flags = 3 }});
    defer mappings.deinit();
    const before: [64]u64 = @splat(0);
    var after = before;
    after[0] = 17;
    var clocks: [64]u32 = @splat(0);
    clocks[0] = 4;
    const rights: [64]u2 = @splat(3);
    const openings = [_]R.batch.Opening{.{ .index = 8, .before = &before, .after = &after, .terminal_clocks = &clocks, .rights = &rights }};
    var captured = try R.openings.Owned.copy(a, .chunk512, &openings);
    defer captured.deinit();
    var trace = try R.private_trace.Trace.initOwned(a, &cache, &mappings, &captured);
    defer trace.deinit();
    try std.testing.expectEqual(@as(usize, 0), captured.words.len);
    var rom = try R.policy_provider.Trace.init(a, &mappings, trace.policy_counts);
    defer rom.deinit();
    var bytes = try frontend.rv64_air.range.provider.Trace.init(a, &trace.byte_counts);
    defer bytes.deinit();
    var source = proof.Source.fromTrace(&trace);
    var channel = frontend.rv64_air.protocol.Channel{};
    const challenge = try R.private_interaction.Challenges.draw(a, &channel);
    var reference = try R.private_interaction.Interaction.initRows(a, source.rows, &challenge);
    defer reference.deinit();
    var main = try source.takeMainForCommit(a, &rom);
    // Simulate complete PCS adoption/retirement: EVERY wide main/provider
    // source byte disappears before interaction generation begins.
    main.deinit(a);
    try std.testing.expectEqual(R.private_trace.Phase.main_detached, trace.phase);
    var zero = challenge;
    zero.bytes = @import("stwo_core").fields.qm31.QM31.zero();
    try std.testing.expectError(error.DivisionByZero, source.generateInteractions(a, &zero));
    try std.testing.expect(trace.captured != null);
    var actual = try source.generateInteractions(a, &challenge);
    defer actual.deinit();
    try std.testing.expectEqualDeep(reference.claims, actual.claims);
    for (reference.tables, actual.tables) |old, current| try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, old, current);
    try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, reference.provider.columns, actual.provider.columns);
    try std.testing.expectError(error.InvalidPrivateRamTracePhase, source.generateInteractions(a, &challenge));
    _ = try bytes.generateInteraction(challenge.bytes);
    _ = try rom.generateInteraction(.{ .policy = challenge.policy });
    _ = try R.private_interaction.close(trace.witness.before, trace.witness.after, .chunk512, &actual.claims, actual.provider.claims, bytes.claim, rom.claim, &challenge);
    try source.retireMetadata();
    try std.testing.expect(trace.captured == null);
    try std.testing.expectError(error.InvalidPrivateRamTracePhase, source.generateInteractions(a, &challenge));
    try std.testing.expectError(error.InvalidPrivateRamTracePhase, source.retireMetadata());
}

test "private RAM omitted provider claims and unused caller slots cannot carry unauthenticated physical claims" {
    const Q = @import("stwo_core").fields.qm31.QM31;
    var claims = proof.Claims{ .callers = .{}, .provider = @splat(Q.zero()), .policy = Q.zero(), .bytes = Q.zero() };
    try claims.validateWithoutByte();
    claims.bytes = Q.one();
    try std.testing.expectError(error.UnexpectedPrivateRamByteProviderClaim, claims.validateWithoutByte());
    claims.bytes = Q.zero();
    claims.callers.tables[@intFromEnum(R.private_trace.Table.side)][R.side_air.SUMS] = Q.one();
    try std.testing.expectError(error.NoncanonicalPrivateRamClaimTail, claims.validateWithoutByte());
}

fn privateContextFailure(a: std.mem.Allocator, bytes: []const u8, expected: [32]u8) !void {
    var context = try @import("../rv64_ram_private_receipt.zig").decode(a, bytes, expected);
    defer context.deinit();
}
test "private RAM public context: independent pin canonical bounds and allocation failures precede proof admission" {
    const a = std.testing.allocator;
    const codec = @import("../rv64_ram_private_receipt.zig");
    var mappings = try R.policy.Policy.init(a, &.{ .{ .first = 0x1000, .last = 0x1fff, .flags = 5 }, .{ .first = 0x2000, .last = 0x2fff, .flags = 3 } });
    defer mappings.deinit();
    const public = proof.Statement{ .geometry = .chunk512, .before = @splat(17), .after = @splat(29), .policy = &mappings };
    const bytes = try codec.encode(a, public);
    defer a.free(bytes);
    const pin = codec.hash(bytes);
    var decoded = try codec.decode(a, bytes, pin);
    defer decoded.deinit();
    try std.testing.expectEqualDeep(public.before, decoded.before);
    try std.testing.expectEqualDeep(public.after, decoded.after);
    try std.testing.expectEqualDeep(mappings.identity, decoded.policy.identity);
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var wrong_pin = pin;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.PrivateRamContextShaMismatch, codec.decode(failing.allocator(), bytes, wrong_pin));
    try std.testing.checkAllAllocationFailures(a, privateContextFailure, .{ bytes, pin });
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    changed[84 + 16] = 7;
    // Even a caller who independently pins malformed WX policy cannot bypass
    // immutable-ROM admission or force a wide allocation first.
    try std.testing.expectError(error.InvalidPrivateRamContext, codec.decode(failing.allocator(), changed, codec.hash(changed)));
    @memcpy(changed, bytes);
    @memset(changed[8..12], 255);
    try std.testing.expectError(error.NonCanonicalDigest, codec.decode(failing.allocator(), changed, codec.hash(changed)));
}

const TerminalFixture = struct {
    memory: frontend.rv64.memory.Memory,
    policy: R.policy.Policy,
    cache: R.values.Cache,
    output: [43]u8,
    fn init(a: std.mem.Allocator, geometry: R.values.Geometry, high_private: u64) !TerminalFixture {
        var memory = frontend.rv64.memory.Memory.init(a, .{});
        errdefer memory.deinit();
        try memory.map(.{ .start = 0xc00000, .size = 4096, .permissions = .{ .read = true, .write = true } });
        try memory.store(0xc00000, 8, (@as(u64, 43) << 32) | 1);
        try memory.store(0xc00030, 8, high_private & 0xffffffffff000000);
        var output: [43]u8 = undefined;
        for (&output, 0..) |*byte, i| {
            byte.* = @intCast((7 * i + 3) & 255);
            try memory.store(0xc00008 + i, 1, byte.*);
        }
        var mappings = try R.policy.Policy.fromMemory(a, &memory);
        errdefer mappings.deinit();
        const cache = try R.values.Cache.fromMemory(a, geometry, &memory);
        return .{ .memory = memory, .policy = mappings, .cache = cache, .output = output };
    }
    fn public(self: *const TerminalFixture) @import("../rv64_ram_terminal.zig").Statement {
        return .{ .geometry = self.cache.geometry, .root = self.cache.root(), .policy = &self.policy, .halt_flag = 0xc00000, .output = self.output };
    }
    fn rebuild(self: *TerminalFixture, a: std.mem.Allocator) !void {
        const replacement = try R.values.Cache.fromMemory(a, self.cache.geometry, &self.memory);
        self.cache.deinit();
        self.cache = replacement;
    }
    fn deinit(self: *TerminalFixture) void {
        self.cache.deinit();
        self.policy.deinit();
        self.memory.deinit();
    }
};
test "terminal root observation STARK: expected43 bytes halt length and private upper bytes bind without synthetic state" {
    const a = std.testing.allocator;
    const terminal = @import("../rv64_ram_terminal.zig");
    var fixture = try TerminalFixture.init(a, .chunk512, 0x9876543210000000);
    defer fixture.deinit();
    const public = fixture.public();
    const bytes = try terminal.prove(a, public, &fixture.cache, &fixture.memory);
    defer a.free(bytes);
    try terminal.verify(a, public, bytes);
    const diagnostic = try terminal.proveDiagnostic(a, public, &fixture.cache, &fixture.memory);
    defer a.free(diagnostic);
    try std.testing.expectError(error.InvalidPrivateRamProofShape, terminal.verify(a, public, diagnostic));
    var wrong_output = public;
    wrong_output.output[42] ^= 1;
    try std.testing.expectError(error.UnbalancedPrivateRamGraph, terminal.verify(a, wrong_output, bytes));
    // This is a FRESH transcript with the true committed root/words and wrong
    // public output. Only the extra terminal AIR binding is unsatisfied.
    try std.testing.expectError(error.ConstraintsNotSatisfied, terminal.proveDiagnostic(a, wrong_output, &fixture.cache, &fixture.memory));
    var other = try TerminalFixture.init(a, .chunk512, 0x1122334455000000);
    defer other.deinit();
    try std.testing.expect(!R.values.equal(public.root, other.cache.root()));
    const other_bytes = try terminal.prove(a, other.public(), &other.cache, &other.memory);
    defer a.free(other_bytes);
    try terminal.verify(a, other.public(), other_bytes);
    try std.testing.expectError(error.UnbalancedPrivateRamGraph, terminal.verify(a, other.public(), bytes));
}

test "terminal root observation fresh transcripts: wrong halt flag and output length cannot pass through genuine hashes" {
    const a = std.testing.allocator;
    const terminal = @import("../rv64_ram_terminal.zig");
    var fixture = try TerminalFixture.init(a, .chunk512, 0);
    defer fixture.deinit();
    try fixture.memory.store(0xc00000, 8, (@as(u64, 43) << 32) | 2);
    try fixture.rebuild(a);
    try std.testing.expectError(error.ConstraintsNotSatisfied, terminal.proveDiagnostic(a, fixture.public(), &fixture.cache, &fixture.memory));
    try fixture.memory.store(0xc00000, 8, (@as(u64, 44) << 32) | 1);
    try fixture.rebuild(a);
    try std.testing.expectError(error.ConstraintsNotSatisfied, terminal.proveDiagnostic(a, fixture.public(), &fixture.cache, &fixture.memory));
}

fn terminalContextFailure(a: std.mem.Allocator, bytes: []const u8, expected: [32]u8) !void {
    var context = try @import("../rv64_ram_terminal_receipt.zig").decode(a, bytes, expected);
    defer context.deinit();
}
test "terminal context: all root bytes ABI output and independent pin remain bounded before allocation" {
    const a = std.testing.allocator;
    const codec = @import("../rv64_ram_terminal_receipt.zig");
    const hash = @import("../rv64_ram_private_receipt.zig").hash;
    var fixture = try TerminalFixture.init(a, .chunk512, 0x9876543210000000);
    defer fixture.deinit();
    const public = fixture.public();
    const bytes = try codec.encode(a, public);
    defer a.free(bytes);
    const pin = hash(bytes);
    var context = try codec.decode(a, bytes, pin);
    defer context.deinit();
    try std.testing.expectEqualDeep(public.root, context.statement().root);
    try std.testing.expectEqualDeep(public.output, context.output);
    try std.testing.checkAllAllocationFailures(a, terminalContextFailure, .{ bytes, pin });
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var wrong_pin = pin;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.TerminalContextShaMismatch, codec.decode(failing.allocator(), bytes, wrong_pin));
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    changed[8 + 44] ^= 1;
    try std.testing.expectError(error.InvalidTerminalRootObservation, codec.decode(failing.allocator(), changed, hash(changed)));
    @memcpy(changed, bytes);
    const inner_len = std.mem.readInt(u32, changed[4..8], .little);
    changed[8 + inner_len] |= 1;
    try std.testing.expectError(error.InvalidRv64TerminalLayout, codec.decode(failing.allocator(), changed, hash(changed)));
}
