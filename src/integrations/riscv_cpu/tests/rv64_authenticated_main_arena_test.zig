const std = @import("std");
const H = @import("../rv64_authenticated_main_arena.zig");
const Raw = @import("../rv64_main_arena.zig");
const M = @import("stwo_core").fields.m31.M31;

test "authenticated main arena rejects wide copies and malformed headers before sealing narrow multiplicities" {
    const a = std.testing.allocator;
    var layout = H.Layout{};
    for (std.enums.values(Raw.Role), 0..) |role, i| {
        layout.specs[i] = .{ .role = role, .width = 1, .log_size = 4 };
        layout.len += 1;
    }
    var owner = H.MainArena{ .arena = try Raw.Arena.init(a, layout.slice()), .layout = layout };
    defer owner.deinit();
    const core = try owner.coreBuffers();
    try std.testing.expect(core.arithmetic.division != null and core.arithmetic.multiplication != null and core.keccak != null and core.secp[0] != null and core.secp[1] != null);
    const ram = try owner.ramBuffers();
    try std.testing.expectEqual((try owner.arena.matrix(.bytes)).values.ptr, ram.byte_tail.ptr);
    try std.testing.expectEqual((try owner.arena.matrix(.ram_policy)).values.ptr, ram.policy_tail.ptr);
    try std.testing.expectEqual((try owner.arena.matrix(.cpu)).values.ptr, (try owner.cpuMain()).ptr);
    const headers = try a.alloc(H.Column, layout.len);
    defer a.free(headers);
    for (layout.slice(), headers) |spec, *header| {
        const matrix = try owner.arena.matrix(spec.role);
        @memset(matrix.values, M.fromCanonical(7));
        header.* = .{ .log_size = 4, .values = matrix.values };
    }
    var narrow: [5][16]M = @splat(@splat(M.fromCanonical(19)));
    const roles = [_]Raw.Role{ .rom, .bytes, .byte_and, .byte_shift, .ram_policy };
    for (roles, &narrow) |role, *values| headers[@intFromEnum(role)].values = values;
    const cpu = headers[0];
    headers[0].values = &narrow[0];
    try std.testing.expectError(error.AuthenticatedWideMainCopyForbidden, owner.sealFromColumns(headers));
    headers[0] = cpu;
    headers[0].log_size = 5;
    try std.testing.expectError(error.AuthenticatedMainHeaderMismatch, owner.sealFromColumns(headers));
    headers[0] = cpu;
    const rom = headers[@intFromEnum(Raw.Role.rom)];
    headers[@intFromEnum(Raw.Role.rom)].values = cpu.values;
    try std.testing.expectError(error.AliasedMainMultiplicitySource, owner.sealFromColumns(headers));
    headers[@intFromEnum(Raw.Role.rom)] = rom;
    for (roles) |role| for ((try owner.arena.matrix(role)).values) |value| try std.testing.expectEqualDeep(M.fromCanonical(7), value);
    try std.testing.expectEqual(layout.len, owner.arena.remaining);
    try owner.sealFromColumns(headers);
    try std.testing.expectError(error.InvalidMainPhase, owner.sealFromColumns(headers));
    const columns = try owner.arena.canonicalColumns(a);
    defer a.free(columns);
    for (roles) |role| try std.testing.expectEqualSlices(M, &narrow[0], columns[@intFromEnum(role)].values);
    try std.testing.expectEqualSlices(M, cpu.values, columns[0].values);
    const backing = owner.arena.raw.ptr;
    var commit = try owner.takeForCommit(a);
    defer commit.deinit(a);
    try std.testing.expectEqual(backing, commit.backing[0].ptr);
    try std.testing.expectEqual(@as(usize, 1), commit.backing.len);
}

test "authenticated RAM release precedes both failing commit descriptor allocations without moving backing or metadata" {
    const a = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(a, .{});
    const owned_allocator = failing.allocator();
    {
        const A = @import("../rv64_authenticated_execution.zig");
        const R = A.R;
        const T = A.T;
        var cache = try R.values.Cache.empty(a, .chunk512);
        defer cache.deinit();
        var policy = try R.policy.Policy.init(a, &.{.{ .first = 0x1000, .last = 0x11ff, .flags = 3 }});
        defer policy.deinit();
        const before: [64]u64 = @splat(0);
        var after = before;
        after[0] = 17;
        var clocks: [64]u32 = @splat(0);
        clocks[0] = 4;
        const rights: [64]u2 = @splat(3);
        const opening = [_]R.batch.Opening{.{ .index = 8, .before = &before, .after = &after, .terminal_clocks = &clocks, .rights = &rights }};
        var captured = try R.openings.Owned.copy(owned_allocator, .chunk512, &opening);
        defer captured.deinit();
        var preparation = try T.Preparation.init(owned_allocator, .chunk512, &policy, captured.chunks);
        defer preparation.deinit();
        var layout = H.Layout{};
        layout.specs[0] = .{ .role = .bytes, .log_size = 8, .width = 1 };
        layout.len = 1;
        const roles = [_]Raw.Role{ .ram_chunk, .ram_common_cells, .ram_edge_cells, .ram_leaf, .ram_node, .ram_side, .ram_common_permits, .ram_edge_permits };
        for (T.TABLES, roles) |table, role| {
            layout.specs[layout.len] = .{ .role = role, .log_size = T.tableLog(preparation.shapes, table), .width = T.mainWidth(table) };
            layout.len += 1;
        }
        layout.specs[layout.len] = .{ .role = .ram_poseidon, .log_size = preparation.shapes.provider_log, .width = 303 };
        layout.len += 1;
        layout.specs[layout.len] = .{ .role = .ram_policy, .log_size = 4, .width = 1 };
        layout.len += 1;
        var arena = H.MainArena{ .arena = try Raw.Arena.init(owned_allocator, layout.slice()), .layout = layout };
        defer arena.deinit();
        var trace = try T.Trace.initPreparedBorrowedOwned(owned_allocator, &cache, &preparation, &captured, try arena.ramBuffers());
        defer trace.deinit();
        var source = A.RAM.Source.fromTrace(&trace);
        var policy_trace = try R.policy_provider.Trace.init(a, &policy, source.policy_counts);
        defer policy_trace.deinit();
        var byte_trace = try A.rv.range.provider.Trace.init(a, &source.byte_counts);
        defer byte_trace.deinit();
        const ram_columns = try A.RAM.mainColumnsWithoutByte(a, source, &policy_trace);
        defer a.free(ram_columns);
        const columns = try a.alloc(H.Column, ram_columns.len + 1);
        defer a.free(columns);
        columns[0] = .{ .log_size = 8, .values = byte_trace.main };
        @memcpy(columns[1..], ram_columns);
        var channel = A.P.Channel{};
        const ch = try A.I.Challenges.draw(a, &channel);
        var expected = try A.I.Interaction.initRows(a, source.rows, &ch);
        defer expected.deinit();
        try arena.sealFromColumns(columns);
        try source.releaseBorrowedMain();
        const original = arena.arena.raw;
        for (0..2) |offset| {
            failing.fail_index = failing.alloc_index + offset;
            try std.testing.expectError(error.OutOfMemory, arena.takeForCommit(owned_allocator));
            failing.fail_index = std.math.maxInt(usize);
            try std.testing.expectEqual(Raw.Phase.ready, arena.arena.phase);
            try std.testing.expect(arena.arena.raw.ptr == original.ptr and arena.arena.raw.len == original.len);
            try std.testing.expectEqual(T.Phase.main_detached, trace.phase);
            try std.testing.expectEqual(@as(usize, 0), source.provider_main.len);
            for (source.rows.mains) |values| try std.testing.expectEqual(@as(usize, 0), values.len);
            var restored = try A.I.Interaction.initMetadata(a, &trace, &ch);
            defer restored.deinit();
            try std.testing.expectEqualDeep(expected.claims, restored.claims);
            for (expected.tables, restored.tables) |first, second| try std.testing.expectEqualSlices(M, first, second);
            try std.testing.expectEqualSlices(M, expected.provider.columns, restored.provider.columns);
        }
        // Success still moves exactly the original owner after failed attempts.
        var commit = try arena.takeForCommit(owned_allocator);
        try std.testing.expectEqual(@as(usize, 1), commit.backing.len);
        try std.testing.expect(commit.backing[0].ptr == original.ptr);
        commit.deinit(owned_allocator);
        var restored = try source.generateInteractions(a, &ch);
        defer restored.deinit();
        try std.testing.expectEqualDeep(expected.claims, restored.claims);
    }
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}
