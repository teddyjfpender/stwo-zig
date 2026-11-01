const std = @import("std");
const M = @import("global_flow_model.zig");

const initial = [_]M.Word{
    .{ .address = 0x1000, .value = 10, .rights = 3 },
    .{ .address = 0x2000, .value = 20, .rights = 3 },
};
const terminal = [_]M.Word{
    .{ .address = 0x1000, .value = 17, .rights = 3 },
    .{ .address = 0x2000, .value = 22, .rights = 3 },
};
const events = [_]M.Event{
    .{ .address = 0x1000, .previous_epoch = 0, .previous_tick = 0, .epoch = 1, .tick = 4, .before = 10, .after = 15, .rights = 3, .origin = .load_store, .origin_ordinal = 0 },
    .{ .address = 0x2000, .previous_epoch = 0, .previous_tick = 0, .epoch = 1, .tick = 8, .before = 20, .after = 21, .rights = 3, .origin = .keccak, .origin_ordinal = 0 },
    .{ .address = 0x1000, .previous_epoch = 1, .previous_tick = 4, .epoch = 2, .tick = 4, .before = 15, .after = 17, .rights = 3, .origin = .secp256k1, .origin_ordinal = 0 },
    .{ .address = 0x2000, .previous_epoch = 1, .previous_tick = 8, .epoch = 2, .tick = 4, .before = 21, .after = 22, .rights = 3, .origin = .keccak, .origin_ordinal = 1 },
};

test "global RAM reference accepts two epochs and simultaneous service time on different words" {
    try M.audit(&initial, &terminal, &events, 2);
    var reversed = events;
    std.mem.reverse(M.Event, &reversed);
    try M.audit(&initial, &terminal, &reversed, 2);
}

test "global RAM reference rejects double-event time alias and predecessor fork" {
    var changed = events;
    changed[2].previous_epoch = 0;
    changed[2].previous_tick = 0;
    changed[2].epoch = 1;
    changed[2].tick = 4;
    try std.testing.expectError(error.DuplicateMemoryTime, M.audit(&initial, &terminal, &changed, 2));
    changed = events;
    changed[2].previous_epoch = 0;
    changed[2].previous_tick = 0;
    try std.testing.expectError(error.ForkedMemoryPredecessor, M.audit(&initial, &terminal, &changed, 2));
    changed = events;
    changed[2].previous_epoch = 3;
    try std.testing.expectError(error.InvalidMemoryTime, M.audit(&initial, &terminal, &changed, 2));
    changed = events;
    changed[2].previous_epoch = 2;
    changed[2].previous_tick = 4;
    try std.testing.expectError(error.InvalidMemoryTime, M.audit(&initial, &terminal, &changed, 2));
}

test "global RAM reference rejects stale predecessor, wrong terminal, orphan and untrusted word" {
    var changed = events;
    changed[2].before = 14;
    try std.testing.expectError(error.StaleMemoryBeforeValue, M.audit(&initial, &terminal, &changed, 2));
    var final = terminal;
    final[1].value = 23;
    try std.testing.expectError(error.MemoryTerminalMismatch, M.audit(&initial, &final, &events, 2));
    changed = events;
    changed[2].address = 0x3000;
    try std.testing.expectError(error.MissingMemoryGenesis, M.audit(&initial, &terminal, &changed, 2));
    changed = events;
    changed[2].address = 0x1004;
    try std.testing.expectError(error.UnalignedMemoryEvent, M.audit(&initial, &terminal, &changed, 2));
    // A second valid-time fragment that cannot descend to the genesis must
    // not disappear merely because all honest terminal values still match.
    var with_orphan: [5]M.Event = undefined;
    @memcpy(with_orphan[0..4], &events);
    with_orphan[4] = events[2];
    with_orphan[4].previous_tick = 5;
    with_orphan[4].tick = 6;
    try std.testing.expectError(error.UnreachableMemoryEvent, M.audit(&initial, &terminal, &with_orphan, 2));
}

test "global RAM reference rejects double genesis, wrong rights and unauthorized writes" {
    var cells = initial;
    cells[1].address = cells[0].address;
    try std.testing.expectError(error.NoncanonicalMemoryBoundary, M.audit(&cells, &terminal, &events, 2));
    var changed = events;
    changed[0].rights = 2;
    try std.testing.expectError(error.MemoryPolicyMismatch, M.audit(&initial, &terminal, &changed, 2));
    var readonly = initial;
    readonly[1].rights = 1;
    var readonly_terminal = terminal;
    readonly_terminal[1].rights = 1;
    var readonly_events = events;
    readonly_events[1].rights = 1;
    readonly_events[3].rights = 1;
    try std.testing.expectError(error.UnauthorizedMemoryWrite, M.audit(&readonly, &readonly_terminal, &readonly_events, 2));
    changed = events;
    changed[1].rights = 1;
    try std.testing.expectError(error.MemoryPolicyMismatch, M.audit(&initial, &terminal, &changed, 2));
}

test "global RAM reference rejects invalid epoch and missing terminal information" {
    var changed = events;
    changed[1].epoch = 0;
    try std.testing.expectError(error.InvalidMemoryTime, M.audit(&initial, &terminal, &changed, 2));
    try std.testing.expectError(error.AuditCapacity, M.audit(&initial, &terminal, &events, 0));
    try std.testing.expectError(error.MemoryBoundaryMismatch, M.audit(&initial, terminal[0..1], &events, 2));
    changed = events;
    changed[0].epoch = 3;
    try std.testing.expectError(error.InvalidMemoryTime, M.audit(&initial, &terminal, &changed, 2));
}

test "host reference cannot authenticate CPU or service origin without physical proof" {
    // This acceptance is INTENTIONAL. The reference proves neither origin nor
    // event completeness relative to a committed CPU/service source. A future
    // accepting protocol must bind each event to its original AIR and manifest.
    var changed = events;
    changed[1].origin = .secp256k1;
    changed[1].origin_ordinal = 9999;
    try M.audit(&initial, &terminal, &changed, 2);
}

test "global RAM reference distinguishes read permission from no-change write permission" {
    const readonly = [_]M.Word{.{ .address = 0x3000, .value = 42, .rights = 1 }};
    const read = [_]M.Event{.{
        .address = 0x3000,
        .previous_epoch = 0,
        .previous_tick = 0,
        .epoch = 1,
        .tick = 4,
        .before = 42,
        .after = 42,
        .rights = 1,
        .access = .read,
        .origin = .load_store,
        .origin_ordinal = 0,
    }};
    try M.audit(&readonly, &readonly, &read, 1);
    var impossible = read;
    impossible[0].after = 43;
    try std.testing.expectError(error.InvalidReadOnlyMemoryEffect, M.audit(&readonly, &readonly, &impossible, 1));
    const writeonly = [_]M.Word{.{ .address = 0x3000, .value = 42, .rights = 2 }};
    impossible = read;
    impossible[0].rights = 2;
    try std.testing.expectError(error.UnauthorizedMemoryRead, M.audit(&writeonly, &writeonly, &impossible, 1));
}
