//! Independent bounded global-RAM flow diagnostic over *captured advice*.
//! This is not a physical chip-to-RAM-source join. It cannot be used to
//! accept a proof: a producer could supply advice that differs from the
//! already committed CPU/service AIR. That bridge is the next required gate.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const LS = A.memory.load_store_v2;
const Secp = A.crypto.secp256k1;
const Memory = @import("../../word16_execution/memory/statement.zig");
const Model = @import("../../word16_execution/memory/global_flow_model.zig");
const Collected = @import("collector.zig").Advice;

pub const Report = struct {
    epochs: u16,
    touched_words: usize,
    ordinary_accesses: usize,
    keccak_word_accesses: usize,
    secp_word_accesses: usize,
    total_transitions: usize,
    pub const physical_origin_join_verified = false;
};

fn append(out: *[Model.MAX_AUDIT_EVENTS]Model.Event, count: *usize, event: Model.Event) !void {
    if (count.* == out.len) return error.GlobalDiagnosticEventLimit;
    out[count.*] = event;
    count.* += 1;
}
fn serviceWord(pointer: u64, lane: usize) !u64 {
    return std.math.add(u64, pointer, @as(u64, @intCast(lane)) * 8) catch return error.InvalidGlobalServicePointer;
}

/// Tests the selected 14-coordinate global RAM transition semantics against
/// real collected Keccak, secp and load/store advice, not synthetic host
/// events. Every initialized word is checked against an independently
/// supplied pristine image. All event times and values are taken from the
/// captured provider records. A separate physical proof must eventually
/// constrain those exact records as columns before the shared challenge.
pub fn auditCaptured(advice: *const Collected, image: Memory.Image) !Report {
    if (advice.events.len == 0 or advice.events.len > 65535 or
        advice.keccak.len != advice.events.len or advice.secp.len != advice.events.len)
        return error.InvalidGlobalDiagnosticRoster;
    if (advice.initial.len > Model.MAX_AUDIT_WORDS or advice.initial.len != advice.terminal.len)
        return error.GlobalDiagnosticBoundaryLimit;
    var initial: [Model.MAX_AUDIT_WORDS]Model.Word = undefined;
    var terminal: [Model.MAX_AUDIT_WORDS]Model.Word = undefined;
    for (advice.initial, advice.terminal, 0..) |before, after, i| {
        if (before.state.value != try image.initialWord(before.address) or
            before.state.rights != try image.wordRights(before.address))
            return error.UntrustedGlobalDiagnosticGenesis;
        initial[i] = .{ .address = before.address, .value = before.state.value, .rights = before.state.rights };
        terminal[i] = .{ .address = after.address, .value = after.state.value, .rights = after.state.rights };
    }
    var events: [Model.MAX_AUDIT_EVENTS]Model.Event = undefined;
    var count: usize = 0;
    var ls_count: usize = 0;
    var keccak_count: usize = 0;
    var secp_count: usize = 0;
    for (advice.events, advice.keccak, advice.secp, 0..) |ordinary, hashes, curves, shard| {
        const epoch: u16 = @intCast(shard + 1);
        for (ordinary, 0..) |e, i| {
            if (e.epoch != epoch or e.after.epoch != epoch) return error.InvalidGlobalDiagnosticEpoch;
            const d = try LS.native.describe(e.opcode);
            try append(&events, &count, .{
                .address = (e.a +% e.immediate) & ~@as(u64, 7),
                .previous_epoch = e.before.epoch,
                .previous_tick = e.before.tick,
                .epoch = e.epoch,
                .tick = e.tick,
                .before = e.before.value,
                .after = e.after.value,
                .rights = e.before.rights,
                .access = if (d.write) .write else .read,
                .origin = .load_store,
                .origin_ordinal = @intCast(i),
            });
            ls_count += 1;
        }
        for (hashes, 0..) |call, call_index| {
            if (call.epoch != epoch) return error.InvalidGlobalDiagnosticEpoch;
            for (0..25) |lane| {
                const prev = call.predecessors[lane];
                if (call.before[lane] != prev.value) return error.InconsistentCapturedServiceBefore;
                try append(&events, &count, .{
                    .address = try serviceWord(call.pointer, lane),
                    .previous_epoch = prev.epoch,
                    .previous_tick = prev.tick,
                    .epoch = call.epoch,
                    .tick = call.tick,
                    .before = call.before[lane],
                    .after = call.after[lane],
                    .rights = prev.rights,
                    .access = .read_write,
                    .origin = .keccak,
                    .origin_ordinal = @intCast(call_index),
                });
                keccak_count += 1;
            }
        }
        for (curves, 0..) |calls, kind_index| {
            const kind: Secp.program.Kind = if (kind_index == 0) .add else .double;
            // Projective inputs count 256-bit field elements; the RAM bus uses four 64-bit words per element.
            const words = Secp.word16_bridge.types.coordinates(kind) * 4;
            for (calls, 0..) |call, call_index| {
                if (call.epoch != epoch) return error.InvalidGlobalDiagnosticEpoch;
                for (0..words) |lane| {
                    const prev = call.predecessors[lane];
                    if (call.before[lane] != prev.value) return error.InconsistentCapturedServiceBefore;
                    try append(&events, &count, .{
                        .address = try serviceWord(call.pointer, lane),
                        .previous_epoch = prev.epoch,
                        .previous_tick = prev.tick,
                        .epoch = call.epoch,
                        .tick = call.tick,
                        .before = call.before[lane],
                        .after = call.after[lane],
                        .rights = prev.rights,
                        .access = .read_write,
                        .origin = .secp256k1,
                        .origin_ordinal = @intCast(call_index),
                    });
                    secp_count += 1;
                }
            }
        }
    }
    try Model.audit(initial[0..advice.initial.len], terminal[0..advice.terminal.len], events[0..count], @intCast(advice.events.len));
    return .{ .epochs = @intCast(advice.events.len), .touched_words = advice.initial.len, .ordinary_accesses = ls_count, .keccak_word_accesses = keccak_count, .secp_word_accesses = secp_count, .total_transitions = count };
}
