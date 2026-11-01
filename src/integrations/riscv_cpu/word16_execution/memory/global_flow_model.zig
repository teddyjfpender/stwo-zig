//! Bounded independent reference model for the proposed global RAM LogUp
//! time/flow relation. This is NOT an AIR, a producer or a proof verifier.
//! It deliberately cannot be used for accepting a native/global execution:
//! CPU/service ownership, committed source tuples, initial-image openings
//! and terminal ABI values still require physical proofs and admissions.
const std = @import("std");

pub const MAX_AUDIT_WORDS = 64;
pub const MAX_AUDIT_EVENTS = 256;

pub const Word = struct {
    address: u64,
    value: u64,
    rights: u2,
};

pub const Origin = enum { load_store, keccak, secp256k1 };
pub const Event = struct {
    address: u64,
    previous_epoch: u16,
    previous_tick: u24,
    epoch: u16,
    tick: u24,
    before: u64,
    after: u64,
    rights: u2,
    origin: Origin,
    origin_ordinal: u32,
};

fn earlier(a_epoch: u16, a_tick: u24, b_epoch: u16, b_tick: u24) bool {
    return a_epoch < b_epoch or (a_epoch == b_epoch and a_tick < b_tick);
}

/// Check strict per-address time chains, uniqueness and exact terminal
/// values against independently supplied (not producer-inferred) boundaries.
/// The same epoch/tick on DIFFERENT addresses is allowed for a Keccak service
/// that touches many independent words. The same (address,epoch,tick) is not.
///
/// The model is intentionally quadratic and capped: no allocation, no hidden
/// host scale assumption and no claim that it constrains a prover's witness.
pub fn audit(initial: []const Word, terminal: []const Word, events: []const Event, execution_epochs: u16) !void {
    if (execution_epochs == 0 or initial.len > MAX_AUDIT_WORDS or events.len > MAX_AUDIT_EVENTS)
        return error.AuditCapacity;
    if (initial.len != terminal.len) return error.MemoryBoundaryMismatch;

    for (initial, terminal, 0..) |first, last, i| {
        if (first.address & 7 != 0 or
            (i != 0 and initial[i - 1].address >= first.address) or
            last.address != first.address or last.rights != first.rights)
            return error.NoncanonicalMemoryBoundary;
    }

    for (events, 0..) |event, i| {
        if (event.address & 7 != 0) return error.UnalignedMemoryEvent;
        if (event.epoch == 0 or event.epoch > execution_epochs or
            event.previous_epoch > execution_epochs or
            !earlier(event.previous_epoch, event.previous_tick, event.epoch, event.tick))
            return error.InvalidMemoryTime;
        if (event.before != event.after and (event.rights & 2) == 0)
            return error.UnauthorizedMemoryWrite;
        var admitted = false;
        for (initial) |first| if (first.address == event.address) {
            if (event.rights != first.rights) return error.MemoryPolicyMismatch;
            admitted = true;
            break;
        };
        if (!admitted) return error.MissingMemoryGenesis;
        for (events[0..i]) |prior| {
            if (prior.address == event.address and prior.epoch == event.epoch and prior.tick == event.tick)
                return error.DuplicateMemoryTime;
        }
    }

    var used: [MAX_AUDIT_EVENTS]bool = @splat(false);
    for (initial, terminal) |first, last| {
        var value = first.value;
        var epoch: u16 = 0;
        var tick: u24 = 0;
        while (true) {
            var next: ?usize = null;
            for (events, 0..) |event, i| {
                if (event.address != first.address or
                    event.previous_epoch != epoch or event.previous_tick != tick)
                    continue;
                if (next != null) return error.ForkedMemoryPredecessor;
                next = i;
            }
            const at = next orelse break;
            if (used[at]) return error.MemoryEventCycle;
            const event = events[at];
            if (event.before != value) return error.StaleMemoryBeforeValue;
            used[at] = true;
            value = event.after;
            epoch = event.epoch;
            tick = event.tick;
        }
        if (value != last.value) return error.MemoryTerminalMismatch;
    }
    for (used[0..events.len]) |seen| if (!seen) return error.UnreachableMemoryEvent;
}
