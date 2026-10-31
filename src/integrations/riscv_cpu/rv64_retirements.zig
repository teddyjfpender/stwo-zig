//! Concrete advice sources for the same RV64 witness projector. A compact
//! source borrows decoded immutable ROM and never re-executes the guest.
const rv = @import("stwo_riscv_frontend").rv64;
pub const Source = union(enum) {
    journal: []const rv.machine.Retirement,
    compact: *const rv.compact_tape.Tape,

    pub fn len(self: Source) usize {
        return switch (self) {
            .journal => |records| records.len,
            .compact => |tape| tape.len,
        };
    }
    pub fn pc(self: Source, index: usize) u64 {
        return switch (self) {
            .journal => |records| records[index].pc.toInt(),
            .compact => |tape| if (index == 0) tape.initial_pc else tape.storage[index - 1].next_pc,
        };
    }
    pub fn record(self: Source, index: usize, raw: u32, instruction: rv.decode.Instruction) !rv.machine.Retirement {
        return switch (self) {
            .journal => |records| records[index],
            .compact => |tape| try tape.restore(index, .{ .raw = raw, .instruction = instruction }, .local),
        };
    }
    /// The native session keeps global clocks; AIR clocks reset per batch.
    /// Checked subtraction happens before any bounded field conversion.
    pub fn localCall(self: Source, call: rv.services.Call) !rv.services.Call {
        var result = call;
        result.clock = try self.localClock(call.clock);
        return result;
    }
    pub fn localSecpCall(self: Source, call: rv.ethereum_services.SecpCall) !rv.ethereum_services.SecpCall {
        var result = call;
        result.clock = try self.localClock(call.clock);
        return result;
    }
    fn localClock(self: Source, clock: u64) !u64 {
        if (self == .compact) {
            const tape = self.compact;
            if (clock <= tape.initial_clock or clock - tape.initial_clock > tape.len) return error.InvalidTapeServiceClock;
            return clock - tape.initial_clock;
        }
        return clock;
    }
};
