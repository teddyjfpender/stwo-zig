//! Allocation-free live OAM-DMA cycle controller.
//!
//! The pure `dma.zig` transition remains authoritative. This controller owns
//! only integration state needed within one CPU M-cycle: the latest transfer
//! and whether that cycle was prepared.

const std = @import("std");
const dma = @import("dma.zig");

pub const ValidationError = dma.StateError || error{
    PreparedCheckpoint,
};

pub const AdvanceError = dma.TransitionError || error{
    CycleAlreadyPrepared,
    MissingSourceByte,
    UnexpectedSourceByte,
};

pub const Controller = struct {
    state: dma.State,
    last_transfer: ?dma.Transfer = null,
    prepared: bool = false,

    pub fn init(state: dma.State) dma.StateError!Controller {
        try state.validate();
        return .{ .state = state };
    }

    pub fn validate(self: Controller) ValidationError!void {
        try self.state.validate();
        if (self.prepared) return error.PreparedCheckpoint;
    }

    pub fn nextSourceAddress(self: Controller) ?u16 {
        if (self.state.phase != .transfer) return null;
        return dma.effectiveSourceAddress(self.state.page, self.state.copied);
    }

    /// Advances DMA before the CPU access. `ff46_page` is supplied only when
    /// that same CPU cycle writes FF46, preserving old-copy-before-restart.
    pub fn advance(
        self: *Controller,
        source_byte: ?u8,
        ff46_page: ?u8,
    ) AdvanceError!dma.Transition {
        if (self.prepared) return error.CycleAlreadyPrepared;
        const expects_source = self.state.phase == .transfer;
        if (expects_source and source_byte == null)
            return error.MissingSourceByte;
        if (!expects_source and source_byte != null)
            return error.UnexpectedSourceByte;

        const event: dma.Event = if (source_byte) |value|
            if (ff46_page) |page|
                .{ .transfer_and_write = .{
                    .source_byte = value,
                    .page = page,
                } }
            else
                .{ .transfer = value }
        else if (ff46_page) |page|
            .{ .write_ff46 = page }
        else
            .tick;
        const transition = try dma.Transition.apply(self.state, event);
        self.state = transition.after;
        self.last_transfer = transition.transfer;
        self.prepared = true;
        return transition;
    }

    pub fn finishCycle(self: *Controller) void {
        std.debug.assert(self.prepared);
        self.prepared = false;
    }
};

test "controller requires exact source arity and one advance per M-cycle" {
    var controller = try Controller.init(.{});
    const start = try controller.advance(null, 0xc0);
    try std.testing.expectEqual(dma.Phase.startup, start.after.phase);
    try std.testing.expectError(
        error.CycleAlreadyPrepared,
        controller.advance(null, null),
    );
    controller.finishCycle();
    _ = try controller.advance(null, null);
    controller.finishCycle();
    try std.testing.expectError(
        error.MissingSourceByte,
        controller.advance(null, null),
    );
    var idle = try Controller.init(.{});
    try std.testing.expectError(
        error.UnexpectedSourceByte,
        idle.advance(0x42, null),
    );
}

test "controller exposes the current in-cycle transfer" {
    var controller = try Controller.init(.{});
    _ = try controller.advance(null, 0xc0);
    controller.finishCycle();
    _ = try controller.advance(null, null);
    controller.finishCycle();
    const transfer = try controller.advance(0x42, null);
    try std.testing.expectEqualDeep(transfer.transfer, controller.last_transfer);
}
