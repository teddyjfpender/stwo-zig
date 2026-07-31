//! Deterministic DMG-B joypad matrix and P1 selector propagation.
//!
//! This mirrors pinned SameBoy with physical key bouncing disabled:
//! - `Core/joypad.c:GB_update_joyp` defines active-low key lines and IF edges.
//! - `Core/memory.c` defines DMG selector-switch delays.
//! - `Core/joypad.c:GB_joypad_run` applies a pending selector after that delay.
//!
//! Key bouncing and faux-analog input are host policies, not SM83 program
//! semantics. Oracle harnesses must call `GB_set_emulate_joypad_bouncing(false)`.

const std = @import("std");

pub const P1_ADDRESS: u16 = 0xff00;
pub const JOYPAD_INTERRUPT: u8 = 1 << 4;
pub const SAMEBOY_CYCLES_PER_M_CYCLE: usize = 8;

const HIGH_BITS: u8 = 0xc0;
const SELECT_BITS: u8 = 0x30;
const LINE_BITS: u8 = 0x0f;
const MAX_SWITCHING_DELAY: u8 = 48;

pub const Key = enum(u3) {
    right,
    left,
    up,
    down,
    a,
    b,
    select,
    start,

    pub fn mask(self: Key) u8 {
        return @as(u8, 1) << @intFromEnum(self);
    }
};

pub const ValidationError = error{
    InvalidHighBits,
    InvalidLineBits,
    InvalidStableSelection,
    InvalidSwitchingDelay,
};

/// One deterministic boundary event consumed by the joypad runner.
///
/// Host key replacement and P1 writes are explicit events. Time advances one
/// SM83 M-cycle at a time so the proving trace does not need an unconstrained
/// variable-duration host tick.
pub const Event = union(enum) {
    set_pressed: u8,
    write_p1: u8,
    tick_mcycle,
};

/// Complete deterministic joypad state for one DMG-B controller.
///
/// `p1` is the internal register. During selector propagation, `readP1`
/// overlays `pending_selection` on its selector bits while preserving the old
/// internal line values, matching SameBoy's externally visible read behavior.
pub const State = struct {
    p1: u8 = 0xcf,
    pressed: u8 = 0,
    pending_selection: u2 = 0,
    switching_delay: u8 = 0,

    pub fn init(
        p1: u8,
        pressed: u8,
        pending_selection: u2,
        switching_delay: u8,
    ) ValidationError!State {
        const state = State{
            .p1 = p1,
            .pressed = pressed,
            .pending_selection = pending_selection,
            .switching_delay = switching_delay,
        };
        try state.validate();
        return state;
    }

    pub fn validate(self: State) ValidationError!void {
        if (self.p1 & HIGH_BITS != HIGH_BITS)
            return error.InvalidHighBits;
        if (self.switching_delay > MAX_SWITCHING_DELAY)
            return error.InvalidSwitchingDelay;
        if (self.p1 & LINE_BITS != lineBits(self.selection(), self.pressed))
            return error.InvalidLineBits;
        if (self.switching_delay == 0 and
            self.selection() != self.pending_selection)
        {
            return error.InvalidStableSelection;
        }
    }

    pub fn hasCanonicalShape(self: State) bool {
        self.validate() catch return false;
        return true;
    }

    pub fn readP1(self: State) u8 {
        if (self.switching_delay == 0) return self.p1;
        return (self.p1 & ~SELECT_BITS) |
            (@as(u8, self.pending_selection) << 4);
    }

    /// Replaces all eight host key states.
    ///
    /// Returns whether a selected P1 line transitioned high-to-low. The caller
    /// must OR `JOYPAD_INTERRUPT` into IF when this is true.
    pub fn setPressed(self: *State, pressed: u8) bool {
        self.pressed = pressed;
        return self.updateLines();
    }

    /// Changes one host key state and reports a high-to-low selected-line edge.
    pub fn setKey(self: *State, key: Key, is_pressed: bool) bool {
        if (is_pressed) {
            self.pressed |= key.mask();
        } else {
            self.pressed &= ~key.mask();
        }
        return self.updateLines();
    }

    /// Writes P1 selector bits and starts any DMG-B propagation delay.
    ///
    /// Bits 0...3 are read-only and bits 6...7 remain high.
    pub fn writeP1(self: *State, value: u8) bool {
        const requested: u2 = @truncate(value >> 4);
        if (requested == self.selection()) return false;

        // A second write during propagation first installs the previous
        // pending selector. This is the ordering in SameBoy Core/memory.c.
        if (self.switching_delay != 0)
            self.setInternalSelection(self.pending_selection);

        const previous_selection = self.selection();
        self.pending_selection = requested;
        self.switching_delay = @max(
            self.switching_delay,
            selectorDelay(previous_selection, requested),
        );

        const internal_selection = if (self.switching_delay == 0)
            requested
        else
            requested & previous_selection;
        self.setInternalSelection(internal_selection);
        return self.updateLines();
    }

    /// Advances SameBoy's 8 MHz internal cycle unit.
    ///
    /// Returns whether installing the pending selector produced a selected-line
    /// high-to-low edge.
    pub fn tickSameBoyCycles(self: *State, cycles: usize) bool {
        if (self.switching_delay == 0) return false;
        if (@as(usize, self.switching_delay) > cycles) {
            self.switching_delay -= @intCast(cycles);
            return false;
        }

        self.switching_delay = 0;
        self.setInternalSelection(self.pending_selection);
        return self.updateLines();
    }

    pub fn tickMcycles(self: *State, count: usize) bool {
        const max_count = std.math.maxInt(usize) /
            SAMEBOY_CYCLES_PER_M_CYCLE;
        const cycles = if (count > max_count)
            std.math.maxInt(usize)
        else
            count * SAMEBOY_CYCLES_PER_M_CYCLE;
        return self.tickSameBoyCycles(cycles);
    }

    fn selection(self: State) u2 {
        return @truncate(self.p1 >> 4);
    }

    fn setInternalSelection(self: *State, selected: u2) void {
        self.p1 = (self.p1 & ~SELECT_BITS) |
            (@as(u8, selected) << 4);
    }

    fn updateLines(self: *State) bool {
        const previous = self.p1 & LINE_BITS;
        const current = lineBits(self.selection(), self.pressed);
        self.p1 = HIGH_BITS | (self.p1 & SELECT_BITS) | current;
        return previous & ~current != 0;
    }
};

/// Canonical result of applying exactly one joypad event.
pub const Transition = struct {
    before: State,
    after: State,
    event: Event,
    p1_read: u8,
    interrupt_requested: bool,

    pub fn apply(before: State, event: Event) ValidationError!Transition {
        try before.validate();
        var after = before;
        const interrupt_requested = switch (event) {
            .set_pressed => |pressed| after.setPressed(pressed),
            .write_p1 => |value| after.writeP1(value),
            .tick_mcycle => after.tickMcycles(1),
        };
        try after.validate();
        return .{
            .before = before,
            .after = after,
            .event = event,
            .p1_read = after.readP1(),
            .interrupt_requested = interrupt_requested,
        };
    }

    pub fn validate(self: Transition) error{InvalidTransition}!void {
        const expected = Transition.apply(self.before, self.event) catch
            return error.InvalidTransition;
        if (!std.meta.eql(expected, self))
            return error.InvalidTransition;
    }
};

fn lineBits(selection: u2, pressed: u8) u8 {
    const directions = pressed & LINE_BITS;
    const buttons = pressed >> 4;
    return switch (selection) {
        3 => LINE_BITS,
        2 => directionLines(directions),
        1 => ~buttons & LINE_BITS,
        0 => ~(directions | buttons) & LINE_BITS,
    };
}

fn directionLines(directions: u8) u8 {
    var lines = ~directions & LINE_BITS;
    // SameBoy's default policy gives Right precedence over Left and Up
    // precedence over Down when an action contains opposing directions.
    if (directions & Key.right.mask() != 0) lines |= Key.left.mask();
    if (directions & Key.up.mask() != 0) lines |= Key.down.mask();
    return lines;
}

fn selectorDelay(previous: u2, requested: u2) u8 {
    const transition = @as(u4, previous) |
        (@as(u4, requested) << 2);
    return switch (transition) {
        0x4, 0x6, 0xc, 0xe => 48,
        0x8, 0x9, 0xd => 24,
        else => 0,
    };
}

fn referenceLines(selection: u2, pressed: u8) u8 {
    var lines: u8 = LINE_BITS;
    for (0..4) |line| {
        const direction_mask = @as(u8, 1) << @intCast(line);
        const button_mask = @as(u8, 1) << @intCast(line + 4);
        const selected = switch (selection) {
            3 => false,
            2 => pressed & direction_mask != 0,
            1 => pressed & button_mask != 0,
            0 => pressed & (direction_mask | button_mask) != 0,
        };
        if (selected) lines &= ~direction_mask;
    }
    if (selection == 2) {
        if (pressed & Key.right.mask() != 0) lines |= Key.left.mask();
        if (pressed & Key.up.mask() != 0) lines |= Key.down.mask();
    }
    return lines;
}

test "reset state is canonical and exposes SameBoy DMG P1 reset value" {
    const state = State{};
    try std.testing.expect(state.hasCanonicalShape());
    try std.testing.expectEqual(@as(u8, 0xcf), state.readP1());
}

test "all selectors and key masks match the independent active-low matrix" {
    for (0..4) |raw_selection| {
        const selection: u2 = @intCast(raw_selection);
        for (0..256) |raw_pressed| {
            const pressed: u8 = @intCast(raw_pressed);
            try std.testing.expectEqual(
                referenceLines(selection, pressed),
                lineBits(selection, pressed),
            );
        }
    }
}

test "canonical matrix and delay vector matches pinned SameBoy DMG-B" {
    // Generated from conformance/upstream.md's SameBoy revision with bouncing
    // disabled. Layout: 4 selectors x 256 key masks, followed by
    // delay/internal-P1/read-P1 for all 16 selector transitions.
    var vector: [4 * 256 + 4 * 4 * 3]u8 = undefined;
    var cursor: usize = 0;

    for (0..4) |raw_selection| {
        const selected: u2 = @intCast(raw_selection);
        for (0..256) |raw_pressed| {
            var state = State{};
            _ = state.setPressed(@intCast(raw_pressed));
            _ = state.writeP1(@as(u8, selected) << 4);
            _ = state.tickSameBoyCycles(MAX_SWITCHING_DELAY);
            vector[cursor] = state.readP1();
            cursor += 1;
        }
    }

    for (0..4) |raw_previous| {
        const previous: u2 = @intCast(raw_previous);
        for (0..4) |raw_requested| {
            const requested: u2 = @intCast(raw_requested);
            var state = try State.init(
                HIGH_BITS | (@as(u8, previous) << 4) | LINE_BITS,
                0,
                previous,
                0,
            );
            _ = state.writeP1(@as(u8, requested) << 4);
            vector[cursor] = state.switching_delay;
            vector[cursor + 1] = state.p1;
            vector[cursor + 2] = state.readP1();
            cursor += 3;
        }
    }
    try std.testing.expectEqual(vector.len, cursor);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&vector, &digest, .{});
    const pinned_digest =
        "\xab\x18\xa2\x56\x30\x30\x07\x1c\x42\xd2\xf0\x39\xe0\xf7\x75\xd7" ++
        "\xb4\x31\x8d\x8f\xe2\xf1\x48\x96\xc2\x31\x0a\xb8\x49\x79\x5b\x8c";
    try std.testing.expectEqualSlices(u8, pinned_digest, &digest);
}

test "default opposing-direction policy matches pinned SameBoy" {
    const opposing = Key.right.mask() | Key.left.mask() |
        Key.up.mask() | Key.down.mask();
    try std.testing.expectEqual(
        @as(u8, 0x0a),
        lineBits(2, opposing),
    );
    // SameBoy applies the opposing-direction filter only to direction-only
    // selection, not when both key groups are selected.
    try std.testing.expectEqual(
        @as(u8, 0),
        lineBits(0, opposing | 0xf0),
    );
}

test "selected key presses request IF only on high-to-low edges" {
    for (std.enums.values(Key)) |key| {
        const selection: u2 = if (@intFromEnum(key) < 4) 2 else 1;
        var state = try State.init(
            HIGH_BITS | (@as(u8, selection) << 4) | LINE_BITS,
            0,
            selection,
            0,
        );
        try std.testing.expect(state.setKey(key, true));
        try std.testing.expect(!state.setKey(key, true));
        try std.testing.expect(!state.setKey(key, false));
        try std.testing.expect(state.hasCanonicalShape());
    }

    var unselected = try State.init(0xff, 0, 3, 0);
    try std.testing.expect(!unselected.setPressed(0xff));
    try std.testing.expectEqual(@as(u8, 0xff), unselected.readP1());
}

test "selector writes use the exhaustive DMG-B delay table" {
    for (0..4) |raw_previous| {
        const previous: u2 = @intCast(raw_previous);
        for (0..4) |raw_requested| {
            const requested: u2 = @intCast(raw_requested);
            var state = try State.init(
                HIGH_BITS | (@as(u8, previous) << 4) | LINE_BITS,
                0,
                previous,
                0,
            );
            try std.testing.expect(!state.writeP1(
                @as(u8, requested) << 4,
            ));
            const expected = if (previous == requested)
                0
            else
                selectorDelay(previous, requested);
            try std.testing.expectEqual(expected, state.switching_delay);
            try std.testing.expectEqual(
                @as(u8, requested),
                (state.readP1() & SELECT_BITS) >> 4,
            );
            try std.testing.expect(state.hasCanonicalShape());
        }
    }
}

test "pending selector installs at the exact SameBoy cycle boundary" {
    var state = try State.init(0xef, 0, 2, 0);
    try std.testing.expect(!state.writeP1(0x10));
    try std.testing.expectEqual(@as(u8, 48), state.switching_delay);
    try std.testing.expectEqual(@as(u8, 0xdf), state.readP1());

    try std.testing.expect(!state.tickSameBoyCycles(47));
    try std.testing.expectEqual(@as(u8, 1), state.switching_delay);
    try std.testing.expectEqual(@as(u8, 0xdf), state.readP1());

    try std.testing.expect(!state.tickSameBoyCycles(1));
    try std.testing.expectEqual(@as(u8, 0), state.switching_delay);
    try std.testing.expectEqual(@as(u8, 0xdf), state.readP1());
    try std.testing.expect(state.hasCanonicalShape());
}

test "Pokemon direction then button polling settles before its final reads" {
    var state = try State.init(0xff, 0, 3, 0);
    try std.testing.expect(!state.setPressed(
        Key.up.mask() | Key.a.mask(),
    ));

    // home/joypad.asm first selects directions and performs six P1 reads.
    try std.testing.expect(state.writeP1(0x20));
    try std.testing.expectEqual(@as(u8, 0xeb), state.readP1());
    try std.testing.expect(!state.tickMcycles(6));
    try std.testing.expectEqual(@as(u8, 0xeb), state.readP1());

    // It then selects buttons and performs ten reads. The 48 SameBoy-cycle
    // DMG transition has completed after six M-cycles.
    // The transition temporarily selects both groups, revealing A and
    // producing the same selector-induced edge as SameBoy.
    try std.testing.expect(state.writeP1(0x10));
    try std.testing.expectEqual(@as(u8, 48), state.switching_delay);
    try std.testing.expectEqual(@as(u8, 0xda), state.readP1());
    try std.testing.expect(!state.tickMcycles(5));
    try std.testing.expectEqual(@as(u8, 8), state.switching_delay);
    try std.testing.expect(!state.tickMcycles(1));
    try std.testing.expectEqual(@as(u8, 0xde), state.readP1());
    try std.testing.expect(state.hasCanonicalShape());
}

test "checkpoint validation rejects every non-canonical state class" {
    try std.testing.expectError(
        error.InvalidHighBits,
        State.init(0x4f, 0, 0, 0),
    );
    try std.testing.expectError(
        error.InvalidLineBits,
        State.init(0xce, 0, 0, 0),
    );
    try std.testing.expectError(
        error.InvalidStableSelection,
        State.init(0xef, 0, 1, 0),
    );
    try std.testing.expectError(
        error.InvalidSwitchingDelay,
        State.init(0xcf, 0, 0, 49),
    );
}

test "canonical transition validates and rejects forged outputs" {
    const before = try State.init(0xef, 0, 2, 0);
    const transition = try Transition.apply(
        before,
        .{ .set_pressed = Key.right.mask() },
    );
    try transition.validate();
    try std.testing.expect(transition.interrupt_requested);
    try std.testing.expectEqual(transition.after.readP1(), transition.p1_read);

    var forged = transition;
    forged.p1_read ^= 1;
    try std.testing.expectError(
        error.InvalidTransition,
        forged.validate(),
    );

    forged = transition;
    forged.interrupt_requested = false;
    try std.testing.expectError(
        error.InvalidTransition,
        forged.validate(),
    );
}
