//! Shared protocol validation for verifier-published OODS mask columns.
//!
//! RISC-V recursion currently has two exact two-point LogUp conventions.
//! Shared/legacy providers request `[current, previous]`; universal typed rows
//! request `[previous, current]`. Both are authenticated by the native PCS
//! verifier, and downstream capture identities retain the original order.

const stwo_core = @import("stwo_core");

const CirclePointQM31 = stwo_core.circle.CirclePointQM31;

pub const Error = error{SamplePointLayoutMismatch};

/// Compact, identity-stable description of one column's OODS mask.
///
/// The first three tags intentionally equal the legacy sample-count encoding.
/// Existing `none`, `current`, and current-first pair profiles therefore retain
/// their byte-for-byte profile identity. Tag 3 extends the formerly-invalid
/// count space with the universal typed row's previous-first convention.
pub const Layout = enum(u8) {
    none = 0,
    current = 1,
    current_previous = 2,
    previous_current = 3,

    pub fn sampleCount(self: Layout) u8 {
        return switch (self) {
            .none => 0,
            .current => 1,
            .current_previous, .previous_current => 2,
        };
    }

    pub fn hasPeriodicity(self: Layout) bool {
        return switch (self) {
            .current_previous, .previous_current => true,
            .none, .current => false,
        };
    }
};

/// Classifies one column without normalizing its order. The returned tag is
/// suitable for inclusion in verifier-owned profile identities.
pub fn classifyColumn(
    points: []const CirclePointQM31,
    current: CirclePointQM31,
    previous: CirclePointQM31,
) Error!Layout {
    return switch (points.len) {
        0 => .none,
        1 => if (points[0].eql(current))
            .current
        else
            error.SamplePointLayoutMismatch,
        2 => if (points[0].eql(current) and points[1].eql(previous))
            .current_previous
        else if (points[0].eql(previous) and points[1].eql(current))
            .previous_current
        else
            error.SamplePointLayoutMismatch,
        else => error.SamplePointLayoutMismatch,
    };
}

/// Accepts the complete protocol vocabulary for one sampled column:
/// empty, current-only, or either exact ordered current/previous pair.
/// Previous-only, duplicate, mutated, and wider masks are rejected.
pub fn validateColumn(
    points: []const CirclePointQM31,
    current: CirclePointQM31,
    previous: CirclePointQM31,
) Error!void {
    _ = try classifyColumn(points, current, previous);
}
