//! Shared protocol validation for verifier-published OODS mask columns.
//!
//! Exact native mask orders, including the wider Ethereum provider windows.
//! Capture identities retain the original order; arbitrary masks are rejected.

const stwo_core = @import("stwo_core");
const keccak = @import("../air/guest_precompile/keccakf_component.zig");
const secp = @import("../air/guest_precompile/secp256k1_component.zig");

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
    secp256k1_main = 4,
    keccak_state = 5,

    pub fn offsets(self: Layout) []const isize {
        return switch (self) {
            .none => &.{},
            .current => &.{0},
            .current_previous => &.{ 0, -1 },
            .previous_current => &.{ -1, 0 },
            .secp256k1_main => &secp.MAIN_MASK_OFFSETS,
            .keccak_state => &keccak.STATE_MASK_OFFSETS,
        };
    }

    pub fn sampleCount(self: Layout) u8 {
        return @intCast(self.offsets().len);
    }

    pub fn hasPeriodicity(self: Layout) bool {
        // The native PCS inserts a periodicity term only for two-point masks.
        return self.sampleCount() == 2;
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
        3, 6 => blk: {
            const layout: Layout = if (points.len == 3) .secp256k1_main else .keccak_state;
            const step = current.sub(previous);
            for (points, layout.offsets()) |point, offset| {
                if (!point.eql(current.add(step.mulSigned(offset))))
                    return error.SamplePointLayoutMismatch;
            }
            break :blk layout;
        },
        else => error.SamplePointLayoutMismatch,
    };
}

/// Accepts the complete protocol vocabulary for one sampled column:
/// empty, current-only, either current/previous pair, or the native Ethereum
/// windows. Previous-only, duplicate, reordered and mutated masks are rejected.
pub fn validateColumn(
    points: []const CirclePointQM31,
    current: CirclePointQM31,
    previous: CirclePointQM31,
) Error!void {
    _ = try classifyColumn(points, current, previous);
}
