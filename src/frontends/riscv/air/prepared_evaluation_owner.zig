//! Owned quotient-domain views for prepared RISC-V AIR evaluators.
//!
//! A committed polynomial is normally retained on the PCS LDE domain.  That
//! domain happens to equal the degree-one quotient domain in the frozen V1
//! profile, but it is not an AIR invariant.  Higher PCS blowup factors retain
//! a wider LDE while the quotient still needs only `trace_log + 1` points.
//!
//! `Owner` preserves the zero-copy V1 fast path and evaluates retained
//! coefficients only for sources whose committed domain differs.  Its buffers
//! are prepared once, before task publication, and remain immutable while
//! parallel row evaluators borrow them.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_poly = @import("stwo_prover_engine").poly.circle.poly;
const prover_twiddles = @import("stwo_prover_engine").poly.twiddles;

pub const Error = error{
    InvalidProofShape,
    ResourceReservationOverflow,
};

pub fn needsOwned(
    poly: prover_component.Poly,
    trace_log_size: u32,
    evaluation_log_size: u32,
) !bool {
    try validateSource(poly, trace_log_size, evaluation_log_size);
    return poly.log_size != evaluation_log_size;
}

pub const Owner = struct {
    allocator: std.mem.Allocator,
    buffers: [][]M31,
    initialized: usize = 0,

    pub fn init(allocator: std.mem.Allocator, owned_count: usize) !Owner {
        return .{
            .allocator = allocator,
            .buffers = try allocator.alloc([]M31, owned_count),
        };
    }

    pub fn deinit(self: *Owner) void {
        for (self.buffers[0..self.initialized]) |buffer| {
            self.allocator.free(buffer);
        }
        self.allocator.free(self.buffers);
        self.* = undefined;
    }

    /// Returns a stable quotient-domain view.  Equal-domain sources remain
    /// borrowed; mismatched sources are staged as zero-padded coefficients and
    /// evaluated together by `finish`.
    pub fn value(
        self: *Owner,
        poly: prover_component.Poly,
        trace_log_size: u32,
        evaluation_log_size: u32,
        evaluation_size: usize,
    ) ![]const M31 {
        try validateSource(poly, trace_log_size, evaluation_log_size);
        if (poly.log_size == evaluation_log_size) return poly.values;
        if (self.initialized == self.buffers.len)
            return error.InvalidProofShape;

        const coefficients = poly.coefficients.?;
        const source = coefficients.coefficients();
        if (source.len > evaluation_size) return error.InvalidProofShape;
        const buffer = try self.allocator.alloc(M31, evaluation_size);
        errdefer self.allocator.free(buffer);
        @memcpy(buffer[0..source.len], source);
        @memset(buffer[source.len..], M31.zero());
        self.buffers[self.initialized] = buffer;
        self.initialized += 1;
        return buffer;
    }

    /// Converts every staged coefficient buffer to evaluations in one batched
    /// transform setup.  No work or twiddle allocation occurs on the V1 path.
    pub fn finish(self: *Owner, evaluation_domain: anytype) !void {
        if (self.initialized != self.buffers.len)
            return error.InvalidProofShape;
        if (self.buffers.len == 0) return;

        var twiddles = try prover_twiddles.precomputeM31(
            self.allocator,
            evaluation_domain.half_coset,
        );
        defer prover_twiddles.deinitM31(self.allocator, &twiddles);
        try prover_poly.evaluateBuffersWithTwiddles(
            self.buffers,
            evaluation_domain,
            prover_twiddles.TwiddleTree([]const M31).init(
                twiddles.root_coset,
                twiddles.twiddles,
                twiddles.itwiddles,
            ),
        );
    }
};

/// Resident bytes added by an owner, excluding allocator metadata.
pub fn residentBytes(owned_count: usize, evaluation_size: usize) Error!usize {
    const views = std.math.mul(usize, owned_count, @sizeOf([]M31)) catch
        return error.ResourceReservationOverflow;
    const values = std.math.mul(usize, owned_count, evaluation_size) catch
        return error.ResourceReservationOverflow;
    const value_bytes = std.math.mul(usize, values, @sizeOf(M31)) catch
        return error.ResourceReservationOverflow;
    return std.math.add(usize, views, value_bytes) catch
        error.ResourceReservationOverflow;
}

fn validateSource(
    poly: prover_component.Poly,
    trace_log_size: u32,
    evaluation_log_size: u32,
) !void {
    try poly.validate();
    if (poly.log_size == evaluation_log_size) return;
    const coefficients = poly.coefficients orelse
        return error.InvalidProofShape;
    if (coefficients.logSize() != trace_log_size)
        return error.InvalidProofShape;
}
