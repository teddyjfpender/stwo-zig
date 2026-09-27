//! ONE genuine tail verifier at an independently selected common ancestor.
//! The returned original public byte wires must be joined to actual window
//! consumer exports; this API cannot grant coverage/source completeness.
const std = @import("std");
const Source = @import("block_v5_input_tail_source_v1.zig");
const Receiver = @import("block_v5_input_tail_receiver_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
pub const Prepared = struct {
    source: Source.Source,
    verifier: Child.Prepared,
    pub const complete_source_authority = false;
    pub fn deinit(self: *Prepared) void {
        self.verifier.deinit();
        self.* = undefined;
    }
};
/// Fresh/policy owners must survive all ancestor public-source readers. This
/// consumes no capture; the existing real State.plan/emit path authenticates
/// full DEEP/FRI/Merkle/PoW and exact original new-provider transcript.
pub fn prepare(a: std.mem.Allocator, fresh: *const Receiver.Fresh, child_ordinal: u32, namespace_start: u32, transcript_capacity: u32) !Prepared {
    const source = try Source.Source.init(fresh);
    const admitted = Source.Admission.init(&source);
    const verifier = try Child.prepare(a, admitted, &fresh.equation, child_ordinal, Source.PUBLIC_CIRCUIT, namespace_start, transcript_capacity);
    return .{ .source = source, .verifier = verifier };
}

/// This expresses only exact provider placement, not semantic/source closure.
/// The final exact window ancestor must derive this policy from its admitted
/// whole-job roster, not a supplied list of arbitrary zero claim coordinates.
pub const Placement = struct {
    first_window: u32,
    window_count: u32,
    job_window_count: u32,
    provider_occurrences: u32,
    pub fn requireCommonAncestor(self: Placement, independent_job_windows: u32) !void {
        if (independent_job_windows == 0 or self.first_window != 0 or self.window_count != independent_job_windows or self.job_window_count != independent_job_windows or self.provider_occurrences != 1) return error.UntrustedInputTailPlacement;
    }
    pub fn requireComplete(_: Placement) !void {
        return error.InputTailWindowSourceClosureUnavailable;
    }
};
