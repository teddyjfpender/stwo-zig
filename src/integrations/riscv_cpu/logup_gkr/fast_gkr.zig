//! WGKR-LS-RANGE-v0 adaptor over the engine's clone-free LogUp GKR prover
//! (`lookups.gkr_prover_fast`), which emits exactly the transcript and proof
//! of the reference `lookups/gkr_prover.zig:proveBatch`; the suite compares
//! encoded proofs byte for byte. This file keeps the prototype's ownership
//! contract (inputs are consumed) and its four-instance batch limit.
const std = @import("std");
const core = @import("stwo_core");
const QM31 = core.fields.qm31.QM31;
const lookups = @import("stwo_prover_engine").lookups;
const gkr_prover = lookups.gkr_prover;
const Fast = lookups.gkr_prover_fast.ForField(QM31);

/// Owned input layer. `num == null` means LogUp singles (all numerators 1).
pub const Input = struct {
    num: ?[]QM31,
    den: []QM31,
    pub fn nVariables(self: Input) usize {
        return std.math.log2_int(usize, self.den.len);
    }
};

pub const Stats = Fast.Stats;

pub const Options = struct {
    /// Dedicated prototype pool, never borrowed from a production coordinator.
    /// The caller must include it in its own scheduling/resource admission.
    threads: usize = 1,
    /// Smallest loop that is split across the pool (tests lower it).
    min_parallel: usize = 1 << 13,
};

pub const MAX_THREADS: usize = lookups.gkr_prover_fast.MAX_THREADS;

/// Consumes `inputs` (frees their buffers). Returns the same result type as
/// the reference prover.
pub fn proveBatch(a: std.mem.Allocator, channel: anytype, inputs: []Input, options: Options, stats: ?*Stats) !gkr_prover.ProveBatchResult {
    var generic: [4]Fast.Input = undefined;
    if (inputs.len == 0 or inputs.len > generic.len) {
        for (inputs) |input| {
            if (input.num) |n| a.free(n);
            a.free(input.den);
        }
        return error.InvalidBatch;
    }
    for (inputs, 0..) |input, i| generic[i] = .{
        .num = if (input.num) |n| .{ .secure = n } else .ones,
        .den = input.den,
        .owned = true,
    };
    return Fast.proveBatch(a, channel, generic[0..inputs.len], .{ .threads = options.threads, .min_parallel = options.min_parallel }, stats);
}

pub const testing = if (@import("builtin").is_test) struct {
    pub const eqTableWith = Fast.testing.eqTableWith;
} else struct {};
