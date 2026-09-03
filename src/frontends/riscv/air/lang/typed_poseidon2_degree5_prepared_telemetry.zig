//! Process-local timing observer for the non-production degree-five profile.
//!
//! These counters are diagnostic only and never enter a statement, transcript,
//! proof, verifier-program identity, or production dispatch decision.

const std = @import("std");

pub const Snapshot = struct {
    prepare_calls: u64 = 0,
    run_calls: u64 = 0,
    layout_ns: u64 = 0,
    source_stage_ns: u64 = 0,
    twiddle_ns: u64 = 0,
    retained_extension_ns: u64 = 0,
    recomputed_extension_ns: u64 = 0,
    finalize_ns: u64 = 0,
    row_evaluation_ns: u64 = 0,
    source_columns: u64 = 0,
    borrowed_columns: u64 = 0,
    retained_columns: u64 = 0,
    recomputed_columns: u64 = 0,
    evaluated_rows: u64 = 0,

    pub fn delta(after: Snapshot, before: Snapshot) Snapshot {
        var result: Snapshot = undefined;
        inline for (std.meta.fields(Snapshot)) |field| {
            @field(result, field.name) = @field(after, field.name) -
                @field(before, field.name);
        }
        return result;
    }

    pub fn prepareNs(self: Snapshot) u64 {
        return self.layout_ns + self.source_stage_ns + self.twiddle_ns +
            self.retained_extension_ns + self.recomputed_extension_ns +
            self.finalize_ns;
    }
};

pub const PrepareSample = struct {
    layout_ns: u64,
    source_stage_ns: u64,
    twiddle_ns: u64,
    retained_extension_ns: u64,
    recomputed_extension_ns: u64,
    finalize_ns: u64,
    source_columns: usize,
    borrowed_columns: usize,
    retained_columns: usize,
    recomputed_columns: usize,
};

var mutex: std.Thread.Mutex = .{};
var totals: Snapshot = .{};

pub fn reset() void {
    mutex.lock();
    defer mutex.unlock();
    totals = .{};
}

pub fn snapshot() Snapshot {
    mutex.lock();
    defer mutex.unlock();
    return totals;
}

pub fn recordPrepare(sample: PrepareSample) void {
    mutex.lock();
    defer mutex.unlock();
    totals.prepare_calls += 1;
    totals.layout_ns += sample.layout_ns;
    totals.source_stage_ns += sample.source_stage_ns;
    totals.twiddle_ns += sample.twiddle_ns;
    totals.retained_extension_ns += sample.retained_extension_ns;
    totals.recomputed_extension_ns += sample.recomputed_extension_ns;
    totals.finalize_ns += sample.finalize_ns;
    totals.source_columns += sample.source_columns;
    totals.borrowed_columns += sample.borrowed_columns;
    totals.retained_columns += sample.retained_columns;
    totals.recomputed_columns += sample.recomputed_columns;
}

pub fn recordRun(elapsed_ns: u64, rows: usize) void {
    mutex.lock();
    defer mutex.unlock();
    totals.run_calls += 1;
    totals.row_evaluation_ns += elapsed_ns;
    totals.evaluated_rows += rows;
}
