//! Small, owned verifier inputs for candidate-key preparation. The execution
//! witness can be released before the verifier commits its preprocessed tree.
const std = @import("std");
const witness = @import("blake3_ethereum_witness.zig").ShaOwner;
const native_mod = @import("../air/statement.zig");
const extension_mod = @import("blake3_ethereum_sha_statement.zig");
const plan_mod = @import("blake3_commitment_plan.zig");
const public_mod = @import("../air/public_data.zig");
const range_mod = @import("../recursion/air/compact_range_geometry.zig");

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    native: native_mod.Blake3ExecutionStatement,
    extension: extension_mod.Statement,
    plan: plan_mod.Plan,
    plan_id: [32]u8,
    ranges: range_mod.Plan,
    input_words: []u32,
    output_words: []public_mod.OutputWord,

    pub fn init(a: std.mem.Allocator, owner: *const witness) !Snapshot {
        const ranges = (owner.native.compact_ranges orelse return error.MissingCompactRangeGeometry).plan;
        const source_admission = try owner.admission();
        const source = &owner.native.statement;
        const input_words = try a.dupe(u32, source.public_data.io_entries.input_words);
        errdefer a.free(input_words);
        const output_words = try a.dupe(public_mod.OutputWord, source.public_data.io_entries.output_words);
        errdefer a.free(output_words);
        var plan = if (source_admission.plan.program_schedule == .sparse_active)
            try plan_mod.Plan.initSparse(a, source_admission.plan.roots, source_admission.plan.memories, source_admission.plan.programs, source_admission.plan.program_leaves)
        else
            try plan_mod.Plan.init(a, source_admission.plan.roots, source_admission.plan.memories, source_admission.plan.programs, source_admission.plan.program_leaves);
        errdefer plan.deinit();
        var native = source.*;
        native.public_data.io_entries.input_words = input_words;
        native.public_data.io_entries.output_words = output_words;
        const result = Snapshot{
            .allocator = a,
            .native = native,
            .extension = owner.statement,
            .plan = plan,
            .plan_id = source_admission.expected_id,
            .ranges = ranges,
            .input_words = input_words,
            .output_words = output_words,
        };
        try result.admission().validatePublic(&result.native.public_data);
        return result;
    }

    pub fn admission(self: *const Snapshot) plan_mod.Admission {
        return .{ .plan = &self.plan, .expected_id = self.plan_id };
    }

    pub fn deinit(self: *Snapshot) void {
        self.plan.deinit();
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.* = undefined;
    }
};
