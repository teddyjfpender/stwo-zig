//! Owned, backend-neutral quotient topology consumed by resident CUDA ingress.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const quotient_abi = @import(
    "../../../../backends/cuda/abi/stages/quotient.zig",
);

pub const TreeSpan = struct {
    tree_ordinal: u32,
    role: proof_ir.CommitmentRole,
    first_source: u32,
    source_count: u32,
    evaluation_words: u64,
};

/// Tree-relative compact geometry. The tree identity is retained because the
/// four source trees do not share one allocation or storage lifetime.
pub const SourceDescriptor = struct {
    tree_ordinal: u32,
    local_column: u32,
    global_column: u32,
    compact: quotient_abi.CompactSourceDescriptor,
};

pub const Topology = struct {
    allocator: std.mem.Allocator,
    prepared_terms: []quotient_abi.PreparedTermDescriptor,
    group_offsets: []u32,
    group_term_indices: []u32,
    batch_terms: []quotient_abi.BatchTermDescriptor,
    sources: []SourceDescriptor,
    source_trees: []TreeSpan,
    group_log_sizes: []u32,
    partial_log_sizes: []u32,
    partial_offsets: []u64,
    sampled_value_count: u32,
    source_evaluation_word_count: u64,
    maximum_partial_rows: u32,
    identity: proof_ir.Digest,

    pub fn deinit(self: *Topology) void {
        self.allocator.free(self.partial_offsets);
        self.allocator.free(self.partial_log_sizes);
        self.allocator.free(self.group_log_sizes);
        self.allocator.free(self.source_trees);
        self.allocator.free(self.sources);
        self.allocator.free(self.batch_terms);
        self.allocator.free(self.group_term_indices);
        self.allocator.free(self.group_offsets);
        self.allocator.free(self.prepared_terms);
        self.* = undefined;
    }

    pub fn groupCount(self: Topology) usize {
        return self.group_log_sizes.len;
    }

    pub fn termCount(self: Topology) usize {
        return self.prepared_terms.len;
    }
};
