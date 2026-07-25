//! Runtime lowering of tree-relative Cairo quotient sources.
//!
//! The authenticated topology retains stable tree/column identities. This
//! layer resolves those identities to address-stable resident evaluation
//! columns without pretending that four independently owned trees are one
//! allocation.

const std = @import("std");
const proof_ir = @import("stwo_backend_contracts").proof_program;
const quotient_abi = @import(
    "../../../../backends/cuda/abi/stages/quotient.zig",
);
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const quotient_stage = @import(
    "../../../../backends/cuda/runtime/stages/quotient.zig",
);
const pcs_types = @import("../pcs_hooks_types.zig");
const types = @import("types.zig");

pub const Bound = struct {
    allocator: std.mem.Allocator,
    descriptors: []quotient_abi.AddressedSourceDescriptor,
    columns: []common.Words,
    topology_identity: proof_ir.Digest,
    identity: proof_ir.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        topology: types.Topology,
        trees: pcs_types.TraceTrees,
    ) !Bound {
        if (std.mem.allEqual(u8, &topology.identity, 0) or
            topology.sources.len == 0 or
            topology.source_evaluation_word_count == 0)
        {
            return error.InvalidKernelDescriptor;
        }
        try validateTreeInventory(topology, trees);
        const descriptors = try allocator.alloc(
            quotient_abi.AddressedSourceDescriptor,
            topology.sources.len,
        );
        errdefer allocator.free(descriptors);
        const columns = try allocator.alloc(
            common.Words,
            topology.sources.len,
        );
        errdefer allocator.free(columns);
        for (topology.sources, descriptors, columns) |
            source,
            *descriptor,
            *column,
        | {
            const tree = try treeAt(trees, source.tree_ordinal);
            const expected_global = std.math.add(
                u32,
                tree.first_column,
                source.local_column,
            ) catch return error.SizeOverflow;
            if (source.global_column != expected_global or
                source.local_column >= tree.column_count or
                source.compact.stride_words == 0 or
                source.compact.log_size == 0 or
                source.compact.log_size > 30)
            {
                return error.InvalidKernelDescriptor;
            }
            const first = std.math.cast(
                usize,
                source.compact.offset_words,
            ) orelse return error.SizeOverflow;
            column.* = try tree.evaluations.sub(
                first,
                source.compact.stride_words,
            );
            if (column.owner == 0 or column.generation == 0)
                return error.InvalidKernelDescriptor;
            descriptor.* = .{
                .address = column.address,
                .stride_words = source.compact.stride_words,
                .log_size = source.compact.log_size,
            };
        }
        return .{
            .allocator = allocator,
            .descriptors = descriptors,
            .columns = columns,
            .topology_identity = topology.identity,
            .identity = bindingIdentity(topology.identity, descriptors, columns),
        };
    }

    pub fn deinit(self: *Bound) void {
        self.allocator.free(self.columns);
        self.allocator.free(self.descriptors);
        self.* = undefined;
    }

    pub fn prepareNumerator(
        self: Bound,
        session: anytype,
        topology: types.Topology,
        quotient: pcs_types.Quotient,
    ) !quotient_stage.AddressedNumeratorTopology {
        if (!std.mem.eql(
            u8,
            &self.topology_identity,
            &topology.identity,
        ) or self.descriptors.len != topology.sources.len or
            self.columns.len != topology.sources.len or
            quotient.prepared_terms.len != topology.prepared_terms.len or
            quotient.group_offsets.len != topology.group_offsets.len or
            quotient.group_term_indices.len !=
                topology.group_term_indices.len or
            quotient.batch_terms.len != topology.batch_terms.len or
            quotient.source_descriptors.len != topology.sources.len or
            quotient.group_log_sizes.len != topology.group_log_sizes.len)
        {
            return error.InvalidKernelDescriptor;
        }
        return quotient_stage.prepareAddressedNumeratorTopology(
            session,
            topology.group_offsets,
            topology.batch_terms,
            self.descriptors,
            self.columns,
            topology.group_log_sizes,
            topology.partial_offsets,
            quotient.group_offsets,
            quotient.batch_terms,
            quotient.source_descriptors,
            quotient.group_log_sizes,
            quotient.partial_offsets,
            topology.maximum_partial_rows,
            topology.prepared_terms.len,
        );
    }
};

fn validateTreeInventory(
    topology: types.Topology,
    trees: pcs_types.TraceTrees,
) !void {
    if (topology.source_trees.len != trees.len)
        return error.InvalidKernelDescriptor;
    var total_sources: u64 = 0;
    var total_words: u64 = 0;
    for (topology.source_trees) |span| {
        const tree = try treeAt(trees, span.tree_ordinal);
        if (tree.role != span.role or
            tree.first_column != span.first_source or
            tree.column_count != span.source_count or
            tree.evaluations.len != span.evaluation_words)
        {
            return error.InvalidKernelDescriptor;
        }
        total_sources = std.math.add(
            u64,
            total_sources,
            span.source_count,
        ) catch return error.SizeOverflow;
        total_words = std.math.add(
            u64,
            total_words,
            span.evaluation_words,
        ) catch return error.SizeOverflow;
    }
    if (total_sources != topology.sources.len or
        total_words != topology.source_evaluation_word_count)
    {
        return error.InvalidKernelDescriptor;
    }
}

fn treeAt(
    trees: pcs_types.TraceTrees,
    ordinal: u32,
) !pcs_types.CompactTree {
    for (trees.active()) |tree| {
        if (tree.ordinal == ordinal) return tree;
    }
    return error.InvalidKernelDescriptor;
}

fn bindingIdentity(
    topology_identity: proof_ir.Digest,
    descriptors: []const quotient_abi.AddressedSourceDescriptor,
    columns: []const common.Words,
) proof_ir.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/cuda/quotient-resident-sources/v1\x00");
    hash.update(&topology_identity);
    for (descriptors, columns) |descriptor, column| {
        hashInt(&hash, u64, descriptor.address);
        hashInt(&hash, u32, descriptor.stride_words);
        hashInt(&hash, u32, descriptor.log_size);
        hashInt(&hash, u64, column.owner);
        hashInt(&hash, u64, column.generation);
    }
    return hash.finalResult();
}

fn hashInt(
    hash: *std.crypto.hash.sha2.Sha256,
    comptime T: type,
    value: anytype,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
