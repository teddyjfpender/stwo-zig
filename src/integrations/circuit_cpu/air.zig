//! The circuit AIR's constraint programs, bound to one proof's geometry.
//!
//! The oracle's `air-programs` subcommand records the eleven
//! `circuit_air` `FrameworkEval`s of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 into
//! `vectors/circuit/official/circuit_air.air_programs_v1.bin` (design §4.2):
//! the `STWZEVA/1` bundle the Cairo lane's captured-AIR evaluator already
//! runs. The recording is one instance (the recursive-tree test registry's
//! multiverifier). A bundle depends on its sizes only through each
//! component's trace and evaluation log sizes, its denominator inverses and
//! its preprocessed indices (the preprocessed layout is sorted by column
//! size), so `bind` rebinds exactly those to a proof's component log sizes
//! and preprocessed layout. Constraint order, mask order, relation order and
//! the random-coefficient offsets are the recording's.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");

const composition = cairo.witness.composition_bundle;
const component_list = circuit.common.component_list;
const preprocessed = circuit.common.preprocessed;
const sparse = circuit.common.sparse_arithmetic;
const direct = circuit.common.direct_arithmetic;
const finalize = circuit.common.finalize;
const PerComponent = component_list.PerComponent;

pub const Bundle = composition.Bundle;

/// SHA-256 of `circuit_air.air_programs_v1.bin`, as `vectors/circuit/provenance.json` records it.
pub const bundle_sha256 = "7b8022b09d84db371cc433aa0fcf132f7687f2720e05e4dc9a7650c575dc02c2";

/// The committed bundle, relative to the repository root.
pub const bundle_path = "vectors/circuit/official/circuit_air.air_programs_v1.bin";

/// The recorded instance: `recursive_tree_multiverifier` of
/// `crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json`
/// (`tools/stwo-circuit-oracle-rs/src/air_programs.rs`).
pub const recorded_sizes = finalize.ComponentSizes{
    .eq = 1 << 20,
    .qm31_ops = 1 << 23,
    .m31_to_u32 = 1 << 21,
    .triple_xor = 1 << 20,
    .blake_g_gate = 1 << 23,
};

pub const Error = error{
    InvalidCircuitBundle,
    MissingPreprocessedColumn,
};

/// Parses the committed bundle and checks that it is the circuit AIR: one
/// component per `ComponentList` entry, in order.
pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Bundle {
    var bundle = try Bundle.parse(allocator, bytes);
    errdefer bundle.deinit();
    if (bundle.components.len != component_list.N_COMPONENTS) return error.InvalidCircuitBundle;
    for (bundle.components, component_list.COMPONENT_NAMES) |component, name| {
        if (!std.mem.eql(u8, component.label, name)) return error.InvalidCircuitBundle;
    }
    return bundle;
}

/// The bundle rebound to `log_sizes` and `layout`. The result owns its
/// components; `template` is unchanged.
pub fn bind(
    allocator: std.mem.Allocator,
    template: *const Bundle,
    log_sizes: PerComponent(u32),
    layout: *const preprocessed.ColumnLayout,
) !Bundle {
    const recorded_layout = try preprocessed.ColumnLayout.fromComponentSizes(recorded_sizes);
    const components = try allocator.alloc(composition.Component, template.components.len);
    errdefer allocator.free(components);
    var initialized: usize = 0;
    errdefer for (components[0..initialized]) |*component| composition.deinitComponent(allocator, component);
    var max_evaluation_log: u32 = 0;
    for (template.components, components, log_sizes.toArray()) |*source, *component, trace_log| {
        component.* = try bindComponent(allocator, source, trace_log, &recorded_layout, layout);
        initialized += 1;
        max_evaluation_log = @max(max_evaluation_log, component.evaluation_log_size);
    }
    return .{
        .allocator = allocator,
        .format_version = template.format_version,
        .max_kernel_instructions = template.max_kernel_instructions,
        .total_constraints = template.total_constraints,
        .max_evaluation_log_size = max_evaluation_log,
        .plan_hash = composition.scheduleHash(components),
        .components = components,
    };
}

/// Rebind only the three arithmetic components for sparse-v3. The component
/// programs are unchanged, but their preprocessed and trace indices are
/// rebased onto the sparse trees and their random-coefficient schedule is
/// compacted. The selected set is a closed dependency profile: QM31 Gate
/// relation, M31 conversion/range requests, and the range-16 table.
pub fn bindSparseArithmetic(
    allocator: std.mem.Allocator,
    template: *const Bundle,
    log_sizes: [3]u32,
    layout: *const sparse.Layout,
) !Bundle {
    return bindSelectedArithmetic(allocator, template, &sparse.active_component_indices, &log_sizes, layout);
}

/// One-component, no-range specialization for direct-M31 public statements.
pub fn bindDirectArithmetic(
    allocator: std.mem.Allocator,
    template: *const Bundle,
    log_size: u32,
    layout: *const direct.Layout,
) !Bundle {
    return bindSelectedArithmetic(allocator, template, &direct.active_component_indices, &.{log_size}, layout);
}

fn bindSelectedArithmetic(
    allocator: std.mem.Allocator,
    template: *const Bundle,
    selected: []const usize,
    log_sizes: []const u32,
    layout: anytype,
) !Bundle {
    if (selected.len != log_sizes.len) return error.InvalidCircuitBundle;
    const recorded_layout = try preprocessed.ColumnLayout.fromComponentSizes(recorded_sizes);
    const components = try allocator.alloc(composition.Component, selected.len);
    errdefer allocator.free(components);
    var initialized: usize = 0;
    errdefer for (components[0..initialized]) |*component| composition.deinitComponent(allocator, component);
    const facts = component_list.component_facts.toArray();
    var new_base_offset: usize = 0;
    var new_interaction_offset: usize = 0;
    var next_constraint: u32 = 0;
    var max_evaluation_log: u32 = 0;
    for (selected, components, log_sizes) |source_index, *component, trace_log| {
        const source = &template.components[source_index];
        component.* = try bindComponent(allocator, source, trace_log, &recorded_layout, layout);
        initialized += 1;
        var old_base_offset: usize = 0;
        var old_interaction_offset: usize = 0;
        for (facts[0..source_index]) |earlier| {
            old_base_offset += earlier.trace_columns;
            old_interaction_offset += earlier.interaction_columns;
        }
        for (component.trace_spans) |*span| {
            const old_offset, const new_offset, const width = switch (span.tree) {
                0 => continue,
                1 => .{ old_base_offset, new_base_offset, facts[source_index].trace_columns },
                2 => .{ old_interaction_offset, new_interaction_offset, facts[source_index].interaction_columns },
                else => return error.InvalidCircuitBundle,
            };
            if (span.start < old_offset or span.end > old_offset + width)
                return error.InvalidCircuitBundle;
            span.start = @intCast(span.start - old_offset + new_offset);
            span.end = @intCast(span.end - old_offset + new_offset);
        }
        component.random_coefficient_offset = next_constraint;
        next_constraint += component.n_constraints;
        new_base_offset += facts[source_index].trace_columns;
        new_interaction_offset += facts[source_index].interaction_columns;
        max_evaluation_log = @max(max_evaluation_log, component.evaluation_log_size);
    }
    return .{
        .allocator = allocator,
        .format_version = template.format_version,
        .max_kernel_instructions = template.max_kernel_instructions,
        .total_constraints = next_constraint,
        .max_evaluation_log_size = max_evaluation_log,
        .plan_hash = composition.scheduleHash(components),
        .components = components,
    };
}

fn bindComponent(
    allocator: std.mem.Allocator,
    source: *const composition.Component,
    trace_log: u32,
    recorded_layout: *const preprocessed.ColumnLayout,
    layout: anytype,
) !composition.Component {
    const evaluation_delta = std.math.sub(u32, source.evaluation_log_size, source.trace_log_size) catch
        return error.InvalidCircuitBundle;
    const evaluation_log = trace_log + evaluation_delta;
    if (evaluation_log > 31) return error.InvalidCircuitBundle;

    const label = try allocator.dupe(u8, source.label);
    errdefer allocator.free(label);
    const spans = try allocator.dupe(composition.TraceSpan, source.trace_spans);
    errdefer allocator.free(spans);
    const indices = try allocator.alloc(u32, source.preprocessed_indices.len);
    errdefer allocator.free(indices);
    for (source.preprocessed_indices, indices) |recorded, *index| {
        if (recorded >= recorded_layout.entries.len) return error.InvalidCircuitBundle;
        const id = recorded_layout.entries[recorded].id;
        index.* = for (layout.entries, 0..) |entry, position| {
            if (std.mem.eql(u8, entry.id, id)) break @intCast(position);
        } else return error.MissingPreprocessedColumn;
    }
    const denominators = try composition.denominatorInverses(allocator, trace_log, evaluation_log);
    errdefer allocator.free(denominators);
    const sources = try allocator.dupe(composition.ExtSource, source.ext_sources);
    errdefer allocator.free(sources);
    const parts = try allocator.alloc(composition.Part, source.parts.len);
    errdefer allocator.free(parts);
    var parts_initialized: usize = 0;
    errdefer for (parts[0..parts_initialized]) |*part| part.program.deinit();
    for (source.parts, parts) |source_part, *part| {
        var program = try source_part.program.clone(allocator);
        errdefer program.deinit();
        try program.setDomainLogSize(trace_log);
        part.* = .{
            .rc_base = source_part.rc_base,
            .semantic_hash = program.header.semantic_hash,
            .program = program,
        };
        parts_initialized += 1;
    }
    return .{
        .label = label,
        .instance = source.instance,
        .trace_log_size = trace_log,
        .evaluation_log_size = evaluation_log,
        .n_constraints = source.n_constraints,
        .random_coefficient_offset = source.random_coefficient_offset,
        .trace_spans = spans,
        .preprocessed_indices = indices,
        .denominator_inverses = denominators,
        .ext_sources = sources,
        .parts = parts,
    };
}
