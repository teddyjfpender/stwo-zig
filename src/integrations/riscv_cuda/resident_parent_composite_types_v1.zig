//! Immutable routing metadata, never witness values supplied by the prover.
const Routes = @import("resident_parent_value_routes_v1.zig");
pub const SourceKind = Routes.Kind;
pub const Source = Routes.Source;
pub const Destination = enum(u32) { hash_bytes, arithmetic_inputs, resident_words, main_words };
pub const Write = extern struct { source: Source, destination: Destination, byte_offset: u32, bytes: u32, phase: u32 };
pub const Task = struct { phase: u32, operation: Operation };
pub const Operation = union(enum) {
    write: struct { first: u32, count: u32 },
    hash_frame: u32,
    arithmetic: struct { first: u32, count: u32 },
    direct_group: u32,
    readonly: void,
    child_replay: struct { output_first: u32, trace_first: u32 },
    zero_answers: struct { destination_first: u32 },
    derive_answers: void,
    fri_expand: struct { deep_first: u32, alpha_first: u32, destination_first: u32 },
    child_paths: struct { destination_first: u32 },
    child_gather: enum(u2) { composition, deep, fri },
    resolve: struct { count: u32, resident_first: u32 },
    scatter_hash: struct { first: u32, count: u32 },
};
pub const HashRow = extern struct { kind: u32, source_logical_row: u32, destination_cohort: u32, destination_logical_row: u32 };
pub const Cohort = extern struct { first_word: u64, rows: u32, columns: u32 };
pub const Call = Routes.Call;
pub const DirectSource = Routes.Source;
