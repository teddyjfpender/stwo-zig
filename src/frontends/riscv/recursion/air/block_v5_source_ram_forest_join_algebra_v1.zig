//! Original PAGE/Fold plus compact root endpoints. Transition remains OPEN.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Forest = @import("../block_v5_memory_source_page_forest_algebra_v1.zig");
const Batch = @import("../../prover/block_v5_memory_source_batch_protocol_v1.zig");
pub fn close(comptime S: type, sink: anytype, admitted: *const Batch.Admission, source: [22]S, memory: [22]S) !S {
    try Forest.close(S, admitted, source, sink);
    const raw = Forest.decode(S, source).source;
    try sink.zero(memory[1]);
    try sink.zero(memory[2].add(raw.initial));
    try sink.zero(memory[3].sub(raw.endpoint));
    const count = admitted.source.records(.endpoints);
    if (count >= core.fields.m31.Modulus) return error.SourceRamForestFieldCensus;
    try sink.zero(memory[4].sub(S.fromBase(M.fromCanonical(@intCast(count)))));
    for (memory[5..]) |plane| try sink.zero(plane);
    return memory[0];
}
pub const complete_block_authority = false;
