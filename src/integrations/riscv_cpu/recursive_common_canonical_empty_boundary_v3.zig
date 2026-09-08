//! Constrained canonical-empty public hashes and their Poseidon IO boundary.
//! All inputs come from the published node; no native call or claim is a literal.
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const public = @import("recursive_field_node_public_v2.zig");
const canonical = @import("recursive_common_canonical_empty_field_public_v2.zig");
const artifact = @import("recursive_node_artifact_v1.zig");
const recorder = frontend.recursion.air.composition_graph_recorder;
const permutation = frontend.air.memory_commitment.poseidon2_air;
const span = frontend.recursion.span_statement;
const S = recorder.Scalar;
const DIGEST_START = public.HEADER_WORD_COUNT + public.STATEMENT_WORD_COUNT;

pub fn record(builder: *recorder.Builder, words: *const [public.AIR_WORD_COUNT]S, challenges: *const recorder.ChallengeSet) !S {
    const body = words[public.HEADER_WORD_COUNT..][0..public.STATEMENT_WORD_COUNT];
    const layout = span.canonical_layout;
    try builder.constrainZero(words[0].sub(constant(public.FORMAT_VERSION)));
    try builder.constrainZero(words[1].sub(constant(public.SCHEMA_VERSION)));
    try builder.constrainZero(words[2].sub(constant(@intFromEnum(artifact.NodeKindV1.empty))));
    try builder.constrainZero(words[3]);
    try builder.constrainZero(body[layout.slot_height]);
    try builder.constrainZero(words[4].sub(body[layout.slot_node_index_start]));
    for (body[layout.slot_node_index_start + 1 ..][0..3]) |word| try builder.constrainZero(word);
    try builder.constrainZero(words[5].sub(words[4]));
    try builder.constrainZero(body[layout.body_tag].sub(constant(@intFromEnum(span.Tag.empty_body))));
    for (body[layout.body_tag + 1 ..]) |word| try builder.constrainZero(word);
    // The canonical-empty artifact ABI has exactly 46 padding leaves. This
    // product constrains that finite range with ordinary quadratic AIR rows.
    var index_range = S.one();
    for (artifact.REAL_LEAF_COUNT..artifact.PADDED_LEAF_COUNT) |index|
        index_range = index_range.mul(words[4].sub(constant(@intCast(index))));
    try builder.constrainZero(index_range);

    var sum = S.zero();
    const relation = challenges.get(.poseidon2_io);
    try hash(builder, body, public.STATEMENT_DIGEST_DOMAIN, words[DIGEST_START..][0..8], relation, &sum);
    const source = words[0..2].* ++ .{constant(canonical.SOURCE_KIND_CANONICAL_EMPTY)} ++ words[3..6].* ++ words[DIGEST_START..][0..8].*;
    try hash(builder, &source, canonical.SOURCE_DIGEST_DOMAIN, words[DIGEST_START + 8 ..][0..8], relation, &sum);
    const subtree = words[0..public.HEADER_WORD_COUNT].* ++ words[DIGEST_START..][0..16].*;
    try hash(builder, &subtree, public.SUBTREE_DIGEST_DOMAIN, words[DIGEST_START + 16 ..][0..8], relation, &sum);
    try hash(builder, words[0 .. public.AIR_WORD_COUNT - 8], public.OUTPUT_DIGEST_DOMAIN, words[DIGEST_START + 24 ..][0..8], relation, &sum);
    return sum;
}

fn hash(builder: *recorder.Builder, words: []const S, domain: u32, expected: *const [8]S, relation: *const recorder.ChallengeSet.Element, sum: *S) !void {
    var state = [_]S{S.zero()} ** 16;
    state[15] = constant(domain);
    var index: usize = 0;
    while (index <= words.len) : (index += 8) {
        for (0..8) |limb| {
            const position = index + limb;
            const word = if (position < words.len) words[position] else if (position == words.len) S.one() else S.zero();
            state[limb] = state[limb].add(word);
        }
        const input = state;
        permutation.permuteGeneric(S, &state);
        const denominator = try relation.combine(&(input ++ state));
        sum.* = sum.sub(denominator.inverse());
    }
    for (state[0..8], expected) |value, digest| try builder.constrainZero(value.sub(digest));
}

fn constant(value: u32) S {
    return S.fromBase(core.fields.m31.M31.fromCanonical(value));
}
