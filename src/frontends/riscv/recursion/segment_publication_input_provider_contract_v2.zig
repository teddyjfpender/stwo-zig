//! Stable publication-provider authority independent of prepared witnesses.
const shape = @import("air/segment_publication_input_provider_shape_v2.zig");
const air = @import("air/segment_publication_input_provider_v2.zig");
const relation = @import("../air/lang/relation.zig");
const ShaHasher = @import("publication_authority_encoding.zig").ShaHasher;
pub const Shape = shape.Shape;
pub const PROPOSED_ROSTER_ROW = shape.PROPOSED_ROSTER_ROW;
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;

pub fn sourceAuthorityShaId() [32]u8 {
    var hash = ShaHasher.init(
        "stwo-zig/typed-air/segment-publication-input-provider/authority/v2\x00",
    );
    hash.u16Value(FORMAT_VERSION);
    hash.u16Value(SCHEMA_VERSION);
    hash.u8Value(PROPOSED_ROSTER_ROW);
    hash.u16Value(shape.FORMAT_VERSION);
    hash.u16Value(shape.SECURE_LIMB_COUNT);
    hash.u16Value(shape.LUP2_WORD_COUNT);
    hash.u16Value(air.PREPROCESSED_COLUMN_COUNT);
    hash.u16Value(air.PHYSICAL_MAIN_COLUMN_COUNT);
    hash.u16Value(air.INTERACTION_COLUMN_COUNT);
    hash.u16Value(air.DIRECT_CONSTRAINT_COUNT);
    hash.u16Value(air.RELATION_EVENT_COUNT);
    hash.u8Value(@intFromEnum(relation.Domain.recursion_verifier_input_word));
    hash.u8Value(@intFromEnum(relation.Role.emit));
    hash.rawBytes(&air.SEMANTIC_DIGEST);
    hash.rawBytes(&relation.registryOrderDigest());
    return hash.finalize();
}
