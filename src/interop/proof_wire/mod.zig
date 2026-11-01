//! Historical QM31 proof exchange API; wider profiles must select their field explicitly.
const std = @import("std");
pub const ForField = @import("family.zig").ForField;
const Default = ForField(@import("stwo_core").fields.qm31.QM31);
pub const Hasher = Default.Hasher;
pub const Proof = Default.Proof;
pub const FriConfigWire = Default.FriConfigWire;
pub const PcsConfigWire = Default.PcsConfigWire;
pub const Qm31Wire = Default.SecureWire;
pub const HashWire = Default.HashWire;
pub const MerkleDecommitmentWire = Default.MerkleDecommitmentWire;
pub const FriLayerWire = Default.FriLayerWire;
pub const FriProofWire = Default.FriProofWire;
pub const ProofWire = Default.ProofWire;
pub const CodecError = Default.CodecError;
pub const encodeProofBytes = Default.encodeProofBytes;
pub const encodeProofHexAlloc = Default.encodeProofHexAlloc;
pub const decodeProofBytes = Default.decodeProofBytes;
pub const encodeProofBytesBinary = Default.encodeProofBytesBinary;
pub const decodeProofBytesBinary = Default.decodeProofBytesBinary;
pub const proofToWire = Default.proofToWire;
pub const wireToProof = Default.wireToProof;
pub const wireToProofFor = Default.wireToProofFor;

test "api signature: proof wire codecs preserve owned byte and proof results" {
    comptime {
        const encode = @typeInfo(@TypeOf(encodeProofBytes)).@"fn";
        if (encode.params.len != 2) @compileError("encodeProofBytes parameter count drifted");
        const encoded = @typeInfo(encode.return_type.?);
        if (encoded != .error_union or encoded.error_union.payload != []u8) {
            @compileError("encodeProofBytes must return owned bytes");
        }

        const decode = @typeInfo(@TypeOf(decodeProofBytes)).@"fn";
        if (decode.params.len != 2) @compileError("decodeProofBytes parameter count drifted");
        const decoded = @typeInfo(decode.return_type.?);
        if (decoded != .error_union or decoded.error_union.payload != Proof) {
            @compileError("decodeProofBytes must return an owned Proof");
        }
    }
}

test "proof wire binary decoder rejects truncation and wrong versions" {
    try std.testing.expectError(
        CodecError.InvalidBinaryProof,
        decodeProofBytesBinary(std.testing.allocator, ""),
    );
    try std.testing.expectError(
        CodecError.UnsupportedBinaryVersion,
        decodeProofBytesBinary(std.testing.allocator, "NOTSTWO!"),
    );
}

test {
    _ = @import("bounded_count_test.zig");
    _ = @import("wide_test.zig");
}
