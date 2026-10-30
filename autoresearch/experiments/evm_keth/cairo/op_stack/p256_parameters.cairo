// NIST P-256 parameters, split into four 96-bit modular-builtin limbs.
from ethereum_types.numeric import U256, U256Struct, U384, U384Struct
from cairo_ec.curve.g1_point import G1Point, G1PointStruct

struct Curve {
    p: U384,
    a: U384,
    b: U384,
    order: U384,
    prime256: U256,
    order256: U256,
    generator: G1Point,
}

func parameters() -> Curve* {
    tempvar p = U384(new U384Struct(0xffffffffffffffffffffffff, 0x0, 0xffffffff00000001, 0x0));
    tempvar a = U384(new U384Struct(0xfffffffffffffffffffffffc, 0x0, 0xffffffff00000001, 0x0));
    tempvar b = U384(new U384Struct(0xcc53b0f63bce3c3e27d2604b, 0xb3ebbd55769886bc651d06b0, 0x5ac635d8aa3a93e7, 0x0));
    tempvar order = U384(new U384Struct(0xa7179e84f3b9cac2fc632551, 0xffffffffffffffffbce6faad, 0xffffffff00000000, 0x0));
    tempvar gx = U384(new U384Struct(0x2deb33a0f4a13945d898c296, 0xf8bce6e563a440f277037d81, 0x6b17d1f2e12c4247, 0x0));
    tempvar gy = U384(new U384Struct(0x6b315ececbb6406837bf51f5, 0x8ee7eb4a7c0f9e162bce3357, 0x4fe342e2fe1a7f9b, 0x0));
    tempvar prime256 = U256(new U256Struct(0xffffffffffffffffffffffff, 0xffffffff000000010000000000000000));
    tempvar order256 = U256(new U256Struct(0xbce6faada7179e84f3b9cac2fc632551, 0xffffffff00000000ffffffffffffffff));
    tempvar generator = G1Point(new G1PointStruct(gx, gy));
    tempvar result = new Curve(p, a, b, order, prime256, order256, generator);
    return result;
}
