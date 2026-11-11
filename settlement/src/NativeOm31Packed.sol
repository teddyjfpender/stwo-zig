// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice OM31 values stored as eight canonical M31 limbs in one EVM word.
/// @dev Limb i occupies bits [32i,32i+31). Bit 32i+31 is always clear.
/// This is an internal memory representation, not a change to native wire bytes.
library NativeOm31Packed {
    error NonCanonicalField();

    uint256 private constant MASK = 0x7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff7fffffff;
    uint256 private constant ONES = 0x0000000100000001000000010000000100000001000000010000000100000001;

    function fromLimbs(uint32[8] memory limbs) internal pure returns (bytes32 result) {
        uint256 packed;
        for (uint256 i; i < 8; ++i) {
            uint256 limb = limbs[i];
            if (limb >= 0x7fffffff) revert NonCanonicalField();
            packed |= limb << (32 * i);
        }
        return bytes32(packed);
    }

    function toLimbs(bytes32 packed) internal pure returns (uint32[8] memory limbs) {
        for (uint256 i; i < 8; ++i) {
            limbs[i] = uint32(uint256(packed) >> (32 * i));
        }
    }

    /// @dev Caller already validated every little-endian wire coordinate.
    function fromCanonicalWire(bytes32 wire) internal pure returns (bytes32 result) {
        uint256 x = uint256(wire);
        unchecked {
            x = ((x & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff) << 8)
                | ((x >> 8) & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff);
            x = ((x & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff) << 16)
                | ((x >> 16) & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff);
            x = ((x & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff) << 32)
                | ((x >> 32) & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff);
            x = ((x & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff) << 64)
                | ((x >> 64) & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff);
            result = bytes32((x << 128) | (x >> 128));
        }
    }

    function add(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        unchecked {
            return reduce(uint256(a) + uint256(b));
        }
    }

    function sub(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        // Every lane of a+P is >= the corresponding b: no cross-lane borrow.
        unchecked {
            return reduce(uint256(a) + MASK - uint256(b));
        }
    }

    function reduce(uint256 x) private pure returns (bytes32) {
        unchecked {
            // Fold each lane's bit 31 using 2^31 = 1 mod P. Canonical inputs
            // bound the folded result by P; map P to zero without lane carries.
            uint256 r = (x & MASK) + ((x >> 31) & ONES);
            return bytes32((r + (((r + ONES) >> 31) & ONES)) & MASK);
        }
    }

    function mul(bytes32 x, bytes32 y) internal pure returns (bytes32 result) {
        // AIR literals and base-field multipliers need no extension tower.
        // Canonicality is established at the wire/program admission boundary.
        if (uint256(x) >> 32 == 0) return scaleBase(y, uint256(x));
        if (uint256(y) >> 32 == 0) return scaleBase(x, uint256(y));
        // Native tower i^2=-1, u^2=2+i, v^2=u. Keep the representation
        // packed; no expanded input/output arrays are allocated. Canonical
        // half-sums are <=2P-2<2^32, so none carries between coordinates.
        // Signed Karatsuba intermediates stay below 2^80; reduce only once.
        assembly ("memory-safe") {
            function complexMul(ar, ai, br, bi) -> re, im {
                let rr := mul(ar, br)
                let ii := mul(ai, bi)
                re := sub(rr, ii)
                im := sub(sub(mul(add(ar, ai), add(br, bi)), rr), ii)
            }
            function quarticMul(a, b) -> r, i, u, iu {
                let ar := and(a, 0xffffffff)
                let ai := and(shr(32, a), 0xffffffff)
                let au := and(shr(64, a), 0xffffffff)
                let aiu := and(shr(96, a), 0xffffffff)
                let br := and(b, 0xffffffff)
                let bi := and(shr(32, b), 0xffffffff)
                let bu := and(shr(64, b), 0xffffffff)
                let biu := and(shr(96, b), 0xffffffff)
                let lr, li := complexMul(ar, ai, br, bi)
                let hr, hi := complexMul(au, aiu, bu, biu)
                let sr, si := complexMul(add(ar, au), add(ai, aiu), add(br, bu), add(bi, biu))
                r := add(lr, sub(add(hr, hr), hi))
                i := add(li, add(hr, add(hi, hi)))
                u := sub(sub(sr, lr), hr)
                iu := sub(sub(si, li), hi)
            }
            function reduce(value) -> residue {
                residue := smod(value, 0x7fffffff)
                if slt(residue, 0) { residue := add(residue, 0x7fffffff) }
            }
            let lr, li, lu, liu := quarticMul(x, y)
            let hr, hi, hu, hiu := quarticMul(shr(128, x), shr(128, y))
            let sr, si, su, siu := quarticMul(
                add(and(x, 0xffffffffffffffffffffffffffffffff), shr(128, x)),
                add(and(y, 0xffffffffffffffffffffffffffffffff), shr(128, y)))
            result := reduce(add(lr, sub(add(hu, hu), hiu)))
            result := or(result, shl(32, reduce(add(li, add(hu, add(hiu, hiu))))))
            result := or(result, shl(64, reduce(add(lu, hr))))
            result := or(result, shl(96, reduce(add(liu, hi))))
            result := or(result, shl(128, reduce(sub(sub(sr, lr), hr))))
            result := or(result, shl(160, reduce(sub(sub(si, li), hi))))
            result := or(result, shl(192, reduce(sub(sub(su, lu), hu))))
            result := or(result, shl(224, reduce(sub(sub(siu, liu), hiu))))
        }
    }

    function scaleBase(bytes32 value, uint256 scalar) private pure returns (bytes32 result) {
        if (scalar == 0) return bytes32(0);
        if (scalar == 1) return value;
        // Eight independent products; no allocation and no cross-limb carries.
        assembly ("memory-safe") {
            for { let shift := 0 } lt(shift, 256) { shift := add(shift, 32) } {
                result := or(result, shl(shift, mulmod(and(shr(shift, value), 0xffffffff), scalar, 0x7fffffff)))
            }
        }
    }

}
