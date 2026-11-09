// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeFriFold} from "./NativeFriFold.sol";

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
        // Reuse the existing 27-product tower authority. All three expanded
        // operands are temporary; none escapes. Restore the free pointer so
        // a long IR program does not allocate 768+ bytes per multiplication.
        uint256 restore;
        assembly ("memory-safe") { restore := mload(0x40) }
        uint32[8] memory a;
        uint32[8] memory b;
        uint32[8] memory out;
        for (uint256 i; i < 8; ++i) {
            a[i] = uint32(uint256(x) >> (32 * i));
            b[i] = uint32(uint256(y) >> (32 * i));
        }
        NativeFriFold.multiplyInto(a, b, out);
        uint256 packed;
        for (uint256 i; i < 8; ++i) {
            packed |= uint256(out[i]) << (32 * i);
        }
        result = bytes32(packed);
        assembly ("memory-safe") { mstore(0x40, restore) }
    }
}
