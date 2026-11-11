// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Raw BLAKE2s-256 hashing for Stwo's domain-prefixed lifted VCS.
/// @dev Each 64-byte domain block has been compressed once, with count 64
///      and the final flag clear. These states are not finalized digests.
library Blake2sLifted {
    uint256 private constant LEAF_0 = 0x382935d000000000cff75ec300000000fd531f42000000006510b1f7;
    uint256 private constant LEAF_1 = 0x28047aca00000000e8e9286600000000950eb56400000000ab15dbf2;
    uint256 private constant NODE_0 = 0xfc5d8d28000000007b4acada00000000841cea3000000000e5cf8926;
    uint256 private constant NODE_1 = 0x8ae795c800000000c0d319c700000000b29da52800000000fc6ef857;

    // BLAKE2s IV with the unkeyed 32-byte digest parameter in the first lane.
    uint256 private constant IV_0 = 0xa54ff53a000000003c6ef37200000000bb67ae85000000006b08e647;
    uint256 private constant IV_1 = 0x5be0cd19000000001f83d9ab000000009b05688c00000000510e527f;

    /// @dev Hashes one unprefixed block. The caller supplies zero padding.
    function shortDigest(bytes32 left, bytes32 right, uint8 length) internal pure returns (bytes32) {
        assert(length <= 64);
        (uint256 lo, uint256 hi) = compress(IV_0, IV_1, left, right, length, true);
        return digest(lo, hi);
    }

    function node(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        (uint256 lo, uint256 hi) = compress(NODE_0, NODE_1, left, right, 128, true);
        return digest(lo, hi);
    }

    /// @dev row must contain at least one word. The caller checks its shape.
    function leaf(bytes calldata row) internal pure returns (bytes32) {
        return hashTail(LEAF_0, LEAF_1, 64, row);
    }

    /// @dev Raw BLAKE2s of a 32-byte channel digest and an unpadded calldata slice.
    function absorb(bytes32 prefix, bytes calldata data) internal pure returns (bytes32) {
        if (data.length <= 32) return shortDigest(prefix, loadPadded(data, 0), uint8(32 + data.length));
        (uint256 lo, uint256 hi) = compress(IV_0, IV_1, prefix, loadPadded(data, 0), 64, false);
        return hashTail(lo, hi, 64, data[32:]);
    }

    function hashTail(uint256 lo, uint256 hi, uint256 prefixBytes, bytes calldata data)
        private
        pure
        returns (bytes32)
    {
        for (uint256 offset; ; offset += 64) {
            uint256 remaining = data.length - offset;
            bytes32 left = loadPadded(data, offset);
            bytes32 right = remaining > 32 ? loadPadded(data, offset + 32) : bytes32(0);
            if (remaining <= 64) {
                (lo, hi) = compress(lo, hi, left, right, prefixBytes + data.length, true);
                return digest(lo, hi);
            }
            (lo, hi) = compress(lo, hi, left, right, prefixBytes + offset + 64, false);
        }
    }

    function loadPadded(bytes calldata data, uint256 offset) private pure returns (bytes32 word) {
        uint256 remaining = data.length - offset;
        assembly ("memory-safe") {
            word := calldataload(add(data.offset, offset))
            if lt(remaining, 32) {
                let padding := mul(sub(32, remaining), 8)
                word := shl(padding, shr(padding, word))
            }
        }
    }

    function compress(uint256 h0, uint256 h1, bytes32 left, bytes32 right, uint256 count, bool finalBlock)
        private
        pure
        returns (uint256 out0, uint256 out1)
    {
        assembly ("memory-safe") {
            function rot(x, n) -> y {
                let mask := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                y := and(or(shr(n, x), shl(sub(32, n), x)), mask)
            }
            // Four independent 32-bit G operations, separated by 32 carry bits.
            function g(a, b, c, d, x, y) -> aa, bb, cc, dd {
                let mask := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
                aa := and(add(add(a, b), x), mask)
                dd := rot(xor(d, aa), 16)
                cc := and(add(c, dd), mask)
                bb := rot(xor(b, cc), 12)
                aa := and(add(add(aa, bb), y), mask)
                dd := rot(xor(dd, aa), 8)
                cc := and(add(cc, dd), mask)
                bb := rot(xor(bb, cc), 7)
            }
            function selectWords(ptr, indices) -> words {
                // Four nibbles, in the order of the four parallel lanes.
                let w0 := mload(add(ptr, and(shl(5, indices), 0x1e0)))
                let w1 := mload(add(ptr, and(shl(1, indices), 0x1e0)))
                let w2 := mload(add(ptr, and(shr(3, indices), 0x1e0)))
                let w3 := mload(add(ptr, and(shr(7, indices), 0x1e0)))
                words := or(or(w0, shl(64, w1)), or(shl(128, w2), shl(192, w3)))
            }
            function rotateLanes(x, n) -> y {
                y := or(shr(n, x), shl(sub(256, n), x))
            }
            function round(ptr, a, b, c, d, columnX, columnY, diagonalX, diagonalY) -> aa, bb, cc, dd {
                aa, bb, cc, dd := g(a, b, c, d, selectWords(ptr, columnX), selectWords(ptr, columnY))
                aa, bb, cc, dd := g(aa, rotateLanes(bb, 64), rotateLanes(cc, 128), rotateLanes(dd, 192),
                    selectWords(ptr, diagonalX), selectWords(ptr, diagonalY))
                bb := rotateLanes(bb, 192)
                cc := rotateLanes(cc, 128)
                dd := rotateLanes(dd, 64)
            }

            let words := mload(0x40)
            function loadMessage(ptr, blockWord) {
                // Reverse bytes independently in all eight 32-bit words.
                let bytesMask := 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff
                let halfMask := 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff
                let pairs := or(shl(8, and(blockWord, bytesMask)), and(shr(8, blockWord), bytesMask))
                let wordsLE := or(shl(16, and(pairs, halfMask)), and(shr(16, pairs), halfMask))
                mstore(ptr, shr(224, wordsLE))
                mstore(add(ptr, 32), and(shr(192, wordsLE), 0xffffffff))
                mstore(add(ptr, 64), and(shr(160, wordsLE), 0xffffffff))
                mstore(add(ptr, 96), and(shr(128, wordsLE), 0xffffffff))
                mstore(add(ptr, 128), and(shr(96, wordsLE), 0xffffffff))
                mstore(add(ptr, 160), and(shr(64, wordsLE), 0xffffffff))
                mstore(add(ptr, 192), and(shr(32, wordsLE), 0xffffffff))
                mstore(add(ptr, 224), and(wordsLE, 0xffffffff))
            }
            loadMessage(words, left)
            loadMessage(add(words, 256), right)

            let a := h0
            let b := h1
            let c := 0xa54ff53a000000003c6ef37200000000bb67ae85000000006a09e667
            let d := xor(0x5be0cd19000000001f83d9ab000000009b05688c00000000510e527f, count)
            if finalBlock { d := xor(d, shl(128, 0xffffffff)) }

            // RFC 7693 SIGMA, split into column/diagonal and even/odd lanes.
            a, b, c, d := round(words, a, b, c, d, 0x6420, 0x7531, 0xeca8, 0xfdb9)
            a, b, c, d := round(words, a, b, c, d, 0xd94e, 0x6f8a, 0x5b01, 0x372c)
            a, b, c, d := round(words, a, b, c, d, 0xf5cb, 0xd208, 0x973a, 0x416e)
            a, b, c, d := round(words, a, b, c, d, 0xbd37, 0xec19, 0xf452, 0x80a6)
            a, b, c, d := round(words, a, b, c, d, 0xa259, 0xf470, 0x36be, 0xd8c1)
            a, b, c, d := round(words, a, b, c, d, 0x8062, 0x3bac, 0x1f74, 0x9e5d)
            a, b, c, d := round(words, a, b, c, d, 0x4e1c, 0xadf5, 0x8960, 0xb237)
            a, b, c, d := round(words, a, b, c, d, 0x3c7d, 0x91eb, 0x28f5, 0xa640)
            a, b, c, d := round(words, a, b, c, d, 0x0be6, 0x839f, 0xa1dc, 0x5472)
            a, b, c, d := round(words, a, b, c, d, 0x178a, 0x5642, 0xd39f, 0x0ceb)
            out0 := xor(h0, xor(a, c))
            out1 := xor(h1, xor(b, d))
        }
    }

    function digest(uint256 lo, uint256 hi) private pure returns (bytes32 result) {
        assembly ("memory-safe") {
            function encodeRow(row) -> encoded {
                // The 32-bit words occupy the low halves of four 64-bit lanes.
                let bytesMask := 0x0000000000ff00ff0000000000ff00ff0000000000ff00ff0000000000ff00ff
                let halfMask := 0x000000000000ffff000000000000ffff000000000000ffff000000000000ffff
                let pairs := or(shl(8, and(row, bytesMask)), and(shr(8, row), bytesMask))
                let wordsBE := or(shl(16, and(pairs, halfMask)), and(shr(16, pairs), halfMask))
                encoded := or(
                    or(shl(96, and(wordsBE, 0xffffffff)), and(wordsBE, shl(64, 0xffffffff))),
                    or(shl(32, and(shr(128, wordsBE), 0xffffffff)), shr(192, wordsBE))
                )
            }
            result := or(shl(128, encodeRow(lo)), encodeRow(hi))
        }
    }
}
