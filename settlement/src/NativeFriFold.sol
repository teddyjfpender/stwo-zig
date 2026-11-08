// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

/// @notice Native OM31 FRI butterfly for one authenticated query subgroup.
/// @dev The caller owns query and opening authentication. foldCanonical
///      checks the supplied inverses against the canonical domain.
library NativeFriFold {
    error InvalidSubgroup();
    error NonCanonicalField();
    error InvalidInverseCoordinate();

    uint32 private constant P = 0x7fffffff;

    struct Point {
        uint256 x;
        uint256 y;
    }

    /// @param query A bit-reversed query position in the source layer.
    /// @param circleLayer True for the initial circle layer, false for line layers.
    function foldCanonical(
        uint32[8][] memory values,
        uint32[8] memory alpha,
        uint32[] calldata inverses,
        uint8 domainLog,
        uint32 query,
        bool circleLayer
    ) internal pure returns (uint32[8] memory) {
        uint256 length = values.length;
        uint256 maxLog = circleLayer ? 30 : 29;
        if (
            length < 2 || length > 16 || (length & (length - 1)) != 0 || inverses.length != length - 1
                || domainLog > maxLog || length > (uint256(1) << domainLog) || query >= (uint256(1) << domainLog)
        ) revert InvalidSubgroup();

        uint256 base = uint256(query) & ~(length - 1);
        uint256 initial = uint256(1) << (maxLog - domainLog);
        uint256 foldLog;
        for (uint256 width = length; width > 1; width >>= 1) ++foldLog;
        Point memory first = circlePoint(initial * (1 + 4 * reverseBits(base, domainLog)));
        Point memory step = circlePoint(uint256(1) << ((circleLayer ? 32 : 31) - foldLog));
        uint256 at;
        while (length > 1) {
            length >>= 1;
            --foldLog;
            Point memory point = first;
            for (uint256 i; i < length; ++i) {
                uint256 inverse = inverses[at + reverseBits(i, foldLog)];
                if (inverse >= P || mulmod(circleLayer ? point.y : point.x, inverse, P) != 1) {
                    revert InvalidInverseCoordinate();
                }
                point = circleMultiply(point, step);
            }
            at += length;
            // Circle-to-line projects the same half-coset. Subsequent
            // line folds double its generator exponents.
            if (circleLayer) circleLayer = false;
            else {
                first = circleMultiply(first, first);
                step = circleMultiply(step, step);
            }
        }
        return fold(values, alpha, inverses);
    }

    function reverseBits(uint256 index, uint256 bits) private pure returns (uint256 reversed) {
        for (uint256 i; i < bits; ++i) {
            reversed = (reversed << 1) | (index & 1);
            index >>= 1;
        }
    }

    function circlePoint(uint256 exponent) private pure returns (Point memory point) {
        uint256 x = 1;
        uint256 y;
        uint256 powerX = 2;
        uint256 powerY = 1_268_011_823;
        unchecked {
            while (exponent != 0) {
                if ((exponent & 1) != 0) {
                    (x, y) = (
                        addmod(mulmod(x, powerX, P), P - mulmod(y, powerY, P), P),
                        addmod(mulmod(x, powerY, P), mulmod(y, powerX, P), P)
                    );
                }
                exponent >>= 1;
                if (exponent == 0) break;
                (powerX, powerY) = (
                    addmod(mulmod(powerX, powerX, P), P - mulmod(powerY, powerY, P), P),
                    mulmod(2 * powerX, powerY, P)
                );
            }
        }
        return Point(x, y);
    }

    function circleMultiply(Point memory a, Point memory b) private pure returns (Point memory) {
        return Point(
            addmod(mulmod(a.x, b.x, P), P - mulmod(a.y, b.y, P), P),
            addmod(mulmod(a.x, b.y, P), mulmod(a.y, b.x, P), P)
        );
    }

    /// @dev Coefficients are in the native basis [1,i,u,iu,v,iv,uv,iuv].
    /// Inverse coordinates are ordered by fold round, then by butterfly index.
    function fold(uint32[8][] memory values, uint32[8] memory alpha, uint32[] calldata inverses)
        internal pure returns (uint32[8] memory)
    {
        uint256 length = values.length;
        if (length < 2 || length > 16 || (length & (length - 1)) != 0 || inverses.length != length - 1) {
            revert InvalidSubgroup();
        }
        requireCanonical(alpha);
        for (uint256 i; i < length; ++i) requireCanonical(values[i]);
        uint256 at;
        while (length > 1) {
            length >>= 1;
            for (uint256 i; i < length; ++i) {
                uint32 inverse = inverses[at++];
                if (inverse == 0 || inverse >= P) revert NonCanonicalField();
                values[i] = butterfly(values[2 * i], values[2 * i + 1], alpha, inverse);
            }
            if (length > 1) alpha = multiply(alpha, alpha);
        }
        return values[0];
    }

    function butterfly(uint32[8] memory left, uint32[8] memory right, uint32[8] memory alpha, uint32 inverse)
        private pure returns (uint32[8] memory result)
    {
        // Reuse the result allocation for the odd coefficients. The
        // multiplier reads it before the final butterfly sum overwrites it.
        assembly ("memory-safe") {
            let inverseWord := and(inverse, 0xffffffff)
            for { let offset := 0 } lt(offset, 256) { offset := add(offset, 32) } {
                let lhs := and(mload(add(left, offset)), 0xffffffff)
                let rhs := and(mload(add(right, offset)), 0xffffffff)
                mstore(add(result, offset), mulmod(sub(add(lhs, 0x7fffffff), rhs), inverseWord, 0x7fffffff))
            }
        }
        uint32[8] memory scaled = multiply(alpha, result);
        assembly ("memory-safe") {
            for { let offset := 0 } lt(offset, 256) { offset := add(offset, 32) } {
                let lhs := and(mload(add(left, offset)), 0xffffffff)
                let rhs := and(mload(add(right, offset)), 0xffffffff)
                let even := add(lhs, rhs)
                mstore(add(result, offset), mod(add(even, mload(add(scaled, offset))), 0x7fffffff))
            }
        }
    }

    // Multiply in the native quadratic tower i² = -1, u² = 2+i, v² = u.
    // Karatsuba at each level uses 27 base products. We reduce only the
    // final coefficients. All signed intermediates are below 2^80 in
    // magnitude: the inputs are M31 residues and each level only adds
    // bounded multiples of products or doubles the inputs to a subproduct.
    function multiply(uint32[8] memory a, uint32[8] memory b) internal pure returns (uint32[8] memory result) {
        assembly ("memory-safe") {
            function complexMul(ar, ai, br, bi) -> re, im {
                let rr := mul(ar, br)
                let ii := mul(ai, bi)
                re := sub(rr, ii)
                im := sub(sub(mul(add(ar, ai), add(br, bi)), rr), ii)
            }

            // QM31 product of two four-word tuples [1,i,u,iu].
            function quarticMul(x, y, out) {
                let xr := mload(x)
                let xi := mload(add(x, 32))
                let yr := mload(y)
                let yi := mload(add(y, 32))
                let xu := mload(add(x, 64))
                let xiu := mload(add(x, 96))
                let yu := mload(add(y, 64))
                let yiu := mload(add(y, 96))
                let lowR, lowI := complexMul(xr, xi, yr, yi)
                let highR, highI := complexMul(xu, xiu, yu, yiu)
                let sumR, sumI := complexMul(add(xr, xu), add(xi, xiu), add(yr, yu), add(yi, yiu))
                // Multiply the high product by the nonresidue 2+i.
                mstore(out, add(lowR, sub(add(highR, highR), highI)))
                mstore(add(out, 32), add(lowI, add(highR, add(highI, highI))))
                mstore(add(out, 64), sub(sub(sumR, lowR), highR))
                mstore(add(out, 96), sub(sub(sumI, lowI), highI))
            }

            function reduce(value) -> residue {
                residue := smod(value, 0x7fffffff)
                if slt(residue, 0) { residue := add(residue, 0x7fffffff) }
            }

            // Scratch space lives beyond the free-memory pointer and does
            // not escape. The named result already owns eight memory words.
            let low := mload(0x40)
            let high := add(low, 128)
            let sum := add(high, 128)
            let xSum := add(sum, 128)
            let ySum := add(xSum, 128)
            quarticMul(a, b, low)
            quarticMul(add(a, 128), add(b, 128), high)
            for { let offset := 0 } lt(offset, 128) { offset := add(offset, 32) } {
                mstore(add(xSum, offset), add(mload(add(a, offset)), mload(add(add(a, 128), offset))))
                mstore(add(ySum, offset), add(mload(add(b, offset)), mload(add(add(b, 128), offset))))
            }
            quarticMul(xSum, ySum, sum)
            // Multiplication by u maps [r,i,s,t] to [2s-t,s+2t,r,i].
            let s := mload(add(high, 64))
            let t := mload(add(high, 96))
            mstore(result, reduce(add(mload(low), sub(add(s, s), t))))
            mstore(add(result, 32), reduce(add(mload(add(low, 32)), add(s, add(t, t)))))
            mstore(add(result, 64), reduce(add(mload(add(low, 64)), mload(high))))
            mstore(add(result, 96), reduce(add(mload(add(low, 96)), mload(add(high, 32)))))
            for { let offset := 0 } lt(offset, 128) { offset := add(offset, 32) } {
                let cross := sub(sub(mload(add(sum, offset)), mload(add(low, offset))), mload(add(high, offset)))
                mstore(add(add(result, 128), offset), reduce(cross))
            }
        }
    }

    function requireCanonical(uint32[8] memory value) private pure {
        for (uint256 i; i < 8; ++i) {
            if (value[i] >= P) revert NonCanonicalField();
        }
    }
}
