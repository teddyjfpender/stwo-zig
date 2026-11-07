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
        point = Point(1, 0);
        Point memory power = Point(2, 1_268_011_823);
        while (exponent != 0) {
            if ((exponent & 1) != 0) point = circleMultiply(point, power);
            power = circleMultiply(power, power);
            exponent >>= 1;
        }
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
        uint32[8] memory odd;
        for (uint256 i; i < 8; ++i) {
            odd[i] = uint32(((uint256(left[i]) + P - right[i]) * inverse) % P);
        }
        uint32[8] memory scaled = multiply(alpha, odd);
        for (uint256 i; i < 8; ++i) result[i] = uint32((uint256(left[i]) + right[i] + scaled[i]) % P);
    }

    // View the tower as four CM31 coefficients in v with v^4 = 2+i.
    // Accumulate signed products before reduction. Even the largest lane
    // holds only a small multiple of P^2, well within int256.
    function multiply(uint32[8] memory a, uint32[8] memory b) private pure returns (uint32[8] memory result) {
        int256[8] memory accum;
        for (uint256 i; i < 4; ++i) {
            uint256 ai = coefficientOffset(i);
            for (uint256 j; j < 4; ++j) {
                uint256 bi = coefficientOffset(j);
                int256 re = int256(uint256(a[ai]) * b[bi]) - int256(uint256(a[ai + 1]) * b[bi + 1]);
                int256 im = int256(uint256(a[ai]) * b[bi + 1]) + int256(uint256(a[ai + 1]) * b[bi]);
                uint256 degree = i + j;
                uint256 k = coefficientOffset(degree & 3);
                if (degree >= 4) {
                    accum[k] += 2 * re - im;
                    accum[k + 1] += re + 2 * im;
                } else {
                    accum[k] += re;
                    accum[k + 1] += im;
                }
            }
        }
        for (uint256 i; i < 8; ++i) {
            int256 residue = accum[i] % int256(uint256(P));
            result[i] = uint32(uint256(residue < 0 ? residue + int256(uint256(P)) : residue));
        }
    }

    function coefficientOffset(uint256 degree) private pure returns (uint256) {
        return ((degree & 1) << 2) | (degree & 2);
    }

    function requireCanonical(uint32[8] memory value) private pure {
        for (uint256 i; i < 8; ++i) {
            if (value[i] >= P) revert NonCanonicalField();
        }
    }
}
