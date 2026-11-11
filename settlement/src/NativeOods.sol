// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {Blake2sLifted} from "./Blake2sLifted.sol";
import {NativeFriFold} from "./NativeFriFold.sol";
import {NativePcsTranscript} from "./NativePcsTranscript.sol";

/// @notice Checks the native split composition at the transcript's OODS point.
/// @dev A complete verifier must reconstruct the worker transcript up to the
///      composition draw, supply its own sample layout and evaluator, and
///      authenticate these same samples through DEEP/FRI.
library NativeOods {
    error InvalidSampleShape();
    error InvalidPointInverse();
    error CompositionMismatch();

    uint256 private constant P = 0x7fffffff;
    uint256 private constant FIELD_BYTES = 32;
    uint256 private constant DEGREE = 8;

    struct Point {
        uint32[8] x;
        uint32[8] y;
    }

    struct Shape {
        uint32 sampleCount;
        uint8 maskLog;
        uint8 splitDepth;
    }

    function check(
        bytes32 preComposition,
        bytes32 compositionRoot,
        Shape memory shape,
        bytes calldata samples,
        bytes32 pointInverse,
        function(Point memory, uint32[8] memory, bytes calldata) internal pure returns (uint32[8] memory) evaluateAir
    ) internal pure returns (bytes32 pcsPrefix) {
        if (shape.maskLog == 0 || shape.maskLog > 30 || shape.splitDepth == 0 || shape.splitDepth > 8
            || samples.length != uint256(shape.sampleCount) * FIELD_BYTES) revert InvalidSampleShape();
        uint256 chunkCount = uint256(1) << shape.splitDepth;
        uint256 compositionBytes = chunkCount * DEGREE * FIELD_BYTES;
        if (samples.length < compositionBytes) revert InvalidSampleShape();
        NativePcsTranscript.requireCanonical(samples);

        uint32[8] memory alpha = NativePcsTranscript.secureDraw(preComposition);
        pcsPrefix = Blake2sLifted.shortDigest(preComposition, compositionRoot, 64);
        Point memory point = derivePoint(pcsPrefix, pointInverse);
        uint256 split = samples.length - compositionBytes;
        uint32[8] memory expected = evaluateAir(point, alpha, samples[:split]);
        uint32[8] memory committed = composition(point, shape, samples[split:], chunkCount);
        if (!equal(expected, committed)) revert CompositionMismatch();
    }

    function derivePoint(bytes32 pcsPrefix, bytes32 pointInverse) internal pure returns (Point memory point) {
        uint32[8] memory t = NativePcsTranscript.secureDraw(pcsPrefix);
        uint32[8] memory tSquared = NativeFriFold.multiply(t, t);
        uint32[8] memory inverse = readField(pointInverse);
        uint32[8] memory one;
        one[0] = 1;
        if (!equal(NativeFriFold.multiply(add(one, tSquared), inverse), one)) revert InvalidPointInverse();
        point.x = NativeFriFold.multiply(sub(one, tSquared), inverse);
        point.y = NativeFriFold.multiply(add(t, t), inverse);
    }

    function composition(Point memory point, Shape memory shape, bytes calldata tail, uint256 chunkCount)
        private pure returns (uint32[8] memory)
    {
        uint32[8][] memory chunks = new uint32[8][](chunkCount);
        for (uint256 i; i < chunkCount; ++i) {
            chunks[i] = readField(bytes32(tail[i * DEGREE * FIELD_BYTES:]));
            for (uint256 j = 1; j < DEGREE; ++j) {
                uint32[8] memory basis;
                basis[j] = 1;
                uint32[8] memory coordinate = readField(bytes32(tail[(i * DEGREE + j) * FIELD_BYTES:]));
                chunks[i] = add(chunks[i], NativeFriFold.multiply(basis, coordinate));
            }
        }
        // x after n doublings is the n-th Chebyshev iterate. The native
        // chunk order combines adjacent pairs first, starting at maskLog-1.
        uint32[8] memory factor = point.x;
        for (uint256 i = 1; i < shape.maskLog; ++i) factor = doubleX(factor);
        for (uint256 active = chunkCount; active > 1;) {
            active >>= 1;
            for (uint256 i; i < active; ++i) {
                chunks[i] = add(chunks[2 * i], NativeFriFold.multiply(factor, chunks[2 * i + 1]));
            }
            if (active > 1) factor = doubleX(factor);
        }
        return chunks[0];
    }

    function doubleX(uint32[8] memory x) internal pure returns (uint32[8] memory) {
        uint32[8] memory square = NativeFriFold.multiply(x, x);
        uint32[8] memory one;
        one[0] = 1;
        return sub(add(square, square), one);
    }

    function readField(bytes32 value) internal pure returns (uint32[8] memory field) {
        for (uint256 i; i < DEGREE; ++i) {
            uint32 word = NativePcsTranscript.wordLE(value, i);
            if (word >= P) revert NativePcsTranscript.NonCanonicalField();
            field[i] = word;
        }
    }

    function add(uint32[8] memory a, uint32[8] memory b) internal pure returns (uint32[8] memory result) {
        for (uint256 i; i < DEGREE; ++i) result[i] = uint32(addmod(a[i], b[i], P));
    }

    function sub(uint32[8] memory a, uint32[8] memory b) internal pure returns (uint32[8] memory result) {
        for (uint256 i; i < DEGREE; ++i) result[i] = uint32(addmod(a[i], P - b[i], P));
    }

    function equal(uint32[8] memory a, uint32[8] memory b) internal pure returns (bool) {
        for (uint256 i; i < DEGREE; ++i) if (a[i] != b[i]) return false;
        return true;
    }
}
