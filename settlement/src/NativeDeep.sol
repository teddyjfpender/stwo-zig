// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeFriFold} from "./NativeFriFold.sol";
import {NativePcsTranscript} from "./NativePcsTranscript.sol";

/// @notice Computes native OM31 DEEP quotient answers on the lifted circle.
/// @dev The surrounding verifier owns the column layout and sample points and
/// derives alpha from the transcript that absorbed these same samples. Rows
/// are M31 values in the original tree and column order. The opening checker
/// restores that order after authenticating each tree's sorted leaves.
library NativeDeep {
    error InvalidDeepShape();
    error DegenerateDeepLine();
    error ZeroDeepDenominator();

    uint256 private constant P = 0x7fffffff;
    uint256 private constant MAX_COLUMNS = 8192;
    uint256 private constant MAX_SAMPLES = 16384;
    uint256 private constant MAX_BATCHES = 256;

    struct Point {
        uint32[8] x;
        uint32[8] y;
    }

    struct Column {
        // Native column log, including blowup.
        uint8 logSize;
        uint16[] samplePoints;
    }

    struct Batch {
        uint32[8] c;
        uint32[8] a;
        uint32[8] b;
        uint32[8] pix;
        uint32[8] piy;
        uint32[8] determinant;
    }

    struct Plan {
        uint8 domainLog;
        uint16 columnCount;
        uint16 batchCount;
        bytes columnLogs;
        Batch[] batches;
        uint256[] powers;
        uint32[] locations;
    }

    struct RowWorkspace {
        uint32[] base;
        uint32[8][] weightedRows;
    }

    function rowWorkspace(Plan memory plan) internal pure returns (RowWorkspace memory) {
        return RowWorkspace(new uint32[](plan.columnCount), new uint32[8][](plan.batchCount));
    }

    struct Preparation {
        Point[] points;
        uint16[] batchForKey;
        uint32[8][] weightedSamples;
        uint32[8][] slopes;
        uint32[8] power;
        uint32[8] alpha;
        uint32[8] sample;
        uint32[8] difference;
        uint32[8] product;
        uint256 nextTerm;
    }

    /// @param samples One 32-byte little-endian OM31 value per column sample,
    /// in the same tree, column and within-column order as the PCS transcript.
    function prepare(
        uint8 domainLog,
        Column[] memory columns,
        Point[] memory points,
        uint32[8] memory alpha,
        bytes calldata samples
    ) internal pure returns (Plan memory plan) {
        if (
            domainLog == 0 || domainLog > 30 || columns.length == 0 || columns.length > MAX_COLUMNS
                || points.length == 0 || points.length > MAX_BATCHES || samples.length == 0
                || samples.length % 32 != 0 || samples.length / 32 > MAX_SAMPLES
        ) revert InvalidDeepShape();
        canonical(alpha);
        for (uint256 i; i < points.length; ++i) {
            canonical(points[i].x);
            canonical(points[i].y);
        }

        uint256 termCount;
        uint256 sampleCount;
        for (uint256 i; i < columns.length; ++i) {
            if (columns[i].logSize > 30) revert InvalidDeepShape();
            uint256 length = columns[i].samplePoints.length;
            sampleCount += length;
            termCount += length == 2 ? 3 : length;
        }
        if (sampleCount != samples.length / 32) revert InvalidDeepShape();

        plan.domainLog = domainLog;
        plan.columnCount = uint16(columns.length);
        plan.columnLogs = new bytes(columns.length);
        uint256 batchCapacity = termCount < MAX_BATCHES ? termCount : MAX_BATCHES;
        plan.batches = new Batch[](batchCapacity);
        plan.powers = new uint256[](termCount);
        plan.locations = new uint32[](termCount);
        Preparation memory scratch;
        scratch.points = points;
        scratch.batchForKey = new uint16[](points.length * 32);
        scratch.weightedSamples = new uint32[8][](batchCapacity);
        scratch.slopes = new uint32[8][](batchCapacity);
        scratch.power[0] = 1;
        scratch.alpha = alpha;

        uint256 at;
        for (uint256 i; i < columns.length; ++i) {
            Column memory column = columns[i];
            plan.columnLogs[i] = bytes1(column.logSize);
            // A two-sample column prepends a copy of its second sample at
            // that point rotated by the lifted coset step raised to 2^logSize.
            if (column.samplePoints.length == 2) {
                uint256 tag = uint256(column.logSize) + 1;
                // Logs at or above the lifting size give the identity step.
                if (column.logSize >= domainLog) tag = 0;
                readField(samples, at + 32, scratch.sample);
                append(plan, scratch, i, column.samplePoints[1], tag);
            }
            for (uint256 j; j < column.samplePoints.length; ++j) {
                readField(samples, at, scratch.sample);
                append(plan, scratch, i, column.samplePoints[j], 0);
                at += 32;
            }
        }
        // For each point, the native line intercept is
        // sum(alpha^k * (sample * c - (conj(sample)-sample) * point.y)).
        for (uint256 i; i < plan.batchCount; ++i) {
            Batch memory batch = plan.batches[i];
            batch.a = scratch.slopes[i];
            batch.b = sub(
                NativeFriFold.multiply(batch.c, scratch.weightedSamples[i]), NativeFriFold.multiply(batch.a, batch.b)
            );
        }
    }

    function append(
        Plan memory plan,
        Preparation memory scratch,
        uint256 column,
        uint256 pointIndex,
        uint256 tag
    ) private pure {
        if (pointIndex >= scratch.points.length) revert InvalidDeepShape();
        uint256 key = pointIndex * 32 + tag;
        uint256 index = scratch.batchForKey[key];
        if (index == 0) {
            index = plan.batchCount++;
            if (index == plan.batches.length) revert InvalidDeepShape();
            scratch.batchForKey[key] = uint16(index + 1);
            Point memory point = scratch.points[pointIndex];
            if (tag != 0) {
                // Generator has order 2^31; the lifting step is 2^(31-log).
                point = rotate(point, NativeFriFold.circlePoint(uint256(1) << (30 + tag - plan.domainLog)));
            }
            Batch memory batch = plan.batches[index];
            batch.c = conjugateDifference(point.y);
            if (pack(batch.c) == 0) revert DegenerateDeepLine();
            batch.pix = half(point.x, 4);
            batch.piy = half(point.y, 4);
            batch.determinant = sub(
                NativeFriFold.multiply(half(point.x, 0), batch.piy),
                NativeFriFold.multiply(half(point.y, 0), batch.pix)
            );
            // Kept only during preparation to accumulate the intercept.
            batch.b = point.y;
        } else {
            --index;
        }
        plan.locations[scratch.nextTerm] = uint32((column << 16) | index);
        plan.powers[scratch.nextTerm++] = pack(scratch.power);
        NativeFriFold.multiplyInto(scratch.power, scratch.sample, scratch.product);
        addInto(scratch.weightedSamples[index], scratch.product);
        setConjugateDifference(scratch.sample, scratch.difference);
        NativeFriFold.multiplyInto(scratch.power, scratch.difference, scratch.product);
        addInto(scratch.slopes[index], scratch.product);
        NativeFriFold.multiplyInto(scratch.power, scratch.alpha, scratch.power);
    }

    /// @param query Canonical bit-reversed position in the lifting domain.
    /// @param row Exactly one authenticated base value for each layout column.
    function evaluate(Plan memory plan, uint32 query, bytes memory row, RowWorkspace memory workspace)
        internal pure returns (uint32[8] memory result)
    {
        if (query >= (uint256(1) << plan.domainLog) || row.length != uint256(plan.columnCount) * 4) {
            revert InvalidDeepShape();
        }
        uint256 reverse = NativeFriFold.reverseBits(query & ~uint32(1), plan.domainLog);
        NativeFriFold.Point memory domain = NativeFriFold.circlePoint((1 + 4 * reverse) << (30 - plan.domainLog));
        if ((query & 1) != 0) domain.y = P - domain.y;

        uint32[] memory base = workspace.base;
        for (uint256 i; i < base.length; ++i) {
            bytes32 chunk;
            assembly ("memory-safe") {
                chunk := mload(add(add(row, 32), and(shl(2, i), not(31))))
            }
            uint32 word = NativePcsTranscript.wordLE(chunk, i & 7);
            if (word >= P) revert NativePcsTranscript.NonCanonicalField();
            base[i] = word;
        }
        uint32[8][] memory weightedRows = workspace.weightedRows;
        for (uint256 i; i < weightedRows.length; ++i) {
            uint32[8] memory sum = weightedRows[i];
            assembly ("memory-safe") {
                for { let at := sum } lt(at, add(sum, 256)) { at := add(at, 32) } {
                    mstore(at, 0)
                }
            }
        }
        for (uint256 i; i < plan.locations.length; ++i) {
            uint256 location = plan.locations[i];
            uint256 value = base[location >> 16];
            uint32[8] memory sum = weightedRows[location & 0xffff];
            uint256 power = plan.powers[i];
            assembly ("memory-safe") {
                for { let at := sum } lt(at, add(sum, 256)) { at := add(at, 32) } {
                    let scaled := mulmod(value, and(power, 0xffffffff), 0x7fffffff)
                    mstore(at, addmod(mload(at), scaled, 0x7fffffff))
                    power := shr(32, power)
                }
            }
        }
        for (uint256 i; i < plan.batchCount; ++i) {
            Batch memory batch = plan.batches[i];
            uint32[8] memory denominator = sub(
                add(batch.determinant, scale(batch.pix, domain.y)), scale(batch.piy, domain.x)
            );
            uint32[8] memory numerator = sub(
                NativeFriFold.multiply(batch.c, weightedRows[i]), add(scale(batch.a, domain.y), batch.b)
            );
            result = add(result, NativeFriFold.multiply(numerator, invertQuartic(denominator)));
        }
    }

    function invertQuartic(uint32[8] memory value) private pure returns (uint32[8] memory) {
        // a+bu -> (a-bu) / (a² - (2+i)b²). The norm is in CM31,
        // whose inverse uses a single Fermat inverse in M31.
        uint32[8] memory conjugate = half(value, 0);
        conjugate[2] = neg(conjugate[2]);
        conjugate[3] = neg(conjugate[3]);
        uint32[8] memory norm = NativeFriFold.multiply(value, conjugate);
        if (pack(value) == 0) revert ZeroDeepDenominator();
        assembly ("memory-safe") {
            let p := 0x7fffffff
            let re := mload(norm)
            let im := mload(add(norm, 32))
            let baseNorm := addmod(mulmod(re, re, p), mulmod(im, im, p), p)
            // p - 2 has 29 leading one bits, then a zero, then one.
            let inverse := baseNorm
            for { let i := 0 } lt(i, 28) { i := add(i, 1) } {
                inverse := mulmod(mulmod(inverse, inverse, p), baseNorm, p)
            }
            inverse := mulmod(inverse, inverse, p)
            inverse := mulmod(mulmod(inverse, inverse, p), baseNorm, p)
            mstore(norm, mulmod(re, inverse, p))
            mstore(add(norm, 32), mulmod(sub(p, im), inverse, p))
        }
        return NativeFriFold.multiply(conjugate, norm);
    }

    function rotate(Point memory point, NativeFriFold.Point memory delta) private pure returns (Point memory) {
        return Point(
            sub(scale(point.x, delta.x), scale(point.y, delta.y)),
            add(scale(point.x, delta.y), scale(point.y, delta.x))
        );
    }

    function half(uint32[8] memory value, uint256 offset) private pure returns (uint32[8] memory result) {
        for (uint256 i; i < 4; ++i) result[i] = value[offset + i];
    }

    function conjugateDifference(uint32[8] memory value) private pure returns (uint32[8] memory result) {
        setConjugateDifference(value, result);
    }

    function setConjugateDifference(uint32[8] memory value, uint32[8] memory result) private pure {
        for (uint256 i = 4; i < 8; ++i) result[i] = neg(uint32(addmod(value[i], value[i], P)));
    }

    function readField(bytes calldata data, uint256 offset, uint32[8] memory field) private pure {
        bytes32 word = bytes32(data[offset:offset + 32]);
        for (uint256 i; i < 8; ++i) {
            uint32 value = NativePcsTranscript.wordLE(word, i);
            if (value >= P) revert NativePcsTranscript.NonCanonicalField();
            field[i] = value;
        }
    }

    function canonical(uint32[8] memory value) private pure {
        for (uint256 i; i < 8; ++i) {
            if (value[i] >= P) revert NativePcsTranscript.NonCanonicalField();
        }
    }

    function pack(uint32[8] memory value) private pure returns (uint256 result) {
        for (uint256 i; i < 8; ++i) result |= uint256(value[i]) << (i * 32);
    }

    function neg(uint32 value) private pure returns (uint32) {
        return value == 0 ? 0 : uint32(P - value);
    }

    function addInto(uint32[8] memory accumulator, uint32[8] memory value) private pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, 256) { i := add(i, 32) } {
                let at := add(accumulator, i)
                mstore(at, addmod(mload(at), mload(add(value, i)), 0x7fffffff))
            }
        }
    }

    function add(uint32[8] memory a, uint32[8] memory b) private pure returns (uint32[8] memory result) {
        for (uint256 i; i < 8; ++i) result[i] = uint32(addmod(a[i], b[i], P));
    }

    function sub(uint32[8] memory a, uint32[8] memory b) private pure returns (uint32[8] memory result) {
        for (uint256 i; i < 8; ++i) result[i] = uint32(addmod(a[i], P - b[i], P));
    }

    function scale(uint32[8] memory a, uint256 scalar) private pure returns (uint32[8] memory result) {
        for (uint256 i; i < 8; ++i) result[i] = uint32(mulmod(a[i], scalar, P));
    }
}
