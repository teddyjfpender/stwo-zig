// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeFriFold} from "./NativeFriFold.sol";
import {NativeOods} from "./NativeOods.sol";
import {NativePcsTranscript} from "./NativePcsTranscript.sol";

/// @notice Evaluate an authorized RV64 composition component at OODS.
/// @dev The receiver selects the code hash and owns the input routing and
///      parameter derivation. Code encodes the native secure polynomial DAG's
///      ordered residuals. Input and parameter fields use native OM31 bytes.
library NativeAirProgram {
    error ProgramIdentityMismatch();
    error InvalidProgram();
    error InvalidVanishingInverse();

    bytes4 private constant MAGIC = "AIR1";
    uint256 private constant HEADER = 24;
    uint256 private constant NODE = 13;
    uint256 private constant FIELD = 32;

    struct Layout {
        uint256 nodes;
        uint256 roots;
        uint256 constants;
        uint256 constantOffset;
        uint256 rootOffset;
    }

    function quotient(
        bytes32 programHash,
        bytes calldata code,
        bytes calldata inputs,
        bytes calldata parameters,
        NativeOods.Point memory point,
        uint8 maskLog,
        uint32[8] memory alpha,
        bytes32 inverseWitness
    ) internal pure returns (uint32[8] memory) {
        uint32[8] memory inverse = vanishingInverse(point, maskLog, inverseWitness);
        return NativeFriFold.multiply(evaluate(programHash, code, inputs, parameters, alpha), inverse);
    }

    function evaluate(
        bytes32 programHash,
        bytes calldata code,
        bytes calldata inputs,
        bytes calldata parameters,
        uint32[8] memory alpha
    ) private pure returns (uint32[8] memory result) {
        if (keccak256(code) != programHash) revert ProgramIdentityMismatch();
        Layout memory layout = decodeLayout(code, inputs, parameters);
        uint32[8][] memory values = new uint32[8][](layout.nodes);
        for (uint256 i; i < layout.nodes; ++i) {
            uint256 offset = HEADER + i * NODE;
            uint8 op = uint8(code[offset]);
            uint256 lhs = readWord(code, offset + 1);
            uint256 rhs = readWord(code, offset + 5);
            uint256 index = readWord(code, offset + 9);
            if (op < 3) {
                values[i] = leaf(op, index, layout, code, inputs, parameters);
            } else {
                values[i] = operation(op, i, lhs, rhs, values);
            }
        }
        for (uint256 i; i < layout.roots; ++i) {
            uint256 index = readWord(code, layout.rootOffset + i * 4);
            if (index >= layout.nodes) revert InvalidProgram();
            result = NativeOods.add(NativeFriFold.multiply(result, alpha), values[index]);
        }
    }

    function decodeLayout(bytes calldata code, bytes calldata inputs, bytes calldata parameters)
        private pure returns (Layout memory layout)
    {
        if (code.length < HEADER || bytes4(code) != MAGIC) revert InvalidProgram();
        layout.nodes = readWord(code, 4);
        layout.roots = readWord(code, 8);
        layout.constants = readWord(code, 12);
        layout.constantOffset = HEADER + layout.nodes * NODE;
        layout.rootOffset = layout.constantOffset + layout.constants * FIELD;
        if (layout.nodes == 0 || layout.nodes > 1 << 22 || layout.roots == 0 || layout.roots > 1 << 16
            || layout.constants > 1 << 16 || layout.rootOffset + layout.roots * 4 != code.length
            || inputs.length != readWord(code, 16) * FIELD || parameters.length != readWord(code, 20) * FIELD) {
            revert InvalidProgram();
        }
        NativePcsTranscript.requireCanonical(inputs);
        NativePcsTranscript.requireCanonical(parameters);
        NativePcsTranscript.requireCanonical(code[layout.constantOffset:layout.rootOffset]);
    }

    function leaf(
        uint8 op, uint256 index, Layout memory layout, bytes calldata code, bytes calldata inputs, bytes calldata params
    ) private pure returns (uint32[8] memory) {
        if (op == 0) {
            if (index >= layout.constants) revert InvalidProgram();
            return NativeOods.readField(bytes32(code[layout.constantOffset + index * FIELD:]));
        }
        bytes calldata fields = op == 1 ? inputs : params;
        if (index >= fields.length / FIELD) revert InvalidProgram();
        return NativeOods.readField(bytes32(fields[index * FIELD:]));
    }

    function operation(uint8 op, uint256 node, uint256 lhs, uint256 rhs, uint32[8][] memory values)
        private pure returns (uint32[8] memory)
    {
        if (lhs >= node || (op != 6 && rhs >= node)) revert InvalidProgram();
        if (op == 3) return NativeOods.add(values[lhs], values[rhs]);
        if (op == 4) return NativeOods.sub(values[lhs], values[rhs]);
        if (op == 5) return NativeFriFold.multiply(values[lhs], values[rhs]);
        if (op == 6) {
            uint32[8] memory zero;
            return NativeOods.sub(zero, values[lhs]);
        }
        revert InvalidProgram();
    }

    function vanishingInverse(NativeOods.Point memory point, uint8 maskLog, bytes32 witness)
        private pure returns (uint32[8] memory inverse)
    {
        if (maskLog == 0 || maskLog > 30) revert InvalidProgram();
        // CanonicCoset's initial point equals its half-step. The local
        // domain projection and vanishing iterates total maskLog - 1.
        uint32[8] memory vanishing = point.x;
        for (uint256 i = 1; i < maskLog; ++i) vanishing = NativeOods.doubleX(vanishing);
        inverse = NativeOods.readField(witness);
        uint32[8] memory one;
        one[0] = 1;
        if (!NativeOods.equal(NativeFriFold.multiply(vanishing, inverse), one)) revert InvalidVanishingInverse();
    }

    function readWord(bytes calldata data, uint256 offset) private pure returns (uint256) {
        uint32 word;
        assembly ("memory-safe") { word := shr(224, calldataload(add(data.offset, offset))) }
        return NativePcsTranscript.reverse32(word);
    }
}
