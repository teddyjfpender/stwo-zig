// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeAirProgram} from "../src/NativeAirProgram.sol";
import {NativeOods} from "../src/NativeOods.sol";

contract AirProgramHarness {
    bytes32 private immutable programHash;
    uint8 private immutable maskLog;

    constructor(bytes32 authority, uint8 maskSize) {
        programHash = authority;
        maskLog = maskSize;
    }

    function quotient(
        bytes calldata code,
        bytes calldata inputs,
        bytes calldata parameters,
        NativeOods.Point calldata point,
        uint32[8] calldata alpha,
        bytes32 inverseWitness
    ) external view returns (uint32[8] memory) {
        return NativeAirProgram.quotient(programHash, code, inputs, parameters, point, maskLog, alpha, inverseWitness);
    }
}
