// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import {NativeAirProgram} from "../src/NativeAirProgram.sol";
import {NativeOods} from "../src/NativeOods.sol";

/// Test-only caller-supplied code authority; production receivers must pin it.
contract AirProgramDynamicHarness {
    function evaluate(
        bytes32 authority,
        bytes calldata code,
        bytes calldata inputs,
        bytes calldata parameters,
        uint32[8] calldata alpha
    ) external pure returns (uint32[8] memory) {
        NativeOods.Point memory point;
        point.x[0] = 1;
        return
            NativeAirProgram.quotient(authority, code, inputs, parameters, point, 1, alpha, bytes32(uint256(1) << 248));
    }
}
