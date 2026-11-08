// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {KonaTransitionStatement} from "../src/KonaTransitionStatement.sol";

contract KonaStatementHarness {
    function outputs(
        bytes32 expectedDigest,
        KonaTransitionStatement.Scope calldata scope,
        KonaTransitionStatement.Witness calldata witness
    ) external pure returns (bytes memory, bytes memory) {
        return KonaTransitionStatement.outputs(expectedDigest, scope, witness);
    }
}
