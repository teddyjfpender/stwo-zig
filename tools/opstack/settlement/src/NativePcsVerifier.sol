// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {NativeDeep} from "./NativeDeep.sol";
import {NativeDeepOpening} from "./NativeDeepOpening.sol";
import {NativeFriVerifier} from "./NativeFriVerifier.sol";

/// @dev Stateless FRI layer arithmetic for the PCS verifier. The PCS
/// constructor deploys this implementation and pins its address.
contract NativePcsFriVerifier is NativeFriVerifier {
    error UnauthorizedPcsCaller();

    address private immutable pcs = msg.sender;

    function verifyComputed(
        FriState calldata state, bytes32[] calldata deepValues, LayerOpening[] calldata layers
    ) external view returns (bool) {
        if (msg.sender != pcs) revert UnauthorizedPcsCaller();
        return verifyFriLayers(state, deepValues, layers);
    }
}

/// @notice Authenticates the PCS transcript, trace openings, DEEP answers and FRI.
/// @dev A surrounding verifier must reconstruct the OODS prefix, check the
/// AIR at that point and supply the commitment roots and exact sample layout.
/// The samples here must be the same bytes used by the OODS check.
abstract contract NativePcsVerifier is NativeDeepOpening, NativeFriVerifier {
    // Keep DEEP and FRI arithmetic in distinct runtimes. The call below
    // supplies only the transcript state and quotients this verifier computed.
    NativePcsFriVerifier private immutable friVerifier = new NativePcsFriVerifier();

    struct DeepLayout {
        uint8 domainLog;
        uint32 sampleCount;
        NativeDeep.Column[] columns;
        NativeDeep.Point[] points;
        TraceTree[] trees;
    }

    struct PcsOpening {
        bytes32[] friRoots;
        bytes lastCoefficient;
        uint64 nonce;
        TraceOpening[] traces;
        LayerOpening[] layers;
    }

    function verifyPcs(
        bytes32 prefix,
        bytes calldata samples,
        DeepLayout memory layout,
        PcsOpening calldata proof
    ) internal view returns (bool) {
        (bool validPow, FriState memory state) = beginFri(
            prefix, layout.domainLog, layout.sampleCount, samples, proof.friRoots, proof.lastCoefficient, proof.nonce
        );
        if (!validPow) return false;
        bytes32[] memory packed = deepAnswers(state, samples, layout, proof.traces);
        return friVerifier.verifyComputed(state, packed, proof.layers);
    }

    function deepAnswers(
        FriState memory state,
        bytes calldata samples,
        DeepLayout memory layout,
        TraceOpening[] calldata traces
    ) private pure returns (bytes32[] memory packed) {
        NativeDeep.Plan memory plan =
            NativeDeep.prepare(state.domainLog, layout.columns, layout.points, state.deepChallenge, samples);
        uint32[8][] memory answers = openedDeepAnswers(plan, layout.trees, traces, state.queries);
        packed = new bytes32[](answers.length);
        for (uint256 i; i < answers.length; ++i) packed[i] = packFriValue(answers[i]);
    }
}
