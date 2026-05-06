// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
// Compiled with: solc --bin-runtime --optimize --optimize-runs 1 --evm-version byzantium
// Target byzantium to avoid SHL/SHR/PUSH0 — contract is deployed on forks as early as Frontier.

/**
 * Minimum viable test implementation of the BlockRewardAuRa reward contract.
 *
 * Implements the reward(address[], uint16[]) interface called once per block
 * as a system transaction from SYSTEM_ADDRESS (0xffff...fffe) with
 * benefactors=[coinbase] and kind=[0] (RewardAuthor kind).
 *
 * Mirrors the guard logic from BlockRewardAuRaBase.reward(): invalid inputs
 * return empty arrays without reverting. Valid inputs also return empty arrays,
 * simulating the real contract's behaviour when validatorSetContract is unset
 * (as it is in test pre-allocations).
 *
 * Spec: https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md
 * Real contract: https://github.com/gnosischain/posdao-contracts/blob/master/contracts/base/BlockRewardAuRaBase.sol
 */
contract TestBlockReward {
    function reward(
        address[] memory benefactors,
        uint16[] memory kind
    )
        external
        pure
        returns (
            address[] memory receiversNative,
            uint256[] memory rewardsNative
        )
    {
        // Mirror BlockRewardAuRaBase guard: invalid args → return empty (no revert)
        if (
            benefactors.length != kind.length
                || benefactors.length != 1
                || kind[0] != 0
        ) {
            return (new address[](0), new uint256[](0));
        }

        // validatorSetContract unset in test environment → return empty
        return (new address[](0), new uint256[](0));
    }
}
