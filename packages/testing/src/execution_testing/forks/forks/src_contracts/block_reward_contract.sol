// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TestBlockReward {
    /**
     * Return ABI-encoded `(address[], uint256[])` where both arrays are empty:
     * - offset to first array:  0x40
     * - offset to second array: 0x60
     * - first array length:     0
     * - second array length:    0
     */
    fallback() external payable {
        assembly {
            mstore(0x00, 0x40)
            mstore(0x20, 0x60)
            mstore(0x40, 0x00)
            mstore(0x60, 0x00)
            return(0x00, 0x80)
        }
    }
}