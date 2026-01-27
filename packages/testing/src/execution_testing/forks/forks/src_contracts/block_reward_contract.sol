// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TestBlockReward {
    function reward(address[] calldata, uint16[] calldata)
        external pure returns(address[] memory, uint256[] memory)
    {
        assembly {
            // Get free memory pointer
            let ptr := mload(0x40)
            
            // Build ABI-encoded return data for two empty arrays
            mstore(ptr, 0x40)                // Offset to first array (64 bytes)
            mstore(add(ptr, 0x20), 0x60)     // Offset to second array (96 bytes)
            mstore(add(ptr, 0x40), 0)        // First array length = 0
            mstore(add(ptr, 0x60), 0)        // Second array length = 0
            
            // Return 128 bytes (4 words)
            return(ptr, 0x80)
        }
    }
}