"""
Gnosis block rewards system call.

AuRa block rewards via the BlockRewardAuRaBase contract, replacing the
Ethereum PoW coinbase reward.

https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md
"""

from typing import List, Mapping

from execution_testing.base_types import Address

from ....base_fork import BaseFork
from ....bytecode import load_contract_bytecode

BLOCK_REWARDS_CONTRACT_ADDRESS = 0x2000000000000000000000000000000000000001
BLOCK_REWARDS_CONTRACT_BYTECODE = load_contract_bytecode(
    __name__, "block_reward_contract.bin"
)


class BlockRewards(BaseFork):
    """Block rewards class."""

    @classmethod
    def system_contracts(cls) -> List[Address]:
        """Block rewards contract is present from ConstantinopleFix onwards."""
        return [
            Address(
                BLOCK_REWARDS_CONTRACT_ADDRESS,
                label="BLOCK_REWARDS_CONTRACT_ADDRESS",
            ),
        ] + super(BlockRewards, cls).system_contracts()

    @classmethod
    def pre_allocation_blockchain(cls) -> Mapping:
        """Pre-allocate the block rewards contract."""
        return {
            BLOCK_REWARDS_CONTRACT_ADDRESS: {
                "nonce": 1,
                "code": BLOCK_REWARDS_CONTRACT_BYTECODE,
            },
        } | super(BlockRewards, cls).pre_allocation_blockchain()  # type: ignore
