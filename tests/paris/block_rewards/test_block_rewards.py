"""
Tests for Gnosis block rewards system call.

The block rewards contract is called via a system transaction at the
start of every block. If the contract reverts or runs out of gas, the
block MUST be considered invalid.

Spec: https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md
"""

from typing import Any, Dict

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Op,
)
from execution_testing.exceptions import BlockException

pytestmark = pytest.mark.valid_from("Paris")

BLOCK_REWARDS_CONTRACT = Address(
    0x2000000000000000000000000000000000000001
)


def get_minimal_rewards_contract_code():
    """
    Return bytecode that returns empty arrays for reward().

    ABI-encodes (address[], uint256[]) with both arrays empty.
    """
    # Return ABI-encoded (address[], uint256[]) with empty arrays:
    #   offset to first array (0x40)
    #   offset to second array (0x60)
    #   length of first array (0)
    #   length of second array (0)
    return (
        # Store return data in memory starting at offset 0
        Op.MSTORE(0x00, 0x40)
        + Op.MSTORE(0x20, 0x60)
        + Op.MSTORE(0x40, 0x00)
        + Op.MSTORE(0x60, 0x00)
        + Op.RETURN(0, 128)
    )


def test_block_rewards_system_call_succeeds(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that block rewards system call succeeds with a minimal
    contract that returns empty reward arrays.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=get_minimal_rewards_contract_code(),
        nonce=1,
        balance=0,
    )

    blocks = [Block()]

    post = {
        BLOCK_REWARDS_CONTRACT: Account(storage={}),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)


@pytest.mark.exception_test
@pytest.mark.blockchain_test_engine_only
def test_block_rewards_system_call_with_revert(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that a reverting block rewards contract invalidates the block.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=Op.REVERT(0, 0),
        nonce=1,
    )

    blocks = [
        Block(
            exception=BlockException.SYSTEM_CONTRACT_CALL_FAILED,
        ),
    ]

    post: Dict[str, Any] = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)


@pytest.mark.exception_test
@pytest.mark.blockchain_test_engine_only
def test_block_rewards_system_call_out_of_gas(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that a block rewards contract hitting INVALID opcode
    invalidates the block.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=Op.INVALID,
        nonce=1,
    )

    blocks = [
        Block(
            exception=BlockException.SYSTEM_CONTRACT_CALL_FAILED,
        ),
    ]

    post: Dict[str, Any] = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)
