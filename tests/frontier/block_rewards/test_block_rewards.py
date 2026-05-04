"""
Tests for Gnosis block rewards system call.

The block rewards contract is called via a system transaction at the
start of every block. If the contract reverts or runs out of gas, the
block MUST be considered invalid.

Specs:
- Pre-merge: https://github.com/gnosischain/specs/blob/master/execution/posdao.md
- Post-merge: https://github.com/gnosischain/specs/blob/master/execution/posdao-post-merge.md
"""

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Op,
)
from execution_testing.exceptions import BlockException

pytestmark = [
    pytest.mark.valid_from("Frontier"),
    pytest.mark.pre_alloc_mutable,
]

BLOCK_REWARDS_CONTRACT = Address(0x2000000000000000000000000000000000000001)
SYSTEM_ADDRESS = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE


def get_minimal_rewards_contract_code() -> Bytecode:
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


def test_block_rewards_call_data(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that the system transaction delivers calldata to the block
    rewards contract.
    """
    code: Bytecode = (
        Op.SSTORE(0, Op.GT(Op.CALLDATASIZE, 0))
        + get_minimal_rewards_contract_code()
    )

    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=code,
        nonce=1,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        post={
            BLOCK_REWARDS_CONTRACT: Account(
                storage={
                    0x00: 1,
                }
            ),
        },
        blocks=[Block()],
    )


def test_block_rewards_caller_is_system_address(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that msg.sender for the system call is SYSTEM_ADDRESS.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=Op.SSTORE(0, Op.CALLER) + get_minimal_rewards_contract_code(),
        nonce=1,
        balance=0,
    )

    blockchain_test(
        pre=pre,
        post={
            BLOCK_REWARDS_CONTRACT: Account(
                storage={0x00: SYSTEM_ADDRESS},
            ),
        },
        blocks=[Block()],
    )


def test_block_rewards_system_call_with_no_contract(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that a block is valid when the block rewards address has no code.
    """
    pre[BLOCK_REWARDS_CONTRACT] = Account(
        code=b"",
        nonce=0,
        balance=0,
    )

    blocks = [Block()]

    blockchain_test(pre=pre, post={}, blocks=blocks)


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

    blockchain_test(pre=pre, post={}, blocks=blocks)


@pytest.mark.exception_test
@pytest.mark.blockchain_test_engine_only
def test_block_rewards_system_call_invalid_opcode(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that a block rewards contract that hits the INVALID opcode
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

    blockchain_test(pre=pre, post={}, blocks=blocks)
