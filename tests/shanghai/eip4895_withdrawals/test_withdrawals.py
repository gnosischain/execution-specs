"""
Tests for [EIP-4895: Beacon chain withdrawals](https://eips.ethereum.org/EIPS/eip-4895).
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
    Withdrawal,
)

from .spec import ref_spec_4895

REFERENCE_SPEC_GIT_PATH = ref_spec_4895.git_path
REFERENCE_SPEC_VERSION = ref_spec_4895.version

pytestmark = pytest.mark.valid_from("Shanghai")

DEPOSIT_CONTRACT = Address(0xB97036A26259B7147018913BD58A774CF91ACF25)


def get_minimal_deposit_contract_code() -> bytes:
    """
    Returns bytecode for minimal deposit contract that just stops.
    Used to verify system calls succeed without testing contract
    internals.
    """
    return bytes(Op.STOP)


def test_withdrawal_system_call_succeeds(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that the system call to deposit contract succeeds.
    Verifies the withdrawal mechanism works without testing contract internals.
    """
    # Deploy deposit contract at specific address
    pre[DEPOSIT_CONTRACT] = Account(
        code=get_minimal_deposit_contract_code(),
        nonce=1,
        balance=0,
    )

    withdrawal_1 = Withdrawal(
        index=0,
        validator_index=0,
        address=Address(0x0A),
        amount=12,  # 12 gwei
    )
    withdrawal_2 = Withdrawal(
        index=1,
        validator_index=1,
        address=Address(0x0B),
        amount=13,  # 13 gwei
    )

    blocks = [
        Block(
            withdrawals=[withdrawal_1, withdrawal_2],
        ),
    ]

    post = {
        DEPOSIT_CONTRACT: Account(storage={}),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_store_withdrawal_values_in_contract(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """Test that system transaction calldata is correctly formed."""
    # Deploy contract at deposit contract address to receive system calls
    pre[DEPOSIT_CONTRACT] = Account(
        code=Op.SSTORE(0, Op.CALLDATASIZE)
        + sum(Op.SSTORE(i + 1, Op.CALLDATALOAD(i * 32)) for i in range(10)),
        nonce=1,
    )

    withdrawal_1 = Withdrawal(
        index=0,
        validator_index=0,
        address=Address(0x0A),
        amount=0x0C,
    )
    withdrawal_2 = Withdrawal(
        index=1,
        validator_index=1,
        address=Address(0x0B),
        amount=0x0D,
    )

    blocks = [
        Block(
            withdrawals=[withdrawal_1, withdrawal_2],
        ),
    ]

    post = {
        DEPOSIT_CONTRACT: Account(
            storage={
                0x00: 0x0000000000000000000000000000000000000000000000000000000000000124,  # noqa: E501
                0x01: 0x79D0C0BC00000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x02: 0x0000000400000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x03: 0x0000006000000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x04: 0x000000C000000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x05: 0x0000000200000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x06: 0x0000000C00000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x07: 0x0000000D00000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x08: 0x0000000200000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x09: 0x0000000A00000000000000000000000000000000000000000000000000000000,  # noqa: E501
                0x0A: 0x0000000B00000000000000000000000000000000000000000000000000000000,  # noqa: E501
            }
        ),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_index_order(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that withdrawal indices are sequential.
    Verifies proper ordering of withdrawals.
    """
    pre[DEPOSIT_CONTRACT] = Account(
        code=get_minimal_deposit_contract_code(),
        nonce=1,
    )

    withdrawals = [
        Withdrawal(
            index=i,
            validator_index=i % 5,  # Reuse validator indices
            address=Address((i % 10) + 1),
            amount=i + 1,
        )
        for i in range(10)
    ]

    blocks = [Block(withdrawals=withdrawals)]
    post = {DEPOSIT_CONTRACT: Account(storage={})}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_system_call_with_revert(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test behavior when deposit contract reverts.

    On Gnosis, if the system call reverts, the block should still be valid
    (unlike Ethereum where withdrawals are unconditional balance updates).
    """
    # Deploy contract that always reverts
    pre[DEPOSIT_CONTRACT] = Account(
        code=Op.REVERT(0, 0),
        nonce=1,
    )

    withdrawal = Withdrawal(
        index=0,
        validator_index=0,
        address=Address(0x01),
        amount=1,
    )

    blocks = [
        Block(
            withdrawals=[withdrawal],
        ),
    ]

    post: Dict[str, Any] = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_system_call_out_of_gas(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test behavior when deposit contract runs out of gas.
    """
    # Deploy contract that uses INVALID opcode
    pre[DEPOSIT_CONTRACT] = Account(
        code=Op.INVALID,
        nonce=1,
    )

    withdrawal = Withdrawal(
        index=0,
        validator_index=0,
        address=Address(0x01),
        amount=1,
    )

    blocks = [
        Block(
            withdrawals=[withdrawal],
        ),
    ]

    post: Dict[str, Any] = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_empty_withdrawals_list(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test that empty withdrawals list is valid.
    System call should still be made (with empty arrays).
    """
    # Deploy contract that stores a value to prove it was called
    pre[DEPOSIT_CONTRACT] = Account(
        code=Op.SSTORE(0, 1),
        nonce=1,
    )

    blocks = [
        Block(
            withdrawals=[],
        ),
    ]

    post = {
        DEPOSIT_CONTRACT: Account(
            storage={
                0x0: 0x1,  # Proves contract was called even with empty list
            }
        ),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_contract_not_deployed(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
) -> None:
    """
    Test what happens if deposit contract is not deployed.
    System call to non-existent contract should handle gracefully.
    """
    # Don't deploy any contract - leave address empty
    # This tests the EVM behavior when calling non-existent address

    withdrawal = Withdrawal(
        index=0,
        validator_index=0,
        address=Address(0x01),
        amount=1,
    )

    blocks = [
        Block(
            withdrawals=[withdrawal],
        ),
    ]

    # Call to non-existent contract succeeds but does nothing
    post: Dict[str, Any] = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)
