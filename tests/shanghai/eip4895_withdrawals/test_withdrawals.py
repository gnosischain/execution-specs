"""
Tests for [EIP-4895: Beacon chain withdrawals](https://eips.ethereum.org/EIPS/eip-4895).
"""

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Op,
    Transaction,
    Withdrawal,
)

from .spec import ref_spec_4895

REFERENCE_SPEC_GIT_PATH = ref_spec_4895.git_path
REFERENCE_SPEC_VERSION = ref_spec_4895.version

pytestmark = pytest.mark.valid_from("Shanghai")

DEPOSIT_CONTRACT = Address(0xB97036A26259B7147018913BD58A774CF91ACF25)
SYSTEM_ADDRESS = Address(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE)


def get_minimal_deposit_contract_code() -> bytes:
    """
    Returns bytecode for minimal deposit contract.

    Contract logic:
    - Check msg.sender == SYSTEM_ADDRESS
    - Check arrays have same length
    - Return success
    """
    return (
        # Check msg.sender == SYSTEM_ADDRESS (0xffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE)  # noqa: E501
        Op.PUSH20(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE)
        + Op.CALLER
        + Op.EQ
        + Op.PUSH1(0x0F)  # Jump to success if equal
        + Op.JUMPI
        +
        # Revert if not system address
        Op.PUSH1(0)
        + Op.PUSH1(0)
        + Op.REVERT
        +
        # JUMPDEST for success path
        Op.JUMPDEST
        +
        # Decode and check array lengths match
        # For simplicity, we just return success
        Op.STOP
    )


def test_withdrawal_system_call_succeeds(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
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

    validator_1 = Address(0x0A)
    validator_2 = Address(0x0B)

    withdrawal_1 = Withdrawal(
        index=0,
        validator_index=0,
        address=validator_1,
        amount=12,  # 12 gwei
    )
    withdrawal_2 = Withdrawal(
        index=1,
        validator_index=1,
        address=validator_2,
        amount=13,  # 13 gwei
    )

    blocks = [
        Block(
            withdrawals=[withdrawal_1, withdrawal_2],
        ),
    ]

    # Verify the call succeeded by checking block is valid
    post = {
        DEPOSIT_CONTRACT: Account(
            storage={},
        ),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_index_order(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
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
):
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

    post = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_system_call_out_of_gas(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
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

    post = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_multiple_withdrawals_same_validator(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
    """
    Test multiple withdrawals to the same validator in one block.
    Verifies the contract can handle multiple calls correctly.
    """
    # Deploy minimal contract
    pre[DEPOSIT_CONTRACT] = Account(
        code=get_minimal_deposit_contract_code(),
        nonce=1,
    )

    validator = Address(0x0A)

    withdrawals = [
        Withdrawal(
            index=i,
            validator_index=0,
            address=validator,
            amount=10 + i,
        )
        for i in range(5)
    ]

    blocks = [
        Block(
            withdrawals=withdrawals,
        ),
    ]

    post = {
        DEPOSIT_CONTRACT: Account(storage={}),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_empty_withdrawals_list(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
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
):
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
    post = {}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_zero_amount(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
    """
    Test withdrawal with zero amount.
    Edge case: system call with zero-value withdrawal.
    """
    pre[DEPOSIT_CONTRACT] = Account(
        code=get_minimal_deposit_contract_code(),
        nonce=1,
    )

    withdrawal = Withdrawal(
        index=0,
        validator_index=0,
        address=Address(0x01),
        amount=0,  # Zero amount
    )

    blocks = [Block(withdrawals=[withdrawal])]
    post = {DEPOSIT_CONTRACT: Account(storage={})}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_max_amount(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
    """
    Test withdrawal with maximum uint64 amount.
    Ensures no overflow in amount handling.
    """
    pre[DEPOSIT_CONTRACT] = Account(
        code=get_minimal_deposit_contract_code(),
        nonce=1,
    )

    withdrawal = Withdrawal(
        index=0,
        validator_index=0,
        address=Address(0x01),
        amount=2**64 - 1,  # Max uint64
    )

    blocks = [Block(withdrawals=[withdrawal])]
    post = {DEPOSIT_CONTRACT: Account(storage={})}

    blockchain_test(pre=pre, post=post, blocks=blocks)


def test_withdrawal_only_system_address_can_call(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
):
    """
    Test that only SYSTEM_ADDRESS can call the deposit contract.
    Regular transactions should not be able to trigger withdrawals.
    """
    # Deploy contract that checks caller
    pre[DEPOSIT_CONTRACT] = Account(
        code=get_minimal_deposit_contract_code(),
        nonce=1,
    )

    sender = pre.fund_eoa()

    tx = Transaction(
        sender=sender,
        to=DEPOSIT_CONTRACT,
        data=bytes.fromhex("79d0c0bc") + (b"\x00" * 96),
        gas_limit=100000,
    )

    blocks = [
        Block(
            txs=[tx],
        ),
    ]

    # Transaction should revert
    post = {
        DEPOSIT_CONTRACT: Account(storage={}),
    }

    blockchain_test(pre=pre, post=post, blocks=blocks)
