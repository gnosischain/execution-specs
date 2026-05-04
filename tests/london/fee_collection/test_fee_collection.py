"""
Tests for Gnosis fee collection to FEE_COLLECTOR_ADDRESS.

From London onwards, the base fee portion of each transaction is sent to
FEE_COLLECTOR_ADDRESS instead of being burned as in Ethereum mainnet.

Spec: https://github.com/gnosischain/specs/blob/master/network-upgrades/london.md
"""

import pytest
from execution_testing import (
    Account,
    Address,
    Alloc,
    Block,
    BlockchainTestFiller,
    Environment,
    Transaction,
)

FEE_COLLECTOR_ADDRESS = Address("0x1559000000000000000000000000000000000000")

pytestmark = [pytest.mark.valid_from("London")]

BASE_FEE_PER_GAS = 10**9  # 1 gwei


@pytest.fixture
def env() -> Environment:
    """Block environment with a non-zero base fee."""
    return Environment(base_fee_per_gas=BASE_FEE_PER_GAS)


def test_base_fee_sent_to_fee_collector(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    env: Environment,
) -> None:
    """
    Test that the base fee is sent to FEE_COLLECTOR_ADDRESS rather than
    burned.

    A simple ETH transfer uses 21000 gas, so with base_fee_per_gas = 1 gwei,
    the fee collector should receive exactly 21000 * 1 gwei = 21000 gwei.
    """
    gas_limit = 21000
    sender = pre.fund_eoa(amount=10**18)
    receiver = pre.fund_eoa(amount=0)

    tx = Transaction(
        sender=sender,
        to=receiver,
        value=0,
        gas_limit=gas_limit,
        max_fee_per_gas=BASE_FEE_PER_GAS * 2,
        max_priority_fee_per_gas=0,
    )

    expected_fee = gas_limit * BASE_FEE_PER_GAS

    blockchain_test(
        pre=pre,
        post={
            FEE_COLLECTOR_ADDRESS: Account(balance=expected_fee),
        },
        blocks=[Block(txs=[tx])],
        genesis_environment=env,
    )


def test_fee_collector_accumulates_across_txs(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    env: Environment,
) -> None:
    """
    Test that FEE_COLLECTOR_ADDRESS accumulates fees across multiple
    transactions in the same block.
    """
    gas_limit = 21000
    sender = pre.fund_eoa(amount=10**18)
    receiver = pre.fund_eoa(amount=0)

    txs = [
        Transaction(
            sender=sender,
            to=receiver,
            value=0,
            gas_limit=gas_limit,
            max_fee_per_gas=BASE_FEE_PER_GAS * 2,
            max_priority_fee_per_gas=0,
            nonce=i,
        )
        for i in range(3)
    ]

    expected_fee = gas_limit * BASE_FEE_PER_GAS * len(txs)

    blockchain_test(
        pre=pre,
        post={
            FEE_COLLECTOR_ADDRESS: Account(balance=expected_fee),
        },
        blocks=[Block(txs=txs)],
        genesis_environment=env,
    )


def test_fee_collector_receives_zero_when_no_txs(
    blockchain_test: BlockchainTestFiller,
    pre: Alloc,
    env: Environment,
) -> None:
    """
    Test that FEE_COLLECTOR_ADDRESS has no balance change when a block
    has no transactions.
    """
    blockchain_test(
        pre=pre,
        post={
            FEE_COLLECTOR_ADDRESS: Account.NONEXISTENT,
        },
        blocks=[Block()],
        genesis_environment=env,
    )
